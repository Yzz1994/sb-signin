package main

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 论坛签到页使用 cap.js（capjs.net）人机验证：
//   1. POST {endpoint}challenge 取题目（c 题数 / s 盐长度 / d 难度）
//   2. 计算 PoW：对第 i 题取 salt=capGen(token+i, s)、target=capGen(token+i+"d", d)，
//      寻找最小 nonce 使 SHA256(salt+nonce) 的前 4*len(target) 位等于 target
//   3. 页面下发的 instrumentation 脚本需在浏览器沙箱中执行并回报 state 等结果
//      （本实现离线复刻其确定性运算，构造等价 instr）
//   4. POST {endpoint}redeem 提交 {token, solutions, instr} 换取 cap-token
//   5. 表单提交时携带隐藏字段 cap-token

// capChallengeResp challenge 接口响应
type capChallengeResp struct {
	Challenge struct {
		C int `json:"c"` // 题目数量
		S int `json:"s"` // 盐长度
		D int `json:"d"` // 难度（十六进制位数，前导零位数 = 4*d）
	} `json:"challenge"`
	Token           string `json:"token"`
	Expires         int64  `json:"expires"`
	Instrumentation string `json:"instrumentation"`
	Format          int    `json:"format"`
	Challenges      []any  `json:"challenges"`
	Error           string `json:"error"`
}

// capRedeemResp redeem 接口响应
type capRedeemResp struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	Error   string `json:"error"`
	Reason  string `json:"reason"`
}

// capGen 复刻 cap.js widget 中的确定性字符串生成函数：
// FNV-1a 作为种子 + xorshift32，逐轮输出 8 位十六进制，取前 length 个字符。
func capGen(seed string, length int) string {
	var t int64 = 2166136261
	for i := 0; i < len(seed); i++ {
		t = int64(int32(uint32(t) ^ uint32(seed[i])))
		a := uint32(t)
		t += int64(int32(a<<1)) + int64(int32(a<<4)) + int64(int32(a<<7)) +
			int64(int32(a<<8)) + int64(int32(a<<24))
	}
	x := uint32(t)
	var sb strings.Builder
	sb.Grow(length + 8)
	for sb.Len() < length {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		sb.WriteString(fmt.Sprintf("%08x", x))
	}
	return sb.String()[:length]
}

// capSolve 求解单个 PoW：返回满足条件的最小 nonce。
func capSolve(salt, target string) uint64 {
	bits := 4 * len(target)
	full := bits / 8
	rem := bits % 8
	hexStr := target
	if len(target)%2 != 0 {
		hexStr += "0"
	}
	tb := make([]byte, len(hexStr)/2)
	for i := range tb {
		v, _ := strconv.ParseUint(hexStr[2*i:2*i+2], 16, 8)
		tb[i] = byte(v)
	}
	var mask byte
	if rem > 0 {
		mask = byte((255 << (8 - rem)) & 255)
	}
	for nonce := uint64(0); ; nonce++ {
		sum := sha256.Sum256([]byte(salt + strconv.FormatUint(nonce, 10)))
		ok := true
		for i := 0; i < full; i++ {
			if sum[i] != tb[i] {
				ok = false
				break
			}
		}
		if ok && rem > 0 && (sum[full]&mask) != (tb[full]&mask) {
			ok = false
		}
		if ok {
			return nonce
		}
	}
}

// solveCapPow 并发生成并求解全部题目，返回按题目顺序排列的 nonce。
func solveCapPow(token string, count, saltLen, difficulty int) []uint64 {
	type job struct {
		salt   string
		target string
	}
	jobs := make([]job, count)
	for i := 0; i < count; i++ {
		seed := fmt.Sprintf("%s%d", token, i+1)
		jobs[i] = job{salt: capGen(seed, saltLen), target: capGen(seed+"d", difficulty)}
	}
	sols := make([]uint64, count)
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > count {
		workers = count
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range ch {
				sols[idx] = capSolve(jobs[idx].salt, jobs[idx].target)
			}
		}()
	}
	for i := 0; i < count; i++ {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return sols
}

var (
	reCapEndpoint = regexp.MustCompile(`data-cap-api-endpoint="([^"]+)"`)
	reInstrNonce  = regexp.MustCompile(`nonce:\s*"([0-9a-fA-F]+)"`)
	reInstrVars   = regexp.MustCompile(`var (\w+)=(\d+);var (\w+)=(\d+);var (\w+)=(\d+);var (\w+)=(\d+);`)
	reInstrCSFn   = regexp.MustCompile(`function (\w+)\(a,b,c\)\{function F\(d\)\{this\.v=function\(\)\{return this\.k\^d;`)
	reInstrGMFn   = regexp.MustCompile(`function (\w+)\(x,y,z\)\{var d=document\.createElement\('div'\)`)
	reTernary     = regexp.MustCompile(`navigator\.userAgent\s*\?\s*(\d+)\s*:\s*(\d+)`)
)

// extractCapEndpoint 从签到页 HTML 中取出人机验证接口地址（带结尾斜杠）
func extractCapEndpoint(html string) string {
	m := reCapEndpoint.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	ep := m[1]
	if !strings.HasSuffix(ep, "/") {
		ep += "/"
	}
	return ep
}

// capFingerprint 构造与 userAgent 一致的浏览器指纹信息。
// instrumentation 脚本会采集这些字段，缺失或明显异常会被判定为自动化环境。
func capFingerprint() map[string]any {
	return map[string]any{
		"isExtended":   nil,
		"deviceMemory": 8,
		"webdriver":    false,
		"screen":       map[string]any{"width": 1920, "height": 1080},
		"fontWidths": []float64{
			268.73, 268.73, 234.38, 268.73, 249.16, 240.5, 242.94, 244.16, 249.16,
			249.16, 231.11, 224.42, 223.17, 224.42, 236.17, 250.41, 243.2,
		},
		"uaData": map[string]any{
			"mobile": false,
			"brands": []string{"Chromium/120", "Google Chrome/120", "Not_A Brand/8"},
		},
		"ua":            userAgent,
		"engine":        map[string]any{"hasMozInnerScreenX": false, "hasChrome": true},
		"oscpu":         "__undefined",
		"uaDataPresent": true,
		"tamper": map[string]any{
			"getParameterWebGL": true,
			"toDataURL":         true,
			"getImageData":      true,
			"permissionsQuery":  true,
			"fnToString":        true,
		},
		"pdfViewerEnabled": true,
		"productSub":       "20030101",
		"plugins":          map[string]any{"length": 5},
		"outerWH":          []int{1920, 1080},
	}
}

// buildInstr 解析页面下发的 instrumentation 脚本，构造等价的上报数据。
func buildInstr(encoded string) (map[string]any, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("解码人机验证脚本失败: %w", err)
	}
	zr := flate.NewReader(bytes.NewReader(raw))
	jsBytes, err := io.ReadAll(zr)
	if err != nil && len(jsBytes) == 0 {
		return nil, fmt.Errorf("解压人机验证脚本失败: %w", err)
	}
	js := string(jsBytes)

	nm := reInstrNonce.FindStringSubmatch(js)
	if len(nm) < 2 {
		return nil, errors.New("人机验证脚本缺少 nonce")
	}
	state, err := evalInstrState(js)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"i":     nm[1],
		"state": state,
		"p":     capFingerprint(),
		"ts":    time.Now().UnixMilli(),
	}, nil
}

// evalInstrState 复刻 instrumentation 脚本中 state 的确定性计算。
// 脚本每次随机生成（变量名、常量、运算顺序均不同），因此需要动态识别并解释执行。
func evalInstrState(js string) (map[string]any, error) {
	vm := reInstrVars.FindStringSubmatch(js)
	if len(vm) < 9 {
		return nil, errors.New("人机验证脚本结构无法识别（state 初值缺失）")
	}
	names := [4]string{vm[1], vm[3], vm[5], vm[7]}
	vals := [4]int64{}
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseInt(vm[2+2*i], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("解析 state 初值失败: %w", err)
		}
		vals[i] = v
	}
	csName := ""
	if m := reInstrCSFn.FindStringSubmatch(js); len(m) > 1 {
		csName = m[1]
	}
	gmName := ""
	if m := reInstrGMFn.FindStringSubmatch(js); len(m) > 1 {
		gmName = m[1]
	}
	if csName == "" || gmName == "" {
		return nil, errors.New("人机验证脚本结构无法识别（运算函数缺失）")
	}

	// 定位 state 计算块：从「A = A ^ (...)」到「D=((D^...)&0x7FFFFFFF)%900000+100000;」
	startRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(names[0]) + `\s*=\s*` + regexp.QuoteMeta(names[0]) + `\s*\^`)
	loc := startRe.FindStringIndex(js)
	if loc == nil {
		return nil, errors.New("人机验证脚本结构无法识别（计算块起点缺失）")
	}
	endRe := regexp.MustCompile(regexp.QuoteMeta(names[3]) + `\s*=\s*\(\(\s*` + regexp.QuoteMeta(names[3]) + `\s*\^\s*\d+\s*\)\s*&\s*0x7FFFFFFF\)`)
	endLoc := endRe.FindStringIndex(js)
	if endLoc == nil || endLoc[0] < loc[0] {
		return nil, errors.New("人机验证脚本结构无法识别（计算块终点缺失）")
	}
	semi := strings.Index(js[endLoc[1]:], ";")
	if semi < 0 {
		return nil, errors.New("人机验证脚本结构无法识别（计算块未闭合）")
	}
	block := js[loc[0] : endLoc[1]+semi+1]
	// 三元表达式按「浏览器 UA 存在」分支取值
	block = reTernary.ReplaceAllString(block, "$1")

	vars := map[string]int64{}
	for i := 0; i < 4; i++ {
		vars[names[i]] = vals[i]
	}
	fns := map[string]func(args []int64) (int64, error){
		gmName: gmDOMCompute,
		csName: csMix,
	}
	for _, stmt := range strings.Split(block, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		eq := strings.Index(stmt, "=")
		if eq <= 0 {
			return nil, fmt.Errorf("人机验证脚本语句无法识别: %q", stmt)
		}
		name := strings.TrimSpace(stmt[:eq])
		expr := stmt[eq+1:]
		val, err := evalJSExpr(expr, vars, fns)
		if err != nil {
			return nil, err
		}
		vars[name] = val
	}
	return map[string]any{
		names[0]: vars[names[0]],
		names[1]: vars[names[1]],
		names[2]: vars[names[2]],
		names[3]: vars[names[3]],
	}, nil
}

// csMix 对应脚本中的 cs49ztk9(a,b,c)：(a^b)|(b^c)
func csMix(args []int64) (int64, error) {
	if len(args) != 3 {
		return 0, fmt.Errorf("运算函数参数数量错误: %d", len(args))
	}
	a, b, c := args[0], args[1], args[2]
	return int64(int32(a^b) | int32(b^c)), nil
}

// gmDOMCompute 对应脚本中基于 DOM 树文本累加的运算函数 gm75n(x,y,z)。
// 该运算只依赖数值与 DOM 结构，与浏览器环境无关，因此可离线复刻。
type gmNode struct {
	parent   *gmNode
	children []*gmNode
	text     int64
}

func gmDOMCompute(args []int64) (int64, error) {
	if len(args) != 3 {
		return 0, fmt.Errorf("运算函数参数数量错误: %d", len(args))
	}
	root := &gmNode{}
	appendChain := func(p *gmNode, v int64) *gmNode {
		v = int64(int32(v))
		for i := 0; i < 8; i++ {
			c := &gmNode{parent: p, text: v}
			p.children = append(p.children, c)
			if v&1 == 0 {
				p = c
			}
			v = v >> 1
		}
		return p
	}
	var walk func(n, r *gmNode, s int64) int64
	walk = func(n, r *gmNode, s int64) int64 {
		if n == nil || n == r {
			return s % 256
		}
		n.children = nil
		return walk(n.parent, r, s+n.text)
	}
	n := appendChain(appendChain(appendChain(root, args[0]), args[1]), args[2])
	return walk(n, root, 0), nil
}

// evalJSExpr 解释 state 计算块中的 JavaScript 表达式（仅支持脚本用到的子集：
// 数字、标识符、函数调用、~ ^ & | + % << >> 与括号，均为 32 位位运算语义）。
func evalJSExpr(src string, vars map[string]int64, fns map[string]func([]int64) (int64, error)) (int64, error) {
	p := &jsParser{src: src, vars: vars, fns: fns}
	v, err := p.parseOr()
	if err != nil {
		return 0, err
	}
	p.skipSpace()
	if p.pos != len(p.src) {
		return 0, fmt.Errorf("表达式无法解析: %q", src)
	}
	return v, nil
}

type jsParser struct {
	src  string
	pos  int
	vars map[string]int64
	fns  map[string]func([]int64) (int64, error)
}

func (p *jsParser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsParser) parseOr() (int64, error) {
	v, err := p.parseXor()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == '|' {
			p.pos++
			r, err := p.parseXor()
			if err != nil {
				return 0, err
			}
			v = int64(int32(v) | int32(r))
			continue
		}
		return v, nil
	}
}

func (p *jsParser) parseXor() (int64, error) {
	v, err := p.parseAnd()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == '^' {
			p.pos++
			r, err := p.parseAnd()
			if err != nil {
				return 0, err
			}
			v = int64(int32(v) ^ int32(r))
			continue
		}
		return v, nil
	}
}

func (p *jsParser) parseAnd() (int64, error) {
	v, err := p.parseShift()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == '&' {
			p.pos++
			r, err := p.parseShift()
			if err != nil {
				return 0, err
			}
			v = int64(int32(v) & int32(r))
			continue
		}
		return v, nil
	}
}

func (p *jsParser) parseShift() (int64, error) {
	v, err := p.parseAdd()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpace()
		if p.pos+1 < len(p.src) && p.src[p.pos] == '<' && p.src[p.pos+1] == '<' {
			p.pos += 2
			r, err := p.parseAdd()
			if err != nil {
				return 0, err
			}
			v = int64(int32(uint32(int32(v)) << (uint32(r) & 31)))
			continue
		}
		if p.pos+1 < len(p.src) && p.src[p.pos] == '>' && p.src[p.pos+1] == '>' {
			p.pos += 2
			r, err := p.parseAdd()
			if err != nil {
				return 0, err
			}
			v = int64(int32(v) >> (uint32(r) & 31))
			continue
		}
		return v, nil
	}
}

func (p *jsParser) parseAdd() (int64, error) {
	v, err := p.parseUnary()
	if err != nil {
		return 0, err
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			return v, nil
		}
		switch p.src[p.pos] {
		case '+':
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return 0, err
			}
			v += r
		case '%':
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return 0, err
			}
			if r == 0 {
				return 0, errors.New("表达式出现除以零")
			}
			v %= r
		default:
			return v, nil
		}
	}
}

func (p *jsParser) parseUnary() (int64, error) {
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == '~' {
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return 0, err
		}
		return int64(^int32(v)), nil
	}
	return p.parsePrimary()
}

func (p *jsParser) parsePrimary() (int64, error) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return 0, errors.New("表达式意外结束")
	}
	c := p.src[p.pos]
	if c == '(' {
		p.pos++
		v, err := p.parseOr()
		if err != nil {
			return 0, err
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return 0, errors.New("表达式缺少右括号")
		}
		p.pos++
		return v, nil
	}
	if c >= '0' && c <= '9' {
		start := p.pos
		for p.pos < len(p.src) && (isHexDigit(p.src[p.pos]) || p.src[p.pos] == 'x' || p.src[p.pos] == 'X') {
			p.pos++
		}
		lit := p.src[start:p.pos]
		var v int64
		var err error
		if strings.HasPrefix(lit, "0x") || strings.HasPrefix(lit, "0X") {
			v, err = strconv.ParseInt(lit[2:], 16, 64)
		} else {
			v, err = strconv.ParseInt(lit, 10, 64)
		}
		if err != nil {
			return 0, fmt.Errorf("数字字面量无法解析: %q", lit)
		}
		return v, nil
	}
	if isIdentStart(c) {
		start := p.pos
		for p.pos < len(p.src) && isIdentPart(p.src[p.pos]) {
			p.pos++
		}
		name := p.src[start:p.pos]
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == '(' {
			fn, ok := p.fns[name]
			if !ok {
				return 0, fmt.Errorf("未知函数调用: %s", name)
			}
			p.pos++
			var args []int64
			for {
				p.skipSpace()
				if p.pos < len(p.src) && p.src[p.pos] == ')' {
					p.pos++
					break
				}
				v, err := p.parseOr()
				if err != nil {
					return 0, err
				}
				args = append(args, v)
				p.skipSpace()
				if p.pos < len(p.src) && p.src[p.pos] == ',' {
					p.pos++
					continue
				}
				if p.pos < len(p.src) && p.src[p.pos] == ')' {
					p.pos++
					break
				}
				return 0, fmt.Errorf("函数调用 %s 参数无法解析", name)
			}
			return fn(args)
		}
		v, ok := p.vars[name]
		if !ok {
			return 0, fmt.Errorf("未知变量: %s", name)
		}
		return v, nil
	}
	return 0, fmt.Errorf("表达式无法解析: %q", p.src)
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// solveCaptcha 完成一次完整的人机验证，返回可提交的 cap-token。
func solveCaptcha(client *http.Client, endpoint string) (string, error) {
	var ch capChallengeResp
	if err := capPostJSON(client, endpoint+"challenge", map[string]any{}, &ch); err != nil {
		return "", fmt.Errorf("获取人机验证题目失败: %w", err)
	}
	if ch.Error != "" {
		return "", errors.New(ch.Error)
	}
	if ch.Format == 2 || len(ch.Challenges) > 0 {
		return "", errors.New("论坛已升级人机验证协议，请更新本程序")
	}
	if ch.Token == "" || ch.Challenge.C <= 0 {
		return "", errors.New("人机验证题目格式异常")
	}

	solutions := solveCapPow(ch.Token, ch.Challenge.C, ch.Challenge.S, ch.Challenge.D)

	payload := map[string]any{"token": ch.Token, "solutions": solutions}
	if ch.Instrumentation != "" {
		instr, err := buildInstr(ch.Instrumentation)
		if err != nil {
			return "", err
		}
		payload["instr"] = instr
	}

	var rd capRedeemResp
	if err := capPostJSON(client, endpoint+"redeem", payload, &rd); err != nil {
		return "", fmt.Errorf("提交人机验证结果失败: %w", err)
	}
	if !rd.Success || rd.Token == "" {
		msg := rd.Error
		if msg == "" {
			msg = rd.Reason
		}
		if msg == "" {
			msg = "验证未通过"
		}
		return "", errors.New(msg)
	}
	return rd.Token, nil
}

// capPostJSON 向人机验证服务发送 JSON 请求（需带论坛来源头，服务端会校验）
func capPostJSON(client *http.Client, url string, body map[string]any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Origin", "https://sb.sb")
	req.Header.Set("Referer", checkinURL)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		return fmt.Errorf("响应解析失败: %w", err)
	}
	return nil
}
