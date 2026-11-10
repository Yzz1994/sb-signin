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
	"math/rand"
	"net/http"
	"regexp"
	"runtime"
	"sort"
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
	x := fnv1a32(seed, 2166136261)
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

// fnv1a32 复刻脚本中通用的 FNV-1a 变体哈希（cap 派生与 instr 校验共用）：
// h = seed；每个字符 h ^= code; h += (h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24)（uint32 回绕）。
// 脚本中 salt/校验值的字符均为 ASCII，按字节取码与 charCodeAt 等价。
func fnv1a32(s string, seed uint32) uint32 {
	h := seed
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h += h<<1 + h<<4 + h<<7 + h<<8 + h<<24
	}
	return h
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
			"brands": []string{"Not?A_Brand/24", "Chromium/152"},
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
// 新版脚本（2026-11 起）：上报 {i, state, d}——state 为与 d 校验值混叠后的结果，
// d 为自定义序列化（键排序）的环境指纹 JSON；旧版脚本回退为 {i, state, p, ts}。
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
	if mixed, d, err := buildInstrNew(js, state); err == nil {
		return map[string]any{"i": nm[1], "state": mixed, "d": d}, nil
	}
	return map[string]any{
		"i":     nm[1],
		"state": state,
		"p":     capFingerprint(),
		"ts":    time.Now().UnixMilli(),
	}, nil
}

// buildInstrNew 解析新版脚本中的混叠常量与校验种子，构造 {state, d}。
// 脚本尾部固定结构（变量名/常量随机生成）：
//
//	Z1=fnv(d,(S1^fnv(stateStr,S2))>>>0); Z2=fnv(d,(S3^fnv(stateStr,S4))>>>0)
//	out["n0"]=((s0^C0)&0x7FFFFFFF)%900000+100000
//	out["n1"]=((s1^C1^Z1)&0x7FFFFFFF)%900000+100000
//	out["n2"]=((s2^C2^Z2)&0x7FFFFFFF)%900000+100000
//	out["n3"]=((s3^C3)&0x7FFFFFFF)%900000+100000
func buildInstrNew(js string, raw map[string]any) (map[string]any, string, error) {
	d := buildCapD()
	mixed, err := mixCapState(js, raw, d)
	if err != nil {
		return nil, "", err
	}
	return mixed, d, nil
}

// mixCapState 按脚本常量将原始 state 与 d 载荷校验值混叠，得到最终上报的 state。
// 脚本生成器会随机化以下细节，须逐脚本解析而非假设固定模板：
//   - 两个校验值的（可为负数的）外/内种子及赋值目标变量名
//   - 四条混叠语句中哪些带校验值 XOR（位置不固定，实测出现过 n1/n2 与 n0/n1 两种）
//   - stateStr 中四个状态名的顺序（出现在校验表达式参数段中）
func mixCapState(js string, raw map[string]any, d string) (map[string]any, error) {
	// 校验值定义：Z=fnv(d,(外种子^fnv(stateStr,内种子))>>>0)
	reChk := regexp.MustCompile(`(\w+)\s*=\s*\w+\(\s*\w+\s*,\s*\(\s*(-?\d+)\s*\^\s*\w+\(\s*\w+\["(\w+)"\][^)]*?,\s*(-?\d+)\s*\)\s*\)\s*>\s*>\s*>\s*0`)
	chk := reChk.FindAllStringSubmatch(js, -1)
	if len(chk) != 2 {
		return nil, errors.New("校验种子缺失")
	}
	type zDef struct{ outer, inner uint32 }
	zByName := map[string]zDef{}
	for _, m := range chk {
		zByName[m[1]] = zDef{seedToUint32(m[2]), seedToUint32(m[4])}
	}
	// 从第一组校验表达式的参数段提取 stateStr 的名字顺序
	nameSet := map[string]bool{}
	for n := range raw {
		nameSet[n] = true
	}
	var names []string
	for _, m := range regexp.MustCompile(`\["(\w+)"\]`).FindAllStringSubmatch(chk[0][0], -1) {
		if nameSet[m[1]] && !containsStr(names, m[1]) {
			names = append(names, m[1])
		}
	}
	if len(names) != 4 {
		return nil, errors.New("状态名顺序无法识别")
	}
	vals := make([]int64, 4)
	for i, n := range names {
		v, ok := raw[n].(int64)
		if !ok {
			return nil, fmt.Errorf("状态值缺失: %s", n)
		}
		vals[i] = v
	}
	stateStr := fmt.Sprintf("%d,%d,%d,%d", vals[0], vals[1], vals[2], vals[3])

	// 混叠语句：COLL["n"]=((RAW["n"]^C[^Z])&0x7FFFFFFF)%900000+100000（Z 可选）
	out := make(map[string]any, 4)
	for i, name := range names {
		pat := `\w+\["` + regexp.QuoteMeta(name) + `"\]\s*=\s*\(\(\s*\w+\["` + regexp.QuoteMeta(name) + `"\]\s*\^\s*(-?\d+)\s*(?:\^\s*(\w+)\s*)?\)\s*&\s*0x7FFFFFFF\)`
		m := regexp.MustCompile(pat).FindStringSubmatch(js)
		if m == nil {
			return nil, fmt.Errorf("混叠语句缺失: %s", name)
		}
		c, _ := strconv.ParseInt(m[1], 10, 64)
		var z uint32
		if m[2] != "" {
			zd, ok := zByName[m[2]]
			if !ok {
				return nil, fmt.Errorf("校验值绑定缺失: %s", m[2])
			}
			z = fnv1a32(d, zd.outer^fnv1a32(stateStr, zd.inner))
		}
		x := int32(vals[i]) ^ int32(c) ^ int32(z)
		out[name] = int64(uint32(x)&0x7FFFFFFF)%900000 + 100000
	}
	return out, nil
}

// seedToUint32 解析（可能为负的）十进制种子为 uint32（JS int32 位运算 + >>>0 语义）
func seedToUint32(s string) uint32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return uint32(int32(v))
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- 自定义 JSON 序列化（复刻脚本 xodxtdynwu：紧凑、键排序、仅转义 " \ 与控制符）----

type jv interface{ write(sb *strings.Builder) }

type jvNull struct{}

func (jvNull) write(sb *strings.Builder) { sb.WriteString("null") }

type jvBool bool

func (b jvBool) write(sb *strings.Builder) {
	if b {
		sb.WriteString("true")
	} else {
		sb.WriteString("false")
	}
}

type jvStr string

func (s jvStr) write(sb *strings.Builder) {
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20:
			switch c {
			case '\b':
				sb.WriteString(`\b`)
			case '\f':
				sb.WriteString(`\f`)
			case '\n':
				sb.WriteString(`\n`)
			case '\r':
				sb.WriteString(`\r`)
			case '\t':
				sb.WriteString(`\t`)
			default:
				fmt.Fprintf(sb, `\u0%x`, c)
			}
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
}

type jvNum float64

func (n jvNum) write(sb *strings.Builder) {
	sb.WriteString(strconv.FormatFloat(float64(n), 'f', -1, 64))
}

type jvInt int64

func (n jvInt) write(sb *strings.Builder) { sb.WriteString(strconv.FormatInt(int64(n), 10)) }

type jvArr []jv

func (a jvArr) write(sb *strings.Builder) {
	sb.WriteByte('[')
	for i, v := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		v.write(sb)
	}
	sb.WriteByte(']')
}

type jvObj map[string]jv

func (o jvObj) write(sb *strings.Builder) {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		jvStr(k).write(sb)
		sb.WriteByte(':')
		o[k].write(sb)
	}
	sb.WriteByte('}')
}

func serializeJV(v jv) string {
	var sb strings.Builder
	v.write(&sb)
	return sb.String()
}

// capDTemplate 新版上报的 d 载荷模板：取自真实浏览器环境（Chromium 152 /
// Win11 / GTX 1650 / 1920x1080）的完整抓包样本，已经服务端校验通过。
// 服务端对 d 做跨字段一致性校验（UA、品牌列表、内存上限、窗口度量等需互相
// 吻合），手工拼装的组合实测会被拒，故整体沿用实测值，仅随机化 el
// （instrumentation 脚本运行耗时毫秒数）。
// 若日后失效：用浏览器完成一次签到页验证，抓 redeem 请求体中的 instr.d 重新采样。
const capDTemplate = `{"ag":[],"bh":null,"ce":0,"el":168,"hp":{"cdp":false,"doc":false,"ha":[],"nav":{"brands":"Not?A_Brand/24,Chromium/152","hc":12,"languages":"zh-CN,zh-Hans-CN","platform":"Win32","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ZCode/3.17.2 Chrome/152.0.7977.130 Electron/44.7.0 Safari/537.36","webdriver":false}},"ia":null,"p":{"activeText":["rgb(0, 102, 204)",false],"cv":[1,2042],"deviceMemory":32,"em":[175.75,86],"engine":{"hasChrome":true,"hasMozInnerScreenX":false},"evalLen":33,"fm":1320.44,"fontWidths":[1320.44,900,900,1200.88,1156.97,1080.19,1213.5,1320.44,1320.44,1320.44,1320.44,1320.44,1203.86,1122.47,1320.44,1320.44,1320.44],"glsh":{"r":"ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00002188) Direct3D11 vs_5_0 ps_5_0, D3D11)","t":"hlsl"},"gpu":{"a":"turing","f":false,"n":false,"v":"nvidia"},"hev":{"ar":"x86","bi":"64","fl":"Not?A_Brand,Chromium","fv":"152.0.7977.130","pv":"15.0.0"},"ig":[],"isExtended":true,"juggler":null,"langs":[2,true],"lies":[],"mainNav":{"brands":"Not?A_Brand/24,Chromium/152","brave":false,"gl":"ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00002188) Direct3D11 vs_5_0 ps_5_0, D3D11)","hc":12,"languages":"zh-CN,zh-Hans-CN","platform":"Win32","tz":"Asia/Shanghai","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ZCode/3.17.2 Chrome/152.0.7977.130 Electron/44.7.0 Safari/537.36"},"maxTouchPoints":10,"na":255,"no":[],"oscpu":"__undefined","outerWH":[0,0],"pdfViewerEnabled":true,"plugins":{"length":5},"productSub":"20030107","screen":{"dpr":1,"height":1080,"width":1920},"sd":[],"stealth":{"iframe":false,"runtime":false},"tamper":{"fnToString":true,"getImageData":true,"getParameterWebGL":true,"permissionsQuery":true,"toDataURL":true},"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ZCode/3.17.2 Chrome/152.0.7977.130 Electron/44.7.0 Safari/537.36","uaData":{"brands":["Not?A_Brand/24","Chromium/152"],"mobile":false},"uaDataPresent":true,"voices":[3,0],"webdriver":false,"workerNav":{"brands":"Not?A_Brand/24,Chromium/152","brave":false,"gl":"ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00002188) Direct3D11 vs_5_0 ps_5_0, D3D11)","hc":12,"languages":"zh-CN,zh-Hans-CN","platform":"Win32","tz":"Asia/Shanghai","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ZCode/3.17.2 Chrome/152.0.7977.130 Electron/44.7.0 Safari/537.36"}},"v":1,"vp":[1280,720]}`

// buildCapD 由模板生成 d 载荷（随机化 el）
func buildCapD() string {
	return strings.Replace(capDTemplate, `"el":169`, fmt.Sprintf(`"el":%d`, 120+rand.Intn(260)), 1)
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

	// 定位 state 计算块：从「A = A ^ (...)」到收集语句「var X={};X["A"]=A;」之前。
	// 旧版脚本块尾有四条「V=((V^n)&0x7FFFFFFF)%900000+100000;」归一化语句，
	// 新版删掉了归一化、计算完直接收集，因此以收集语句（两种格式均有）为终点锚点，
	// 旧归一化语句仅作兜底。
	startRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(names[0]) + `\s*=\s*` + regexp.QuoteMeta(names[0]) + `\s*\^`)
	loc := startRe.FindStringIndex(js)
	if loc == nil {
		return nil, errors.New("人机验证脚本结构无法识别（计算块起点缺失）")
	}
	blockEnd := -1
	if m := regexp.MustCompile(`var\s+\w+\s*=\s*\{\};\w+\["` + regexp.QuoteMeta(names[0]) + `"\]`).FindStringIndex(js[loc[1]:]); m != nil {
		blockEnd = loc[1] + m[0]
	} else if m := regexp.MustCompile(regexp.QuoteMeta(names[3]) + `\s*=\s*\(\(\s*` + regexp.QuoteMeta(names[3]) + `\s*\^\s*\d+\s*\)\s*&\s*0x7FFFFFFF\)`).FindStringIndex(js[loc[1]:]); m != nil {
		end := loc[1] + m[1]
		if semi := strings.Index(js[end:], ";"); semi >= 0 {
			blockEnd = end + semi + 1
		}
	}
	if blockEnd < 0 {
		return nil, errors.New("人机验证脚本结构无法识别（计算块终点缺失）")
	}
	block := js[loc[0]:blockEnd]
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
