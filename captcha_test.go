package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// expected.json 由 Node.js 按 cap.js 官方算法生成（见仓库说明），
// 用于校验 Go 实现与浏览器端行为一致。
type expectedData struct {
	Token      string                `json:"token"`
	Challenge  struct{ C, S, D int } `json:"challenge"`
	Salts      []string              `json:"salts"`
	Targets    []string              `json:"targets"`
	Nonces     []uint64              `json:"nonces"`
	NonceInstr string                `json:"nonce_instr"`
	State      map[string]int64      `json:"state"`
	GenSamples []string              `json:"gen_samples"`
}

func loadExpected(t *testing.T) *expectedData {
	t.Helper()
	buf, err := os.ReadFile("testdata/expected.json")
	if err != nil {
		t.Fatalf("读取期望数据失败: %v", err)
	}
	var e expectedData
	if err := json.Unmarshal(buf, &e); err != nil {
		t.Fatalf("解析期望数据失败: %v", err)
	}
	return &e
}

// TestCapGen 校验确定性字符串生成与 JS 实现一致
func TestCapGen(t *testing.T) {
	e := loadExpected(t)
	cases := []struct {
		seed string
		n    int
	}{
		{"abc", 8},
		{"abc", 32},
		{e.Token + "1", 16},
		{e.Token + "1d", 6},
	}
	for i, c := range cases {
		got := capGen(c.seed, c.n)
		if got != e.GenSamples[i] {
			t.Errorf("capGen(%q,%d) = %q, want %q", c.seed, c.n, got, e.GenSamples[i])
		}
	}
}

// TestCapSolve 校验 PoW 求解结果与浏览器端一致（最小 nonce）
func TestCapSolve(t *testing.T) {
	e := loadExpected(t)
	for i := range e.Salts {
		got := capSolve(e.Salts[i], e.Targets[i])
		if got != e.Nonces[i] {
			t.Errorf("capSolve(#%d) = %d, want %d", i+1, got, e.Nonces[i])
		}
	}
}

// TestSolveCapPowOrder 校验并发生成时题目顺序与盐值对应关系正确
func TestSolveCapPowOrder(t *testing.T) {
	e := loadExpected(t)
	got := solveCapPow(e.Token, len(e.Salts), e.Challenge.S, e.Challenge.D)
	for i := range got {
		if got[i] != e.Nonces[i] {
			t.Errorf("solveCapPow 第 %d 题 = %d, want %d", i+1, got[i], e.Nonces[i])
		}
	}
}

// TestEvalInstrState 校验 instrumentation 脚本 state 的离线复刻结果
func TestEvalInstrState(t *testing.T) {
	e := loadExpected(t)
	js, err := os.ReadFile("testdata/instr.js")
	if err != nil {
		t.Fatalf("读取脚本样本失败: %v", err)
	}
	got, err := evalInstrState(string(js))
	if err != nil {
		t.Fatalf("解析 state 失败: %v", err)
	}
	if len(got) != len(e.State) {
		t.Fatalf("state 字段数量 = %d, want %d", len(got), len(e.State))
	}
	for k, want := range e.State {
		v, ok := got[k].(int64)
		if !ok {
			t.Fatalf("state[%s] 类型异常: %T", k, got[k])
		}
		if v != want {
			t.Errorf("state[%s] = %d, want %d", k, v, want)
		}
	}
}

// TestBuildInstr 校验完整 instr 构造（nonce、state、指纹、时间戳）
func TestBuildInstr(t *testing.T) {
	e := loadExpected(t)
	buf, err := os.ReadFile("testdata/challenge.json")
	if err != nil {
		t.Fatalf("读取 challenge 样本失败: %v", err)
	}
	var ch capChallengeResp
	if err := json.Unmarshal(buf, &ch); err != nil {
		t.Fatalf("解析 challenge 样本失败: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(ch.Instrumentation); err != nil {
		t.Fatalf("样本 instrumentation 不是合法 base64: %v", err)
	}
	instr, err := buildInstr(ch.Instrumentation)
	if err != nil {
		t.Fatalf("构造 instr 失败: %v", err)
	}
	if instr["i"] != e.NonceInstr {
		t.Errorf("instr.i = %v, want %s", instr["i"], e.NonceInstr)
	}
	state, ok := instr["state"].(map[string]any)
	if !ok {
		t.Fatalf("instr.state 类型异常: %T", instr["state"])
	}
	for k, want := range e.State {
		if got, _ := state[k].(int64); got != want {
			t.Errorf("instr.state[%s] = %v, want %d", k, state[k], want)
		}
	}
	fp, ok := instr["p"].(map[string]any)
	if !ok || fp["ua"] != userAgent || fp["webdriver"] != false {
		t.Errorf("instr.p 指纹异常: %v", instr["p"])
	}
	if ts, _ := instr["ts"].(int64); ts <= 0 {
		t.Errorf("instr.ts 异常: %v", instr["ts"])
	}
}

// TestEvalJSExpr 校验表达式解释器的 32 位运算语义
func TestEvalJSExpr(t *testing.T) {
	vars := map[string]int64{"a": 255, "b": 16, "c": 7}
	fns := map[string]func([]int64) (int64, error){"gm": gmDOMCompute, "cs": csMix}
	cases := []struct {
		expr string
		want int64
	}{
		{"a", 255},
		{"~a", -256},
		{"a & b", 16},
		{"a | b", 255},
		{"a ^ b", 239},
		{"a >> 4", 15},
		{"b << 2", 64},
		{"((a^107065)&0x7FFFFFFF)%900000+100000", 207206},
		{"~0", -1},
		{"cs(a,b,c)", int64(int32(255^16) | int32(16^7))},
	}
	for _, c := range cases {
		got, err := evalJSExpr(c.expr, vars, fns)
		if err != nil {
			t.Errorf("evalJSExpr(%q) 报错: %v", c.expr, err)
			continue
		}
		if got != c.want {
			t.Errorf("evalJSExpr(%q) = %d, want %d", c.expr, got, c.want)
		}
	}
	if _, err := evalJSExpr("1/0", vars, fns); err == nil {
		t.Error("非法表达式应报错")
	}
	if _, err := evalJSExpr("a + ", vars, fns); err == nil {
		t.Error("截断表达式应报错")
	}
}

// TestCsMixAndGMDOM 校验两个运算函数与 JS 语义一致
func TestCsMixAndGMDOM(t *testing.T) {
	if got, _ := csMix([]int64{216, 211, 136}); got != int64(int32(216^211)|int32(211^136)) {
		t.Errorf("csMix 结果异常: %d", got)
	}
	if got, err := gmDOMCompute([]int64{140, 216, 216}); err != nil || got < 0 || got > 255 {
		t.Errorf("gmDOMCompute 结果异常: %d, %v", got, err)
	}
	if _, err := gmDOMCompute([]int64{1, 2}); err == nil {
		t.Error("参数数量错误应报错")
	}
}

// TestExtractCapEndpoint 校验验证码接口地址提取
func TestExtractCapEndpoint(t *testing.T) {
	if got := extractCapEndpoint(`<cap-widget data-cap-api-endpoint="https://capjs.net/abc/">`); got != "https://capjs.net/abc/" {
		t.Errorf("extractCapEndpoint = %q", got)
	}
	if got := extractCapEndpoint(`<cap-widget data-cap-api-endpoint="https://capjs.net/abc">`); got != "https://capjs.net/abc/" {
		t.Errorf("缺少结尾斜杠时应补全: %q", got)
	}
	if got := extractCapEndpoint(`<div>无验证码</div>`); got != "" {
		t.Errorf("无验证码时应返回空: %q", got)
	}
}

// TestExtractSiteError 校验错误页文案提取
func TestExtractSiteError(t *testing.T) {
	// 真实错误页结构：title 里也含「出错了」，正文才是提示文案
	html := `<html><head><title>出错了 - 烧饼论坛</title></head><body>` +
		`<div class="main"><h1>出错了</h1><p>人机验证未通过，请重新验证后再试</p>` +
		`<a href="/">回到首页</a></div><script>var x = "出错了 不应被提取";</script></body></html>`
	got := extractSiteError(html)
	want := "人机验证未通过，请重新验证后再试"
	if got != want {
		t.Errorf("extractSiteError = %q, want %q", got, want)
	}
	if got := extractSiteError(`<html><body>每日签到</body></html>`); got != "" {
		t.Errorf("非错误页应返回空: %q", got)
	}
}

// TestCapGenLength 校验生成长度边界
func TestCapGenLength(t *testing.T) {
	for _, n := range []int{1, 6, 7, 8, 9, 32, 33, 64} {
		if got := capGen("seed"+strconv.Itoa(n), n); len(got) != n {
			t.Errorf("capGen 长度 = %d, want %d", len(got), n)
		}
	}
}
