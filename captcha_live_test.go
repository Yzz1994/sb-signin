package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// 联调测试（默认跳过，需手动开启环境变量）。
// 论坛签到协议（页面地址、人机验证）随时可能调整，改版后可用这两个用例快速自检：
//
//	LIVE_CAP=1    go test -run TestLiveSolveCaptcha -v .   # 仅校验人机验证能否换取 cap-token
//	LIVE_SIGNIN=1 go test -run TestLiveDoSignin -v .       # 用 data.json 首个账号走完整签到流程

const liveCapEndpoint = "https://capjs.net/415786673b/"

// isTransientNetworkError 判断失败信息是否属于可重试的网络抖动
func isTransientNetworkError(msg string) bool {
	for _, kw := range []string{"EOF", "timeout", "timed out", "connection reset", "TLS", "proxy"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

func TestLiveSolveCaptcha(t *testing.T) {
	if os.Getenv("LIVE_CAP") == "" {
		t.Skip("需要 LIVE_CAP=1 手动开启")
	}
	client := &http.Client{Timeout: 90 * time.Second}
	start := time.Now()
	tok, err := solveCaptcha(client, liveCapEndpoint)
	if err != nil {
		t.Fatalf("人机验证失败: %v", err)
	}
	t.Logf("cap-token = %s（耗时 %s）", tok, time.Since(start).Round(time.Millisecond))
}

func TestLiveDoSignin(t *testing.T) {
	if os.Getenv("LIVE_SIGNIN") == "" {
		t.Skip("需要 LIVE_SIGNIN=1 手动开启")
	}
	buf, err := os.ReadFile("data.json")
	if err != nil {
		t.Fatalf("读取 data.json 失败: %v", err)
	}
	var wrapper struct {
		Accounts []*Account `json:"accounts"`
	}
	if err := json.Unmarshal(buf, &wrapper); err != nil {
		t.Fatalf("解析 data.json 失败: %v", err)
	}
	if len(wrapper.Accounts) == 0 {
		t.Fatal("data.json 中没有账号")
	}
	a := *wrapper.Accounts[0]

	// 论坛偶发网络抖动（EOF / 超时）时重试一次，避免误报
	var res SigninResult
	for attempt := 1; ; attempt++ {
		res = doSignin(&a)
		if res.Result != "fail" || attempt >= 3 || !isTransientNetworkError(res.Message) {
			break
		}
		t.Logf("第 %d 次请求网络异常（%s），1 秒后重试", attempt, res.Message)
		time.Sleep(time.Second)
	}
	t.Logf("doSignin -> result=%s message=%q 连续=%d 最长=%d 本月=%d 累计=%d 今日=%d",
		res.Result, res.Message, res.Streak, res.Longest, res.Month, res.Total, res.Today)
	if res.Result == "fail" {
		t.Errorf("签到失败: %s", res.Message)
	}

	// 用无效 cap-token 重复提交，校验错误页文案识别
	client := &http.Client{Timeout: 60 * time.Second}
	html, err := getSigninPage(client, &a)
	if err != nil {
		t.Fatalf("获取页面失败: %v", err)
	}
	csrf := extractCSRF(html)
	if csrf == "" {
		t.Log("页面无 _csrf（已签到且无表单），跳过重复提交测试")
		return
	}
	post, err := postSignin(client, &a, csrf, "invalid-cap-token")
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	t.Logf("无效令牌提交 -> 含今日已签到=%v 错误文案=%q 长度=%d",
		strings.Contains(post, "今日已签到"), extractSiteError(post), len(post))
	if msg := extractSiteError(post); msg == "" {
		t.Log("提示：未识别到站点错误文案（可能已签到或协议已变化）")
	}
}
