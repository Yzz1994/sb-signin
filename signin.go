package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// checkinURL 签到页（旧地址 /signin/ 已 301 跳转到 /checkin/）
	checkinURL = "https://sb.sb/checkin/"
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

// SigninResult 单次签到结果
type SigninResult struct {
	Result  string // success / fail / expired
	Message string
	Streak  int // 当前连续
	Longest int // 最长连续
	Month   int // 本月签到
	Total   int // 累计签到
	Today   int // 今日签到人数
}

// doSignin 对单个账号执行签到。
// 签到机制：GET /checkin/ 页面，若显示「立即签到」按钮则提取 form 中的 _csrf，
// 并在需要时先完成 cap.js 人机验证（见 captcha.go），再 POST /checkin/
// 提交 _csrf + cap-token；若页面显示「今日已签到」说明当天已签到。
func doSignin(a *Account) SigninResult {
	res := SigninResult{Result: "fail"}

	if a.Session == "" {
		res.Message = "缺少登录 Cookie（__Host-bbs_session）"
		return res
	}

	// 超时含人机验证（PoW）耗时：难度提升时求解时间会变长，故给到 120 秒
	client := &http.Client{Timeout: 120 * time.Second}

	// 第一步：GET 签到页面，判断当前状态
	pageHTML, err := getSigninPage(client, a)
	if err != nil {
		res.Message = err.Error()
		return res
	}

	// 登录态失效（被重定向到登录页）
	if isLoginExpired(pageHTML) {
		res.Result = "expired"
		res.Message = "登录态失效，请更新 Cookie"
		return res
	}

	// 当天已签到（显示 disabled 的「今日已签到」）
	if strings.Contains(pageHTML, "今日已签到") {
		res.Result = "success"
		res.Message = "签到成功（今日已签到）"
		parseStats(pageHTML, &res)
		return res
	}

	// 尚未签到：提取页面里的 _csrf 令牌
	csrf := extractCSRF(pageHTML)
	if csrf == "" {
		res.Message = "未找到签到令牌（_csrf），无法提交签到"
		return res
	}

	// 需要人机验证时先过验证，拿到 cap-token
	capToken := ""
	if ep := extractCapEndpoint(pageHTML); ep != "" {
		tok, err := solveCaptcha(client, ep)
		if err != nil {
			res.Message = "人机验证失败: " + err.Error()
			return res
		}
		capToken = tok
	}

	// 第二步：POST /checkin/ 提交 _csrf（与 cap-token），真正完成签到
	postHTML, err := postSignin(client, a, csrf, capToken)
	if err != nil {
		res.Message = err.Error()
		return res
	}

	if strings.Contains(postHTML, "今日已签到") {
		res.Result = "success"
		res.Message = "签到成功（本次完成签到）"
		parseStats(postHTML, &res)
		return res
	}

	// 站点错误页（如「人机验证未通过」）
	if msg := extractSiteError(postHTML); msg != "" {
		res.Message = "签到失败: " + msg
		return res
	}

	// 仍停留在未签到页面，说明提交未生效
	if strings.Contains(postHTML, "signin-form") {
		res.Message = "签到未生效（页面仍显示未签到）"
		return res
	}

	res.Message = fmt.Sprintf("无法识别签到结果（长度 %d）", len(postHTML))
	return res
}

// newSigninRequest 构造带登录 Cookie 的签到请求
func newSigninRequest(method, target string, a *Account) (*http.Request, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.AddCookie(&http.Cookie{Name: "__Host-bbs_session", Value: a.Session})
	if a.CSRF != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-bbs_csrf", Value: a.CSRF})
	}
	return req, nil
}

// doRequest 执行请求并读取响应体（限制 1MB）
func doRequest(client *http.Client, req *http.Request) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getSigninPage GET 签到页面并返回 HTML
func getSigninPage(client *http.Client, a *Account) (string, error) {
	req, err := newSigninRequest(http.MethodGet, checkinURL, a)
	if err != nil {
		return "", fmt.Errorf("构造请求失败: %w", err)
	}
	html, err := doRequest(client, req)
	if err != nil {
		return "", fmt.Errorf("获取签到页面失败: %w", err)
	}
	return html, nil
}

// isLoginExpired 判断响应是否已跳转到登录页
func isLoginExpired(html string) bool {
	return strings.Contains(html, `action="/login/"`) || strings.Contains(html, "<title>登录")
}

var (
	reNoiseTags = regexp.MustCompile(`(?is)<(script|style|title|noscript)[^>]*>.*?</(script|style|title|noscript)>`)
	reTags      = regexp.MustCompile(`<[^>]*>`)
	reSpaces    = regexp.MustCompile(`\s+`)
)

// stripTags 去掉脚本/样式/标题与 HTML 标签并压缩空白，便于提取页面文案
func stripTags(html string) string {
	text := reNoiseTags.ReplaceAllString(html, " ")
	text = reTags.ReplaceAllString(text, " ")
	return reSpaces.ReplaceAllString(text, " ")
}

// extractSiteError 从错误页中提取提示文案（如「人机验证未通过，请重新验证后再试」）
func extractSiteError(html string) string {
	if !strings.Contains(html, "出错了") {
		return ""
	}
	text := stripTags(html)
	i := strings.Index(text, "出错了")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(text[i+len("出错了"):])
	if j := strings.Index(rest, "回到首页"); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(rest)
	if len(rest) > 120 {
		rest = rest[:120]
	}
	return rest
}

// extractCSRF 从签到页面 HTML 提取 form 中的 _csrf 令牌
func extractCSRF(html string) string {
	m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(html)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// postSignin POST /checkin/ 提交 _csrf（与 cap-token），真正完成签到
func postSignin(client *http.Client, a *Account, csrf, capToken string) (string, error) {
	form := url.Values{"_csrf": {csrf}, "message": {""}}
	if capToken != "" {
		form.Set("cap-token", capToken)
	}
	req, err := http.NewRequest(http.MethodPost, checkinURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("构造签到请求失败: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://sb.sb")
	req.Header.Set("Referer", checkinURL)
	req.AddCookie(&http.Cookie{Name: "__Host-bbs_session", Value: a.Session})
	if a.CSRF != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-bbs_csrf", Value: a.CSRF})
	}
	html, err := doRequest(client, req)
	if err != nil {
		return "", fmt.Errorf("提交签到失败: %w", err)
	}
	return html, nil
}

// signinResultMap 把签到结果转成通知/接口用的 map（含统计字段）
func signinResultMap(id, name string, res SigninResult) map[string]any {
	return map[string]any{
		"id":      id,
		"name":    name,
		"result":  res.Result,
		"message": res.Message,
		"streak":  res.Streak,
		"longest": res.Longest,
		"month":   res.Month,
		"total":   res.Total,
		"today":   res.Today,
	}
}

// parseStats 从签到页 HTML 提取统计信息
func parseStats(html string, res *SigninResult) {
	if m := regexp.MustCompile(`signin-streak-num">(\d+)<`).FindStringSubmatch(html); len(m) > 1 {
		res.Streak, _ = strconv.Atoi(m[1])
	}
	// signin-stat-value 顺序：最长连续 / 本月签到 / 累计签到 / 今日签到人数
	vals := regexp.MustCompile(`signin-stat-value">(\d+)<`).FindAllStringSubmatch(html, -1)
	nums := make([]int, 0, len(vals))
	for _, v := range vals {
		n, _ := strconv.Atoi(v[1])
		nums = append(nums, n)
	}
	if len(nums) >= 1 {
		res.Longest = nums[0]
	}
	if len(nums) >= 2 {
		res.Month = nums[1]
	}
	if len(nums) >= 3 {
		res.Total = nums[2]
	}
	if len(nums) >= 4 {
		res.Today = nums[3]
	}
}
