package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	signinURL = "https://sb.sb/signin/"
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
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

// doSignin 对单个账号执行签到（访问 /signin/ 即签到）
func doSignin(a *Account) SigninResult {
	res := SigninResult{Result: "fail"}

	if a.Session == "" {
		res.Message = "缺少登录 Cookie（__Host-bbs_session）"
		return res
	}

	req, err := http.NewRequest(http.MethodGet, signinURL, nil)
	if err != nil {
		res.Message = "构造请求失败: " + err.Error()
		return res
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.AddCookie(&http.Cookie{Name: "__Host-bbs_session", Value: a.Session})
	if a.CSRF != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-bbs_csrf", Value: a.CSRF})
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		res.Message = "请求失败: " + err.Error()
		return res
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		res.Message = "读取响应失败: " + err.Error()
		return res
	}
	html := string(body)

	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(html, "今日已签到"):
		res.Result = "success"
		res.Message = "签到成功（今日已签到）"
		parseStats(html, &res)

	case resp.StatusCode == http.StatusOK && strings.Contains(html, "signin-panel"):
		res.Result = "success"
		res.Message = "签到成功（本次完成签到）"
		parseStats(html, &res)

	case strings.Contains(html, `action="/login/"`):
		res.Result = "expired"
		res.Message = "登录态失效，请更新 Cookie"

	default:
		res.Message = fmt.Sprintf("无法识别响应（HTTP %d，长度 %d）", resp.StatusCode, len(html))
	}
	return res
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
