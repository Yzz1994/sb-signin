package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	serverChanURL  = "https://sctapi.ftqq.com/%s.send"
	telegramAPIURL = "https://api.telegram.org/bot%s/sendMessage"
)

// sendServerChan 通过 Server酱 推送微信通知
func sendServerChan(sendKey, title, desp string) error {
	if sendKey == "" {
		return fmt.Errorf("未配置 Server酱 SendKey")
	}
	payload, _ := json.Marshal(map[string]string{
		"title": title,
		"desp":  desp,
	})
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf(serverChanURL, sendKey), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Server酱失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &result)
	if result.Code != 0 {
		return fmt.Errorf("Server酱返回错误(code=%d): %s", result.Code, result.Message)
	}
	return nil
}

// sendTelegram 通过 Telegram Bot 推送通知（HTML 格式）
func sendTelegram(botToken, chatID, text string) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("未配置 Telegram Bot Token 或 Chat ID")
	}
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf(telegramAPIURL, botToken), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Telegram 失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &result)
	if !result.OK {
		return fmt.Errorf("Telegram 返回错误: %s", result.Description)
	}
	return nil
}

// htmlEscape 转义 HTML 特殊字符（Telegram parse_mode=HTML 需要）
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// discoverTelegramChatID 通过 getUpdates 自动发现 Chat ID。
// 用户需要在 wait 时间内给 Bot 发送任意一条消息。
func discoverTelegramChatID(botToken string, wait time.Duration) (string, error) {
	if botToken == "" {
		return "", fmt.Errorf("请先填写 Bot Token")
	}
	deadline := time.Now().Add(wait)
	var offset int64
	first := true

	for time.Now().Before(deadline) {
		// 首次快速查询（不带长轮询），看是否有历史消息；之后长轮询等新消息
		timeout := 50
		if first {
			timeout = 0
		}
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=%d", botToken, timeout)
		if offset > 0 {
			url += fmt.Sprintf("&offset=%d", offset)
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("请求 Telegram 失败: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		var upd struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
			Result      []struct {
				UpdateID int64 `json:"update_id"`
				Message  *struct {
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
				} `json:"message"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &upd); err != nil {
			return "", fmt.Errorf("解析 Telegram 响应失败: %w", err)
		}
		if !upd.OK {
			return "", fmt.Errorf("Telegram 返回错误: %s", upd.Description)
		}

		for _, u := range upd.Result {
			if u.Message != nil && u.Message.Chat.ID != 0 {
				return strconv.FormatInt(u.Message.Chat.ID, 10), nil
			}
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
		}
		first = false
	}
	return "", fmt.Errorf("超时未收到消息，请先给 Bot 发送任意消息后重试")
}

// signinRow 通知用的单账号签到结果行
type signinRow struct {
	name, msg, result      string
	streak, month, total, longest int
}

// notifyResults 汇总签到结果并推送通知（微信 + Telegram 独立发送）
func (s *Server) notifyResults(trigger string, results []map[string]any) {
	cfg := s.store.getSettings()
	if len(results) == 0 {
		return
	}
	if !cfg.NotifyEnabled && !cfg.TelegramEnabled {
		return
	}

	var (
		success, failed, expired int
		rows                     []signinRow
	)
	for _, r := range results {
		res := asStr(r, "result")
		switch res {
		case "success":
			success++
		case "expired":
			expired++
		default:
			failed++
		}
		rows = append(rows, signinRow{
			name:   asStr(r, "name"),
			msg:    asStr(r, "message"),
			result: res,
			streak: asInt(r, "streak"),
			month:  asInt(r, "month"),
			total:  asInt(r, "total"),
			longest: asInt(r, "longest"),
		})
	}

	title := fmt.Sprintf("烧饼签到[%s] 成功%d 失败%d 失效%d", trigger, success, failed, expired)
	nowStr := time.Now().In(cst).Format("2006-01-02 15:04:05 MST")

	// 微信（Server酱）
	if cfg.NotifyEnabled {
		var lines []string
		for _, r := range rows {
			lines = append(lines, formatLine(r, "**%s**", "\n"))
		}
		desp := strings.Join(lines, "\n\n") + "\n\n---\n" + fmt.Sprintf("时间：%s", nowStr)
		if err := sendServerChan(cfg.NotifySendKey, title, desp); err != nil {
			log.Printf("微信通知发送失败: %v", err)
		} else {
			log.Printf("微信通知已发送：%s", title)
		}
	}

	// Telegram
	if cfg.TelegramEnabled {
		var lines []string
		for _, r := range rows {
			lines = append(lines, formatLine(r, "<b>%s</b>", "\n"))
		}
		text := "<b>" + htmlEscape(title) + "</b>\n\n" + strings.Join(lines, "\n") + "\n\n时间：" + nowStr
		if err := sendTelegram(cfg.TelegramBotToken, cfg.TelegramChatID, text); err != nil {
			log.Printf("Telegram 通知发送失败: %v", err)
		} else {
			log.Printf("Telegram 通知已发送：%s", title)
		}
	}
}

// formatLine 构造单账号通知行。nameFmt 为名字的格式模板（如 "**%s**" 或 "<b>%s</b>"）
func formatLine(r signinRow, nameFmt, sep string) string {
	name := r.name
	if nameFmt == "<b>%s</b>" {
		name = htmlEscape(r.name)
	}
	line := fmt.Sprintf("%s %s：%s", iconFor(r.result), fmt.Sprintf(nameFmt, name), r.msg)
	if r.result == "success" {
		line += fmt.Sprintf("%s连续 %d 天 · 本月 %d 次 · 累计 %d 次 · 最长 %d 天", sep, r.streak, r.month, r.total, r.longest)
	}
	return line
}

// asStr 从 map 中安全读取 string
func asStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// asInt 从 map 中安全读取 int（兼容 int/int64/float64）
func asInt(m map[string]any, key string) int {
	switch n := m[key].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func iconFor(result string) string {
	switch result {
	case "success":
		return "✅"
	case "expired":
		return "❌"
	default:
		return "⚠️"
	}
}
