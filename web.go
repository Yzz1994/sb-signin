package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed static
var staticFS embed.FS

// Server HTTP 服务
type Server struct {
	store *Store
}

func newServer(st *Store) *Server {
	return &Server{store: st}
}

// Handler 构建路由
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/accounts", s.handleAccountUpsert)
	mux.HandleFunc("PUT /api/accounts/{id}", s.handleAccountUpdate)
	mux.HandleFunc("DELETE /api/accounts/{id}", s.handleAccountDelete)
	mux.HandleFunc("POST /api/accounts/{id}/signin", s.handleAccountSignin)
	mux.HandleFunc("POST /api/signin-all", s.handleSigninAll)
	mux.HandleFunc("PUT /api/settings", s.handleSettings)
	mux.HandleFunc("POST /api/telegram/discover-chat-id", s.handleTelegramDiscover)
	mux.HandleFunc("POST /api/verify", s.handleVerify) // 安全码验证（匿名）
	mux.HandleFunc("POST /api/token", s.handleSetToken) // 修改安全码（需鉴权）

	// 静态页面
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return withCORS(s.authMiddleware(mux))
}

// withCORS 允许浏览器扩展跨域调用本地 API
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware 校验安全码（/api/verify 匿名放行）
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/verify" {
			if r.Header.Get("X-Auth-Token") != s.store.getAccessToken() {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "安全码无效"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleVerify 验证安全码（匿名访问）
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if in.Token == "" || in.Token != s.store.getAccessToken() {
		writeErr(w, http.StatusUnauthorized, "安全码错误")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSetToken 修改安全码（已被 authMiddleware 保护，需带当前安全码）
func (s *Server) handleSetToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		NewToken string `json:"new_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	tok := strings.TrimSpace(in.NewToken)
	if len(tok) < 6 {
		writeErr(w, http.StatusBadRequest, "安全码至少 6 位")
		return
	}
	if err := s.store.setAccessToken(tok); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// nextRun 计算下一次签到时间（UTC+8 的 run_hour:run_minute）
func nextRun(st Settings) time.Time {
	now := time.Now().In(cst)
	next := time.Date(now.Year(), now.Month(), now.Day(), st.RunHour, st.RunMinute, 0, 0, cst)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	d := s.store.snapshot()
	st := d.Settings
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": st,
		"accounts": d.Accounts,
		"logs":     d.Logs,
		"next_run": nextRun(st).Format("2006-01-02 15:04:05 MST"),
		"now":      time.Now().In(cst).Format("2006-01-02 15:04:05 MST"),
	})
}

// accountPayload 前端/扩展提交的账号数据
type accountPayload struct {
	Name    string `json:"name"`
	Session string `json:"session"`
	CSRF    string `json:"csrf"`
	Enabled *bool  `json:"enabled"`
}

func (p accountPayload) toAccount() *Account {
	a := &Account{
		Name:    strings.TrimSpace(p.Name),
		Session: strings.TrimSpace(p.Session),
		CSRF:    strings.TrimSpace(p.CSRF),
		Enabled: true,
	}
	if p.Enabled != nil {
		a.Enabled = *p.Enabled
	}
	if a.Session == "" {
		a.Enabled = false
	}
	return a
}

func (s *Server) handleAccountUpsert(w http.ResponseWriter, r *http.Request) {
	var p accountPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	a := p.toAccount()
	if a.Session == "" {
		writeErr(w, http.StatusBadRequest, "缺少登录 Cookie（__Host-bbs_session 的值）")
		return
	}
	acc, err := s.store.upsertAccount(a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p accountPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	err := s.store.updateAccount(id, func(a *Account) {
		if p.Name != "" {
			a.Name = strings.TrimSpace(p.Name)
		}
		if p.Session != "" {
			a.Session = strings.TrimSpace(p.Session)
		}
		if p.CSRF != "" {
			a.CSRF = strings.TrimSpace(p.CSRF)
		}
		if p.Enabled != nil {
			a.Enabled = *p.Enabled
		}
	})
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.deleteAccount(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// runAccountSignin 执行单个账号签到并落库
func (s *Server) runAccountSignin(id string) (SigninResult, bool) {
	a := s.store.getAccount(id)
	if a == nil {
		return SigninResult{Result: "fail", Message: "账号不存在"}, false
	}
	res := doSignin(a)
	s.store.recordResult(id, res)
	return res, true
}

func (s *Server) handleAccountSignin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, ok := s.runAccountSignin(id)
	if !ok {
		writeErr(w, http.StatusNotFound, res.Message)
		return
	}
	log.Printf("[手动签到] %s -> %s: %s", id, res.Result, res.Message)
	a := s.store.getAccount(id)
	name := id
	if a != nil {
		name = a.Name
	}
	s.notifyResults("手动签到", []map[string]any{signinResultMap(id, name, res)})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSigninAll(w http.ResponseWriter, r *http.Request) {
	results := s.signinAll()
	writeJSON(w, http.StatusOK, results)
}

// signinAll 对所有启用的账号签到，返回结果
func (s *Server) signinAll() []map[string]any {
	accounts := s.store.listAccounts()
	results := make([]map[string]any, 0, len(accounts))
	for _, a := range accounts {
		if !a.Enabled {
			continue
		}
		res := doSignin(a)
		s.store.recordResult(a.ID, res)
		log.Printf("[定时签到] %s(%s) -> %s: %s", a.Name, a.ID, res.Result, res.Message)
		results = append(results, signinResultMap(a.ID, a.Name, res))
		time.Sleep(2 * time.Second) // 多账号间隔，避免触发限流
	}
	// 签到完成后推送微信通知
	s.notifyResults("定时签到", results)
	return results
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunHour         *int    `json:"run_hour"`
		RunMinute       *int    `json:"run_minute"`
		RunOnStart      *bool   `json:"run_on_start"`
		NotifyEnabled   *bool   `json:"notify_enabled"`
		NotifySendKey   *string `json:"notify_send_key"`
		TelegramEnabled *bool   `json:"telegram_enabled"`
		TelegramBotToken *string `json:"telegram_bot_token"`
		TelegramChatID  *string `json:"telegram_chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	st := s.store.getSettings()
	if in.RunHour != nil {
		st.RunHour = *in.RunHour
	}
	if in.RunMinute != nil {
		st.RunMinute = *in.RunMinute
	}
	if in.RunOnStart != nil {
		st.RunOnStart = *in.RunOnStart
	}
	if in.NotifyEnabled != nil {
		st.NotifyEnabled = *in.NotifyEnabled
	}
	if in.NotifySendKey != nil {
		st.NotifySendKey = strings.TrimSpace(*in.NotifySendKey)
	}
	if in.TelegramEnabled != nil {
		st.TelegramEnabled = *in.TelegramEnabled
	}
	if in.TelegramBotToken != nil {
		st.TelegramBotToken = strings.TrimSpace(*in.TelegramBotToken)
	}
	if in.TelegramChatID != nil {
		st.TelegramChatID = strings.TrimSpace(*in.TelegramChatID)
	}
	if st.RunHour < 0 || st.RunHour > 23 || st.RunMinute < 0 || st.RunMinute > 59 {
		writeErr(w, http.StatusBadRequest, "时间范围错误（hour 0-23，minute 0-59）")
		return
	}
	s.store.setSettings(st)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTelegramDiscover 自动发现 Telegram Chat ID（长轮询最多 60 秒）
func (s *Server) handleTelegramDiscover(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BotToken string `json:"bot_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	chatID, err := discoverTelegramChatID(strings.TrimSpace(in.BotToken), 60*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"chat_id": chatID})
}
