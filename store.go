package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Account 单个签到账号
type Account struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`           // 备注名
	Session     string    `json:"session"`        // __Host-bbs_session 的值
	CSRF        string    `json:"csrf,omitempty"` // __Host-bbs_csrf 的值
	Enabled     bool      `json:"enabled"`
	LastSignin  time.Time `json:"last_signin,omitempty"`
	LastResult  string    `json:"last_result,omitempty"` // success / fail / expired / unknown
	LastMessage string    `json:"last_message,omitempty"`
	Streak      int       `json:"streak,omitempty"` // 当前连续
	Longest     int       `json:"longest,omitempty"`
	Month       int       `json:"month,omitempty"`
	Total       int       `json:"total,omitempty"`
	Today       int       `json:"today,omitempty"` // 今日签到人数
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// Settings 全局设置
type Settings struct {
	RunHour      int    `json:"run_hour"`
	RunMinute    int    `json:"run_minute"`
	RunOnStart   bool   `json:"run_on_start"`
	// 微信（Server酱）
	NotifyEnabled bool   `json:"notify_enabled"`
	NotifySendKey string `json:"notify_send_key"`
	// Telegram
	TelegramEnabled  bool   `json:"telegram_enabled"`
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
}

// LogEntry 签到日志
type LogEntry struct {
	Time    time.Time `json:"time"`
	Account string    `json:"account"` // 账号名
	Result  string    `json:"result"`  // success / fail / expired
	Message string    `json:"message"`
}

// Data 持久化数据
type Data struct {
	AccessToken string    `json:"access_token"`
	Settings    Settings  `json:"settings"`
	Accounts    []*Account `json:"accounts"`
	Logs        []LogEntry `json:"logs"`
}

// Store 线程安全的数据存储
type Store struct {
	mu   sync.Mutex
	path string
	data Data
}

const maxLogs = 500

func newStore(path string) (*Store, error) {
	s := &Store{path: path, data: Data{
		Settings: Settings{RunHour: 8, RunMinute: 5, RunOnStart: true},
		Accounts: []*Account{},
		Logs:     []LogEntry{},
	}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 首次运行，用默认值
		}
		return fmt.Errorf("读取 %s: %w", s.path, err)
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return fmt.Errorf("解析 %s: %w", s.path, err)
	}
	if s.data.Accounts == nil {
		s.data.Accounts = []*Account{}
	}
	if s.data.Logs == nil {
		s.data.Logs = []LogEntry{}
	}
	return nil
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// snapshot 返回数据副本（浅拷贝，避免持锁读大对象）
func (s *Store) snapshot() Data {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data
	d.Accounts = append([]*Account{}, s.data.Accounts...)
	d.Logs = append([]LogEntry{}, s.data.Logs...)
	return d
}

func (s *Store) getSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

func (s *Store) getAccessToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.AccessToken
}

func (s *Store) setAccessToken(t string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AccessToken = t
	return s.save()
}

func (s *Store) setSettings(st Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Settings = st
	_ = s.save()
}

func (s *Store) listAccounts() []*Account {
	return s.snapshot().Accounts
}

// upsertAccount 按 Session 去重：Session 已存在则更新，否则新增
func (s *Store) upsertAccount(a *Account) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, acc := range s.data.Accounts {
		if acc.Session != "" && acc.Session == a.Session {
			// 更新已有账号（保留 ID、创建时间）
			a.ID = acc.ID
			a.CreatedAt = acc.CreatedAt
			*acc = *a
			if err := s.save(); err != nil {
				return nil, err
			}
			return acc, nil
		}
	}
	a.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	a.CreatedAt = time.Now()
	if a.Name == "" {
		a.Name = "账号" + a.ID[len(a.ID)-4:]
	}
	s.data.Accounts = append(s.data.Accounts, a)
	if err := s.save(); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) deleteAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.data.Accounts {
		if a.ID == id {
			s.data.Accounts = append(s.data.Accounts[:i], s.data.Accounts[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("账号不存在: %s", id)
}

func (s *Store) updateAccount(id string, patch func(*Account)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data.Accounts {
		if a.ID == id {
			patch(a)
			return s.save()
		}
	}
	return fmt.Errorf("账号不存在: %s", id)
}

func (s *Store) getAccount(id string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data.Accounts {
		if a.ID == id {
			cp := *a
			return &cp
		}
	}
	return nil
}

// recordResult 更新账号签到结果并写日志
func (s *Store) recordResult(id string, res SigninResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data.Accounts {
		if a.ID != id {
			continue
		}
		a.LastSignin = time.Now()
		a.LastResult = res.Result
		a.LastMessage = res.Message
		if res.Result == "success" {
			a.Streak = res.Streak
			a.Longest = res.Longest
			a.Month = res.Month
			a.Total = res.Total
			a.Today = res.Today
		}
		break
	}
	name := id
	for _, a := range s.data.Accounts {
		if a.ID == id {
			name = a.Name
			break
		}
	}
	s.data.Logs = append(s.data.Logs, LogEntry{
		Time:    time.Now(),
		Account: name,
		Result:  res.Result,
		Message: res.Message,
	})
	if len(s.data.Logs) > maxLogs {
		s.data.Logs = s.data.Logs[len(s.data.Logs)-maxLogs:]
	}
	_ = s.save()
}
