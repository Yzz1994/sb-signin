//go:build windows

package main

import (
	"net/url"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// systemProxyURL 读取 Windows 系统代理（Internet Settings），未启用时返回 nil。
func systemProxyURL() *url.URL {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	enable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enable == 0 {
		return nil
	}
	srv, _, err := k.GetStringValue("ProxyServer")
	if err != nil || srv == "" {
		return nil
	}
	// ProxyServer 两种形式："host:port"（所有协议共用）或 "http=a:b;https=c:d"
	pick := srv
	if strings.Contains(srv, "=") {
		pick = ""
		for _, part := range strings.Split(srv, ";") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if kv[0] == "https" || (kv[0] == "http" && pick == "") {
				pick = kv[1]
			}
		}
		if pick == "" {
			return nil
		}
	}
	if !strings.Contains(pick, "://") {
		pick = "http://" + pick
	}
	u, err := url.Parse(pick)
	if err != nil {
		return nil
	}
	return u
}
