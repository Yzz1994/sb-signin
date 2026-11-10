package main

import (
	"net/http"
	"net/url"
	"time"
)

// newHTTPClient 构造签到流程使用的 HTTP 客户端。
// 论坛对部分地区做了访问限制（返回「暂未对您所在地区开放」），浏览器用户
// 通过系统代理正常访问；因此这里同样读取 Windows 系统代理设置，
// 未配置代理时直连（环境变量 HTTP_PROXY/HTTPS_PROXY 优先）。
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 proxyFunc(),
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
	}
}

// proxyFunc 代理选择：环境变量 → 系统代理 → 直连
func proxyFunc() func(*http.Request) (*url.URL, error) {
	env := http.ProxyFromEnvironment
	sys := systemProxyURL()
	if sys == nil {
		return env
	}
	return func(req *http.Request) (*url.URL, error) {
		if u, err := env(req); err != nil || u != nil {
			return u, err
		}
		host := req.URL.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil, nil
		}
		return sys, nil
	}
}
