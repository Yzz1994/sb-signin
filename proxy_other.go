//go:build !windows

package main

import "net/url"

// systemProxyURL 非 Windows 平台暂不读取系统代理（可由环境变量 HTTP_PROXY 提供）
func systemProxyURL() *url.URL { return nil }
