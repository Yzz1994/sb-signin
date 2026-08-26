package main

import (
	"crypto/rand"
	"math/big"
)

const tokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// generateToken 生成指定长度的随机安全码（字母数字）
func generateToken(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(tokenChars)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			// 极低概率失败时回退到单字节取模
			var rb [1]byte
			_, _ = rand.Read(rb[:])
			b[i] = tokenChars[int(rb[0])%len(tokenChars)]
			continue
		}
		b[i] = tokenChars[idx.Int64()]
	}
	return string(b)
}
