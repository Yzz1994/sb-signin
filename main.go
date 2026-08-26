package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// cst 北京时区（UTC+8），论坛签到按 UTC 计算、UTC+8 每日 08:00 更新
var cst = time.FixedZone("UTC+8", 8*3600)

const tokenLength = 20

const helpText = `烧饼论坛（sb.sb）自动签到助手

用法:
  sb-signin.exe [选项]

选项:
  -port <端口>           Web 服务监听端口（默认 8080）
  -data <文件>           数据文件路径（默认 data.json）
  -show-token            显示当前安全码
  -reset-token [值]      重置安全码；带值则设为自定义值，不带值则随机生成
  -h, -help, --help      显示此帮助

示例:
  sb-signin.exe                          # 正常启动（常驻签到 + Web 管理）
  sb-signin.exe -port 9090               # 指定端口启动
  sb-signin.exe -show-token              # 查看当前安全码
  sb-signin.exe -reset-token             # 随机重置安全码
  sb-signin.exe -reset-token mypass123   # 设置自定义安全码
  sb-signin.exe -reset-token=mypass123   # 同上（等号写法）
`

// cliArgs 命令行参数
type cliArgs struct {
	port       int
	dataPath   string
	showToken  bool
	resetToken bool
	resetValue string // 为空表示随机生成，非空表示自定义
	help       bool
}

// parseArgs 手动解析命令行参数（支持 -reset-token 的可选值）
func parseArgs() cliArgs {
	a := cliArgs{port: 8080, dataPath: "data.json"}
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		cur := args[i]
		switch {
		case cur == "-h" || cur == "-help" || cur == "--help":
			a.help = true

		case cur == "-show-token" || cur == "--show-token":
			a.showToken = true

		case cur == "-reset-token" || cur == "--reset-token":
			a.resetToken = true
			// 空格跟值：下一个参数不是 - 开头，则作为自定义值
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				a.resetValue = args[i]
			}

		case strings.HasPrefix(cur, "-reset-token="):
			a.resetToken = true
			a.resetValue = strings.TrimPrefix(cur, "-reset-token=")

		case cur == "-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					a.port = v
				}
			}

		case strings.HasPrefix(cur, "-port="):
			if v, err := strconv.Atoi(strings.TrimPrefix(cur, "-port=")); err == nil {
				a.port = v
			}

		case cur == "-data":
			if i+1 < len(args) {
				i++
				a.dataPath = args[i]
			}

		case strings.HasPrefix(cur, "-data="):
			a.dataPath = strings.TrimPrefix(cur, "-data=")
		}
	}
	return a
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	cli := parseArgs()
	if cli.help {
		fmt.Print(helpText)
		return
	}

	// 解析数据文件路径（默认 data.json 时，若当前目录不存在则回退到系统服务目录）
	dataFile := resolveDataPath(cli.dataPath)

	// 命令行模式：查看/重置（或自定义）安全码
	if cli.showToken || cli.resetToken {
		st, err := newStore(dataFile)
		if err != nil {
			log.Fatalf("初始化存储失败: %v", err)
		}
		if cli.resetToken {
			var tok string
			if cli.resetValue != "" {
				tok = strings.TrimSpace(cli.resetValue)
				if len(tok) < 6 {
					log.Fatalf("安全码至少 6 位")
				}
			} else {
				tok = generateToken(tokenLength)
			}
			if err := st.setAccessToken(tok); err != nil {
				log.Fatalf("保存安全码失败: %v", err)
			}
			if cli.resetValue != "" {
				fmt.Printf("已设置自定义安全码：\n\n  %s\n\n请用它登录 Web 页面/浏览器扩展。\n", tok)
			} else {
				fmt.Printf("已重置安全码（随机）：\n\n  %s\n\n请妥善保存，并用它登录 Web 页面/浏览器扩展。\n", tok)
			}
			return
		}
		// show-token
		tok := st.getAccessToken()
		if tok == "" {
			fmt.Println("安全码尚未生成，请先正常运行一次程序。")
		} else {
			fmt.Printf("当前安全码：\n\n  %s\n", tok)
		}
		return
	}

	st, err := newStore(dataFile)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	log.Printf("数据文件: %s", dataFile)

	// 首次运行：生成安全码
	if st.getAccessToken() == "" {
		tok := generateToken(tokenLength)
		if err := st.setAccessToken(tok); err != nil {
			log.Fatalf("保存安全码失败: %v", err)
		}
		log.Println("==============================================")
		log.Println("首次运行，已生成安全码（Web 页面/扩展登录用）：")
		log.Printf("    %s", tok)
		log.Println("请妥善保存。可用 -show-token 查看，-reset-token [值] 重置/自定义。")
		log.Println("==============================================")
	}

	srv := newServer(st)

	// 启动签到调度器（常驻，每天到点自动签到所有账号）
	go scheduler(st, srv)

	addr := fmt.Sprintf(":%d", cli.port)
	localIP := getLocalIP()
	log.Printf("Web 管理页面: http://%s%s", localIP, addr)
	if localIP != "127.0.0.1" {
		log.Printf("本机访问: http://127.0.0.1%s", addr)
	}
	log.Printf("浏览器扩展请填写服务地址: http://127.0.0.1%s", addr)
	log.Printf("每日签到时间: UTC+8 %02d:%02d", st.getSettings().RunHour, st.getSettings().RunMinute)

	// 启动时可选立即签到一次
	if st.getSettings().RunOnStart {
		go func() {
			log.Println("按设置 run_on_start=true，启动时立即签到一次...")
			srv.signinAll()
		}()
	}

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("Web 服务启动失败: %v", err)
	}
}

// resolveDataPath 解析数据文件路径。
// 当使用默认路径 "data.json" 且当前目录不存在该文件时，回退到 systemd 服务目录，
// 这样通过服务安装后，直接运行 `sb-signin -show-token` 也能读到安全码。
func resolveDataPath(p string) string {
	if p != "data.json" {
		return p // 显式指定了路径，原样使用
	}
	if _, err := os.Stat("data.json"); err == nil {
		return "data.json"
	}
	const sysPath = "/var/lib/sb-signin/data.json"
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath
	}
	return "data.json"
}

// getLocalIP 获取本机第一个非回环 IPv4 地址
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				// 跳过链路本地地址（169.254.x.x）
				if !ip4.IsLinkLocalUnicast() {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

// scheduler 常驻调度：每天在设定时间对所有账号签到
func scheduler(st *Store, srv *Server) {
	for {
		cfg := st.getSettings()
		next := nextRun(cfg)
		wait := time.Until(next)
		log.Printf("下次签到时间: %s（%s 后）", next.In(cst).Format("2006-01-02 15:04:05 MST"), wait.Round(time.Second))
		time.Sleep(wait)

		log.Println("========== 开始定时签到 ==========")
		results := srv.signinAll()
		if len(results) == 0 {
			log.Println("没有启用的账号，跳过")
		}
		log.Println("========== 定时签到结束 ==========")
	}
}
