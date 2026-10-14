// syncd - a single-binary file sync system.
//
// relay:  runs on a cloud server, publishes a directory ("store") to
//         authorized clients over TLS.
// client: runs on edge PCs, keeps a local mirror of each relay's store
//         under its root directory.
//
// Usage:
//
//	syncd relay --token SECRET --store web-data [--listen :9410] [--share /data/share]
//	syncd client --server SECRET@1.2.3.4:9410 [--server ...] [--root DIR]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const version = "0.1.0"

const usageText = `syncd %s - 单二进制云边文件同步工具（云端 relay / 边缘 client）

【核心概念：root 与 store】
  root(根)  = 边缘 PC 上存放所有同步内容的总目录。
              默认就是 syncd 二进制所在的目录，可用 --root 修改。
  store(店) = 云端用 --store 给自己的内容起的"名字"。
              客户端会在 root 下自动创建同名目录，该云端的所有文件
              严格镜像到这个目录里，互不干扰、绝不触碰 root 之外的东西。

  落盘公式:  <root>/<store>/...
  举例:      边缘把 syncd 放在 /opt/syncd/ 下（root 即 /opt/syncd，默认）
             云端 A: syncd relay --store web-data  ->  /opt/syncd/web-data/
             云端 B: syncd relay --store db-backup ->  /opt/syncd/db-backup/
  云端对应关系:
             云端 --share 目录(默认 /data/share) 里的文件 <-> 客户端 <root>/<store>/ 目录

【服务管理】
  -d 必须跟在 relay/client 后面使用（后台运行，类似 nohup &）：
    syncd relay  [参数] -d     云端：后台启动中继服务
    syncd client [参数] -d     边缘：后台启动客户端服务
    （去掉 -d 则前台运行，便于调试）

  以下为顶层独立命令，不用跟 relay/client，自动作用于本机上的服务：
    syncd -c        检查 relay/client 服务是否存活（有存活则退出码 0）
    syncd -s        停止本机所有正在运行的 syncd 服务
    syncd -l        跟踪查看同步日志，类似 tail -f（Ctrl-C 退出）
    syncd -h        显示本帮助

【云端 relay 参数】
  --token SECRET       访问令牌（必填，可重复传入多个，每个对应一个客户端）
  --store NAME         内容源名字（必填建议设置），即客户端本地目录名
  --listen :9410       监听地址
  --share DIR          要发布的目录（默认 /data/share，往里放文件即同步出去）
  --scan-interval 5s   share 目录扫描周期
  --settle 3s          文件静默期：写入停止多久后才发布（防止拷贝到一半被同步）
  --exec               开启远程执行（默认关闭；开启后持有 token 的人可在本机执行命令）
  --exec-timeout 60s   --exec 单条命令超时，超时自动杀进程
  --plain-http         明文 HTTP 模式：给本机 TLS 网关/隧道（如 https://xxx-9410.test-ai.online
                       这类端口转发服务）转发用，TLS 由网关负责，token 认证不变；
                       直连场景（IP/四层透传）不要开启

【边缘 client 参数】
  --server token@host[:port]   上游云端（必填，可重复传入多个，连多台云端）
  --root DIR                   本地同步根目录（默认：二进制所在目录）
  --tls-insecure               跳过 TLS 证书指纹校验（不推荐）
  --heartbeat 10s              心跳间隔
  --miss-threshold 3           连续心跳失败几次判定掉线并重连
  --concurrency 2              每个服务端的并行下载数
  --rescan-interval 5m         无变化时的本地漂移复查周期
  --trash-days 7               删除的文件在回收站保留天数
  --exec                       交互式远程执行会话（只执行命令，不做同步；不能与 -d 同用）

【使用示例】
  syncd relay -d --token SECRET --store web-data     # 云端：后台启动
  syncd client -d --server SECRET@1.2.3.4:9410       # 边缘：后台启动
  syncd -c                                           # 查看服务状态
  syncd -l                                           # 跟踪日志
  syncd -s                                           # 全部停止

【远程执行 --exec】（可选功能，像 ssh 一样在云端执行命令）
  云端开启:  syncd relay ... --exec        # 不加此参数的云端会拒绝执行请求
  边缘使用:  syncd client --server SECRET@1.2.3.4:9410 --exec
  交互会话:  提示符下输入命令（df -h、curl、systemctl status 等均可），
             输出实时回传；Ctrl-C 取消当前命令；exit 或 Ctrl-D 退出
  说明:      · cd 跨命令生效；单条命令默认 60 秒超时；输出上限 8MB
             · 无 TTY，全屏交互程序（vim/top）不可用，top 请用 top -bn1
             · token 等于云端 shell 权限，请妥善保管，仅在可信网络开启

【默认行为】
  同步规则     = 严格镜像：云端有则下载，云端删则本地删（删的先进回收站）
  本地目录     = <root>/<store>/   （store 名由云端 --store 决定）
  回收站       = <root>/.syncd/trash/<store>/（默认保留 7 天）
  状态/日志    = <二进制目录>/.syncd/{relay,client}.{pid,log}
  断点续传     = 下载中断后自动从 .part 临时文件续传，SHA-256 校验通过才落盘
`

func usage() {
	fmt.Fprintf(os.Stderr, usageText, version)
}

func fatal(err error) {
	log.Fatalf("syncd: %v", err)
}

// tokenList collects repeated --token flags.
type tokenList []string

func (t *tokenList) String() string     { return strings.Join(*t, ",") }
func (t *tokenList) Set(v string) error { *t = append(*t, v); return nil }

// serverList collects repeated --server flags (token@host[:port]).
type serverList []string

func (s *serverList) String() string     { return strings.Join(*s, ",") }
func (s *serverList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Standalone top-level service verbs, checked before subcommands.
	switch os.Args[1] {
	case "-c", "--c", "-check", "--check":
		os.Exit(topCheck())
		return
	case "-s", "--s", "-stop", "--stop":
		topStop()
		return
	case "-l", "--l", "-log", "--log":
		topLog()
		return
	}
	switch os.Args[1] {
	case "relay":
		cmdRelay(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func cmdRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	var tokens tokenList
	fs.Var(&tokens, "token", "access token (repeatable, required)")
	store := fs.String("store", defaultStoreName(), "content source name, becomes the local dir name on clients")
	listen := fs.String("listen", ":"+defaultPort, "listen address")
	share := fs.String("share", defaultShareDir, "directory to publish")
	scanInterval := fs.Duration("scan-interval", 5*time.Second, "share rescan period")
	settle := fs.Duration("settle", 3*time.Second, "file quiet period before it is published")
	execEnabled := fs.Bool("exec", false, "allow clients to run commands on this host (enables --exec)")
	execTimeout := fs.Duration("exec-timeout", defaultExecTout, "per-command timeout for --exec")
	plainHTTP := fs.Bool("plain-http", false, "serve plain HTTP (for TLS-terminating proxies/tunnels in front of this relay)")
	svc := addServiceFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usageText, version)
	}
	fs.Parse(args)
	if handleServiceFlags(svc, fs, "relay", args) {
		return
	}

	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "syncd relay: --token 为必填参数")
		os.Exit(2)
	}
	sm := newServiceManager("relay")
	if !sm.acquire() {
		fmt.Fprintf(os.Stderr, "syncd relay: 已在运行 (pid %d)；请先执行 'syncd -s' 停止\n", mustPID(sm))
		os.Exit(1)
	}
	defer sm.release()
	if err := runRelay(relayOptions{
		tokens:       tokens,
		store:        *store,
		listen:       *listen,
		share:        *share,
		scanInterval: *scanInterval,
		settle:       *settle,
		dataDir:      filepath.Join(executableDir(), ".syncd"),
		execEnabled:  *execEnabled,
		execTimeout:  *execTimeout,
		plainHTTP:    *plainHTTP,
	}); err != nil {
		fatal(err)
	}
}

func mustPID(sm *serviceManager) int {
	pid, _ := sm.readPID()
	return pid
}

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var servers serverList
	fs.Var(&servers, "server", "upstream relay as token@host[:port] (repeatable)")
	root := fs.String("root", executableDir(), "local sync root (default: directory of this binary)")
	tlsInsecure := fs.Bool("tls-insecure", false, "skip TLS certificate pinning check")
	heartbeat := fs.Duration("heartbeat", 10*time.Second, "heartbeat interval")
	missThreshold := fs.Int("miss-threshold", 3, "consecutive heartbeat failures before reconnect")
	concurrency := fs.Int("concurrency", 2, "parallel downloads per server")
	rescanInterval := fs.Duration("rescan-interval", 5*time.Minute, "drift re-check period even without remote changes")
	trashDays := fs.Int("trash-days", 7, "days to keep deleted files in trash")
	execMode := addBool(fs, "", "exec", "interactive remote-exec session with the relay (no sync)")
	svc := addServiceFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usageText, version)
	}
	fs.Parse(args)
	if execMode.v && svc.daemon.v {
		fmt.Fprintln(os.Stderr, "syncd client: --exec 是交互模式，不能与 -d 同时使用")
		os.Exit(2)
	}
	if handleServiceFlags(svc, fs, "client", args) {
		return
	}

	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "syncd client: --server 为必填参数（格式 token@host[:port]）")
		os.Exit(2)
	}
	specs := make([]serverSpec, 0, len(servers))
	for _, s := range servers {
		spec, err := parseServerFlag(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "syncd client: --server %q 格式错误: %v\n", s, err)
			os.Exit(2)
		}
		specs = append(specs, spec)
	}
	if execMode.v {
		if len(specs) != 1 {
			fmt.Fprintln(os.Stderr, "syncd client: --exec 模式只支持一个 --server")
			os.Exit(2)
		}
		e := newEngine(specs[0], clientOptions{root: *root}, newStoreRegistry())
		if err := e.execInteractive(context.Background()); err != nil {
			fatal(err)
		}
		return
	}
	sm := newServiceManager("client")
	if !sm.acquire() {
		fmt.Fprintf(os.Stderr, "syncd client: 已在运行 (pid %d)；请先执行 'syncd -s' 停止\n", mustPID(sm))
		os.Exit(1)
	}
	defer sm.release()
	if err := runClient(context.Background(), clientOptions{
		specs:         specs,
		root:          *root,
		tlsInsecure:   *tlsInsecure,
		heartbeat:     *heartbeat,
		missThreshold: *missThreshold,
		concurrency:   *concurrency,
		rescanInterval: *rescanInterval,
		trashDays:     *trashDays,
	}); err != nil {
		fatal(err)
	}
}

// executableDir returns the directory containing the running binary,
// resolving symlinks. It is the default --root for the client and the
// location of relay TLS certs, so behavior never depends on the
// current working directory (e.g. under systemd).
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return filepath.Dir(exe)
}
