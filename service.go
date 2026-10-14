package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Service lifecycle management.
//
//   -d  runs WITH a subcommand:   syncd relay -d ...   /  syncd client -d ...
//   -c  -s  -l  -h are standalone top-level verbs:  syncd -c / -s / -l / -h
//
// They act on every syncd service found on this machine (relay and/or
// client), discovered via pid/log files in <binary dir>/.syncd/.
// ---------------------------------------------------------------------------

var serviceRoles = []string{"relay", "client"}

type serviceManager struct {
	role    string
	pidFile string
	logFile string
}

func newServiceManager(role string) *serviceManager {
	dir := filepath.Join(executableDir(), ".syncd")
	return &serviceManager{
		role:    role,
		pidFile: filepath.Join(dir, role+".pid"),
		logFile: filepath.Join(dir, role+".log"),
	}
}

func (s *serviceManager) readPID() (int, bool) {
	data, err := os.ReadFile(s.pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func (s *serviceManager) writePID(pid int) error {
	if err := os.MkdirAll(filepath.Dir(s.pidFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.pidFile, []byte(strconv.Itoa(pid)), 0o644)
}

func (s *serviceManager) removePID() { _ = os.Remove(s.pidFile) }

// runningPID returns the pid of a live instance, if any (stale pid files are
// detected via a liveness probe and treated as not running).
func (s *serviceManager) runningPID() (int, bool) {
	pid, ok := s.readPID()
	if !ok {
		return 0, false
	}
	if !isAlive(pid) {
		return 0, false
	}
	return pid, true
}

// acquire claims the pid file for this process; returns false if another
// live instance already owns it.
func (s *serviceManager) acquire() bool {
	if pid, ok := s.readPID(); ok && pid != os.Getpid() && isAlive(pid) {
		return false
	}
	if err := s.writePID(os.Getpid()); err != nil {
		return false
	}
	return true
}

// release drops the pid file if this process still owns it.
func (s *serviceManager) release() {
	if pid, ok := s.readPID(); ok && pid == os.Getpid() {
		s.removePID()
	}
}

// stopService gracefully stops the running instance (SIGTERM, then force
// kill after a grace period). Returns nil when nothing was running.
func (s *serviceManager) stopService() (int, error) {
	pid, ok := s.runningPID()
	if !ok {
		s.removePID() // clean up a stale pid file if present
		return 0, nil
	}
	if err := stopProcess(pid); err != nil {
		return pid, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for isAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if isAlive(pid) {
		_ = forceKill(pid)
		time.Sleep(500 * time.Millisecond)
	}
	s.removePID()
	return pid, nil
}

// daemonize re-executes this binary without -d, detached from the terminal,
// with stdout/stderr appended to the role log file.
func (s *serviceManager) daemonize(args []string) {
	if pid, ok := s.runningPID(); ok {
		fmt.Fprintf(os.Stderr, "syncd %s: already running (pid %d)\n", s.role, pid)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(s.logFile), 0o700); err != nil {
		fatal(err)
	}
	logf, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fatal(err)
	}
	defer logf.Close()

	self, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	// Re-run with the role subcommand in front: the child sees
	// "syncd relay --token ..." instead of a bare "--token ...".
	cmdArgs := append([]string{s.role}, filterDaemonArgs(args)...)
	cmd := exec.Command(self, cmdArgs...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Env = append(os.Environ(), "SYNCD_CHILD=1")
	cmd.SysProcAttr = daemonProcAttr()
	if err := cmd.Start(); err != nil {
		fatal(fmt.Errorf("start background service: %w", err))
	}
	fmt.Printf("syncd %s 已在后台启动 (pid %d)\n", s.role, cmd.Process.Pid)
	fmt.Printf("查看日志: syncd -l\n")
	fmt.Printf("停止服务: syncd -s\n")
	os.Exit(0)
}

// filterDaemonArgs strips every spelling of the -d flag before re-exec.
func filterDaemonArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "-d", "--d", "-daemon", "--daemon":
			continue
		}
		out = append(out, a)
	}
	return out
}

// ---------------------------------------------------------------------------
// Top-level verbs: syncd -c / -s / -l.
// ---------------------------------------------------------------------------

// topCheck reports the status of every service found on this machine.
// Exit code 0 = at least one running, 1 = none running (script friendly).
func topCheck() int {
	any := false
	for _, role := range serviceRoles {
		sm := newServiceManager(role)
		if pid, ok := sm.runningPID(); ok {
			fmt.Printf("%s: 运行中 (pid %d)\n", role, pid)
			any = true
			continue
		}
		if _, exists := sm.readPID(); exists {
			sm.removePID() // stale pid file
			fmt.Printf("%s: 未运行（已清理残留 pid 文件）\n", role)
		} else {
			fmt.Printf("%s: 未运行\n", role)
		}
	}
	if any {
		return 0
	}
	return 1
}

// topStop stops every running syncd service on this machine.
func topStop() {
	stopped := 0
	for _, role := range serviceRoles {
		sm := newServiceManager(role)
		pid, ok := sm.runningPID()
		if !ok {
			continue
		}
		fmt.Printf("正在停止 %s (pid %d)... ", role, pid)
		if _, err := sm.stopService(); err != nil {
			fmt.Println()
			fatal(fmt.Errorf("stop %s: %w", role, err))
		}
		fmt.Println("已停止。")
		stopped++
	}
	if stopped == 0 {
		fmt.Println("没有正在运行的 syncd 服务。")
	}
}

// topLog implements syncd -l: tail -f every log file that exists.
func topLog() {
	var targets []logTarget
	for _, role := range serviceRoles {
		sm := newServiceManager(role)
		if _, err := os.Stat(sm.logFile); err == nil {
			targets = append(targets, logTarget{role: role, path: sm.logFile})
		}
	}
	if len(targets) == 0 {
		fmt.Println("尚未找到 syncd 日志（请先启动服务）。")
		os.Exit(1)
	}
	fmt.Printf("== 跟踪日志中（Ctrl-C 退出）\n")
	if err := followLogs(targets); err != nil {
		fatal(err)
	}
}

// lineWriter prefixes every complete line with a role tag when following
// more than one log file.
type lineWriter struct {
	prefix  []byte
	pending []byte // incomplete line carried over between reads
}

func (w *lineWriter) write(data []byte) {
	w.pending = append(w.pending, data...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			return
		}
		os.Stdout.Write(w.prefix)
		os.Stdout.Write(w.pending[:i+1])
		w.pending = w.pending[i+1:]
	}
}

// ---------------------------------------------------------------------------
// tail -f, supporting one or more files.
// ---------------------------------------------------------------------------

type logTarget struct {
	role string
	path string
}

// followLogs prints the recent history of each file, then follows them all
// until interrupted. With multiple files every line is prefixed by its role.
func followLogs(targets []logTarget) error {
	prefix := len(targets) > 1
	writers := make([]*lineWriter, len(targets))
	files := make([]*os.File, len(targets))
	offsets := make([]int64, len(targets))

	for i, t := range targets {
		f, err := os.Open(t.path)
		if err != nil {
			return err
		}
		defer f.Close()
		files[i] = f
		p := ""
		if prefix {
			p = "[" + t.role + "] "
		}
		writers[i] = &lineWriter{prefix: []byte(p)}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		var off int64
		if st.Size() > 8<<10 {
			off = st.Size() - 8<<10
		}
		data := make([]byte, st.Size()-off)
		if _, err := f.ReadAt(data, off); err != nil && err != io.EOF {
			return err
		}
		if off > 0 { // drop the partial first line
			if j := bytes.IndexByte(data, '\n'); j >= 0 {
				data = data[j+1:]
			} else {
				data = nil
			}
		}
		writers[i].write(data)
		offsets[i] = st.Size()
	}

	for {
		time.Sleep(300 * time.Millisecond)
		for i, t := range targets {
			st, err := os.Stat(t.path)
			if err != nil {
				continue
			}
			if st.Size() < offsets[i] {
				offsets[i] = 0 // truncated or rotated
			}
			if st.Size() > offsets[i] {
				chunk := make([]byte, st.Size()-offsets[i])
				n, err := files[i].ReadAt(chunk, offsets[i])
				if n > 0 {
					writers[i].write(chunk[:n])
				}
				if err != nil && err != io.EOF {
					return err
				}
				offsets[i] = st.Size()
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Repeated boolean flags with short and long spellings (-d / --daemon).
// ---------------------------------------------------------------------------

type aliasBool struct{ v bool }

func (a *aliasBool) String() string   { return strconv.FormatBool(a.v) }
func (a *aliasBool) IsBoolFlag() bool { return true }
func (a *aliasBool) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	a.v = b
	return nil
}

func addBool(fs *flag.FlagSet, short, long, usage string) *aliasBool {
	a := &aliasBool{}
	if short != "" {
		fs.Var(a, short, "shorthand for -"+long)
	}
	fs.Var(a, long, usage)
	return a
}

type serviceFlags struct {
	daemon, help *aliasBool
}

// addServiceFlags adds the only flags allowed together with a subcommand:
// -d (daemonize) and -h (usage).
func addServiceFlags(fs *flag.FlagSet) serviceFlags {
	return serviceFlags{
		daemon: addBool(fs, "d", "daemon", "run in the background (like nohup &)"),
		help:   addBool(fs, "h", "help", "show usage"),
	}
}

// handleServiceFlags returns true when a subcommand-scoped flag consumed the
// invocation (caller should return immediately).
func handleServiceFlags(sf serviceFlags, fs *flag.FlagSet, role string, args []string) bool {
	if sf.help.v {
		fs.Usage()
		return true
	}
	if sf.daemon.v {
		newServiceManager(role).daemonize(args)
		return true
	}
	return false
}
