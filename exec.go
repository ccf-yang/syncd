package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Remote command execution (--exec): a minimal ssh-like channel on top of
// the existing TLS+token infrastructure.
//
//   - the relay must be started with --exec to accept requests (opt-in,
//     because a token holder gets a shell on the relay host)
//   - the client runs `syncd client --server token@host --exec` for an
//     interactive session; each command is POSTed and its output is
//     streamed back in JSON chunks
//   - stdout+stderr are merged, base64-encoded, output-capped, and the
//     command is killed on timeout / client disconnect
// ---------------------------------------------------------------------------

const (
	execPath          = "/ctl/exec"
	maxExecReqBody    = 64 << 10 // 64 KiB cap on exec requests
	defaultExecOutput = 8 << 20  // 8 MiB cap on captured output
	defaultExecTout   = 60 * time.Second
)

type execRequest struct {
	Cmd string `json:"cmd"`
	Cwd string `json:"cwd"` // client-tracked working directory ("" = server default)
}

// execChunk is one line of the streamed response.
type execChunk struct {
	Type string `json:"type"`           // "out" | "err" | "exit"
	Data string `json:"data,omitempty"` // base64 of output bytes (out/err)
	Code int    `json:"code,omitempty"` // process exit code (exit)
	Cwd  string `json:"cwd,omitempty"`  // working dir after the command (exit)
}

// ---------------------------------------------------------------------------
// Server side.
// ---------------------------------------------------------------------------

func (r *relayServer) handleExec(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	if !r.opts.execEnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "exec is not enabled on this relay (start with --exec)"})
		return
	}
	var er execRequest
	req.Body = http.MaxBytesReader(w, req.Body, maxExecReqBody)
	if err := json.NewDecoder(req.Body).Decode(&er); err != nil || strings.TrimSpace(er.Cmd) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad exec request"})
		return
	}

	// resolveCd returns the (possibly new) working directory; it only
	// changes it when the target exists, so the shell surfaces its own
	// error otherwise.
	cwd, _ := r.execWorkdir(er)
	ctx, cancel := context.WithTimeout(req.Context(), r.opts.execTimeout)
	defer cancel()

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Flush the headers right away so clients don't wait for the first
	// output chunk (commands may produce nothing for a long time).
	if flusher != nil {
		flusher.Flush()
	}
	send := func(c execChunk) {
		_ = json.NewEncoder(w).Encode(c)
		if flusher != nil {
			flusher.Flush()
		}
	}

	shell, args := "sh", []string{"-c", er.Cmd}
	if runtime.GOOS == "windows" {
		shell, args = "cmd", []string{"/C", er.Cmd}
	}
	// execCommandContext kills the whole process group on timeout/disconnect,
	// so grandchild processes cannot outlive the command.
	command := execCommandContext(ctx, shell, args...)
	command.Dir = cwd

	stdout, err := command.StdoutPipe()
	if err != nil {
		send(execChunk{Type: "err", Data: b64(err.Error())})
		send(execChunk{Type: "exit", Code: -1, Cwd: cwd})
		return
	}
	command.Stderr = command.Stdout // merge stderr into the same stream

	if err := command.Start(); err != nil {
		send(execChunk{Type: "err", Data: b64(err.Error())})
		send(execChunk{Type: "exit", Code: -1, Cwd: cwd})
		return
	}

	capped := false
	var total int64
	buf := make([]byte, 32<<10)
	reader := bufio.NewReader(stdout)
	for {
		n, rerr := reader.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > r.opts.execOutputCap {
				capped = true
				cancel() // kill the process
				break
			}
			send(execChunk{Type: "out", Data: b64(string(buf[:n]))})
		}
		if rerr != nil {
			break
		}
	}

	waitErr := command.Wait()
	if capped {
		send(execChunk{Type: "err", Data: b64(fmt.Sprintf(
			"output limit exceeded (%d MiB), command killed", r.opts.execOutputCap>>20))})
		send(execChunk{Type: "exit", Code: -1, Cwd: cwd})
		return
	}
	code := 0
	if waitErr != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = ee.ExitCode()
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		send(execChunk{Type: "err", Data: b64(fmt.Sprintf(
			"timed out after %s, command killed", r.opts.execTimeout))})
	}
	// Report the (possibly updated) working directory so the client's
	// `cd` persists across commands.
	send(execChunk{Type: "exit", Code: code, Cwd: cwd})
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// execWorkdir resolves the working directory for a command.
func (r *relayServer) execWorkdir(er execRequest) (string, bool) {
	cwd := strings.TrimSpace(er.Cwd)
	if cwd == "" || !filepath.IsAbs(cwd) {
		cwd = defaultCwd()
	}
	if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
		cwd = defaultCwd()
	}
	return resolveCd(er.Cmd, cwd)
}

// defaultCwdFn is a variable so tests can pin the home directory.
var defaultCwdFn = defaultCwd

func defaultCwd() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}

// resolveCd: if cmd starts with `cd`, compute the target directory (only
// when it exists, so the shell surfaces its own error otherwise) and return
// it; otherwise return cwd unchanged.
func resolveCd(cmd, cwd string) (dir string, changed bool) {
	seg := firstShellSegment(cmd)
	fields := strings.Fields(seg)
	if len(fields) == 0 || fields[0] != "cd" {
		return cwd, false
	}
	arg := "~"
	if len(fields) >= 2 {
		arg = stripQuotes(strings.Join(fields[1:], " "))
	}
	switch arg {
	case "", "~":
		return defaultCwdFn(), true
	case "-":
		return cwd, false // OLDPWD not tracked; keep current dir
	}
	if strings.HasPrefix(arg, "~") {
		arg = filepath.Join(defaultCwdFn(), strings.TrimPrefix(arg, "~"))
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(cwd, arg)
	}
	arg = filepath.Clean(arg)
	if st, err := os.Stat(arg); err == nil && st.IsDir() {
		return arg, true
	}
	return cwd, false // let the shell print its own "No such file" error
}

// firstShellSegment returns the part of cmd before any && || ; | & or
// newline, i.e. the segment a leading `cd` must be parsed from.
func firstShellSegment(cmd string) string {
	seg := cmd
	for _, sep := range []string{"&&", "||", ";", "|", "&", "\n"} {
		if i := strings.Index(seg, sep); i >= 0 {
			seg = seg[:i]
		}
	}
	return seg
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Client side.
// ---------------------------------------------------------------------------

// execInteractive runs the --exec session: connect, then loop reading
// commands from stdin and streaming results to the terminal. Ctrl-C cancels
// the running command (or kills the process while sitting at the prompt).
func (e *engine) execInteractive(ctx context.Context) error {
	e.clientMu.Lock()
	e.ensureHTTP()
	e.clientMu.Unlock()

	ar, err := e.auth(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	store := sanitizeStoreName(ar.Store)
	fmt.Printf("connected to %s (store: %s)，输入 'exit' 或 Ctrl-D 退出\n", e.spec.addr, store)

	sig := make(chan os.Signal, 1)
	reader := bufio.NewReader(os.Stdin)
	cwd := ""
	for {
		prompt := cwd
		if prompt == "" {
			prompt = "~"
		}
		fmt.Printf("%s %s$ ", store, prompt)
		line, rerr := reader.ReadString('\n')
		if rerr != nil {
			fmt.Println()
			return nil // EOF (Ctrl-D)
		}
		cmdStr := strings.TrimSpace(line)
		if cmdStr == "" {
			continue
		}
		switch cmdStr {
		case "exit", "quit", "logout":
			return nil
		}

		cmdCtx, cancel := context.WithCancel(ctx)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			select {
			case <-sig:
				cancel()
				fmt.Println("^C")
			case <-done:
			}
		}()
		code, err := e.execOnce(cmdCtx, cwd, cmdStr, &cwd)
		cancel()
		signal.Stop(sig)
		close(done)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Printf("错误: %v\n", err)
			continue
		}
		if code != 0 {
			fmt.Printf("(exit %d)\n", code)
		}
	}
}

// execOnce runs one command on the relay and streams its chunks to the
// terminal, tracking the working directory the relay reports back.
func (e *engine) execOnce(ctx context.Context, cwd, cmdStr string, newCwd *string) (int, error) {
	body, _ := json.Marshal(execRequest{Cmd: cmdStr, Cwd: cwd})
	u := url.URL{Scheme: "https", Host: e.spec.addr, Path: execPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return -1, err
	}
	req.Header.Set(tokenHeader, e.spec.token)
	e.clientMu.Lock()
	hc := e.http
	e.clientMu.Unlock()
	resp, err := hc.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return -1, fmt.Errorf("relay: %s", strings.TrimSpace(string(msg)))
	}

	dec := json.NewDecoder(resp.Body)
	code := -1
	gotExit := false
	for {
		var c execChunk
		if err := dec.Decode(&c); err != nil {
			if gotExit {
				return code, nil
			}
			return -1, errors.New("connection closed before the command finished")
		}
		switch c.Type {
		case "out", "err":
			data, derr := base64.StdEncoding.DecodeString(c.Data)
			if derr != nil {
				continue
			}
			if c.Type == "out" {
				os.Stdout.Write(data)
			} else {
				os.Stderr.Write(data)
			}
		case "exit":
			code = c.Code
			if c.Cwd != "" {
				*newCwd = c.Cwd
			}
			gotExit = true
			// keep reading until EOF so buffered chunks are not lost
		}
	}
}
