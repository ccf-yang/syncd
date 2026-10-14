package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ---------------------------------------------------------------------------
// Unit tests: cd resolution.
// ---------------------------------------------------------------------------

func TestResolveCd(t *testing.T) {
	home := "/root"
	oldDefault := defaultCwdFn
	defaultCwdFn = func() string { return home }
	defer func() { defaultCwdFn = oldDefault }()

	// Real directories, including one with a space in the name, so the
	// "only change cwd when the target exists" rule can be exercised.
	base := t.TempDir()
	spaced := filepath.Join(base, "a b")
	if err := os.Mkdir(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(base, "sub")
	if err := os.Mkdir(rel, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		cmd, cwd, want string
		changed        bool
	}{
		{"df -h", "/var/log", "/var/log", false},       // not a cd
		{"cd /tmp", "/var/log", "/tmp", true},          // absolute
		{"cd " + filepath.Base(rel), base, rel, true},  // relative
		{"cd ..", base, filepath.Dir(base), true},      // parent
		{"cd", "/var", home, true},                     // bare cd -> home
		{"cd ~", "/var", home, true},                   // tilde
		{"cd /no/such/dir", "/var", "/var", false},     // missing dir: no change
		{"cd /tmp && tail -f x", "/var", "/tmp", true}, // cd && more
		{"cd \"" + spaced + "\"", "/", spaced, true},   // quoted path
		{"echo cd", "/", "/", false},                   // cd is an argument
		{"  cd /tmp  ", "/var", "/tmp", true},          // whitespace
		{"cd /tmp; ls", "/var", "/tmp", true},          // semicolon
	}
	for _, c := range cases {
		got, changed := resolveCd(c.cmd, c.cwd)
		if got != c.want || changed != c.changed {
			t.Errorf("resolveCd(%q, %q) = (%q, %v), want (%q, %v)",
				c.cmd, c.cwd, got, changed, c.want, c.changed)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration tests against a live relay.
// ---------------------------------------------------------------------------

// runExec posts one command to the relay and collects the streamed chunks.
func runExec(t *testing.T, addr, token, cwd, cmd string) ([]execChunk, int) {
	t.Helper()
	client := insecureHTTPClient()
	body, _ := json.Marshal(execRequest{Cmd: cmd, Cwd: cwd})
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+execPath, bytes.NewReader(body))
	req.Header.Set("X-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	defer resp.Body.Close()
	var chunks []execChunk
	dec := json.NewDecoder(resp.Body)
	for {
		var c execChunk
		if err := dec.Decode(&c); err != nil {
			break
		}
		chunks = append(chunks, c)
		if c.Type == "exit" {
			return chunks, resp.StatusCode
		}
	}
	return chunks, resp.StatusCode
}

func execOutput(chunks []execChunk) string {
	var b strings.Builder
	for _, c := range chunks {
		if c.Type == "out" {
			data, _ := base64Decode(c.Data)
			b.Write(data)
		}
	}
	return b.String()
}

func TestExecEcho(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) { o.execEnabled = true }, "tok")

	chunks, status := runExec(t, addr, "tok", "", "echo hello-exec")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if got := execOutput(chunks); !strings.Contains(got, "hello-exec") {
		t.Errorf("output %q missing hello-exec", got)
	}
	last := chunks[len(chunks)-1]
	if last.Type != "exit" || last.Code != 0 {
		t.Errorf("bad exit chunk: %+v", last)
	}
}

func TestExecDisabledByDefault(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelay(t, share, "s", "tok")

	_, status := runExec(t, addr, "tok", "", "echo hi")
	if status != http.StatusForbidden {
		t.Fatalf("exec without --exec: got %d, want 403", status)
	}
}

func TestExecExitCodeAndStderr(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) { o.execEnabled = true }, "tok")

	// stdout+stderr are merged into one stream (like a real terminal).
	chunks, _ := runExec(t, addr, "tok", "", "sh -c 'echo out-mark; echo err-mark >&2; exit 7'")
	last := chunks[len(chunks)-1]
	if last.Code != 7 {
		t.Errorf("exit code %d, want 7", last.Code)
	}
	got := execOutput(chunks)
	if !strings.Contains(got, "out-mark") || !strings.Contains(got, "err-mark") {
		t.Errorf("merged output missing marks: %q", got)
	}
}

func TestExecCdPersists(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) { o.execEnabled = true }, "tok")

	// cwd persists client-side: server resolves each request's cd.
	dir := t.TempDir()
	chunks, _ := runExec(t, addr, "tok", "", "cd "+dir)
	last := chunks[len(chunks)-1]
	if last.Cwd != dir {
		t.Fatalf("cd: cwd=%q want %q", last.Cwd, dir)
	}
	chunks, _ = runExec(t, addr, "tok", dir, "pwd")
	if out := execOutput(chunks); strings.TrimSpace(out) != dir {
		t.Errorf("pwd after cd = %q, want %q", strings.TrimSpace(out), dir)
	}
}

func TestExecTimeout(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) {
		o.execEnabled = true
		o.execTimeout = 500 * time.Millisecond
	}, "tok")

	start := time.Now()
	chunks, _ := runExec(t, addr, "tok", "", "sleep 30")
	elapsed := time.Since(start)
	if len(chunks) == 0 {
		t.Fatal("no chunks received")
	}
	last := chunks[len(chunks)-1]
	if last.Code == 0 {
		t.Error("killed command reported success")
	}
	if elapsed > 10*time.Second {
		t.Errorf("timeout took %s, command was not killed", elapsed)
	}
	var hasTimeoutMsg bool
	for _, c := range chunks {
		if c.Type == "err" && strings.Contains(c.Data, "") {
			data, _ := base64Decode(c.Data)
			if strings.Contains(string(data), "timed out") {
				hasTimeoutMsg = true
			}
		}
	}
	if !hasTimeoutMsg {
		t.Error("no timeout error chunk")
	}
}

func TestExecOutputCap(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) {
		o.execEnabled = true
		o.execOutputCap = 1 << 20 // 1 MiB
	}, "tok")

	chunks, _ := runExec(t, addr, "tok", "", "head -c 16M /dev/zero")
	last := chunks[len(chunks)-1]
	if last.Code == 0 {
		t.Error("capped command reported success")
	}
	var size int
	for _, c := range chunks {
		if c.Type == "out" {
			data, _ := base64Decode(c.Data)
			size += len(data)
		}
	}
	if size > 2<<20 {
		t.Errorf("received %d bytes, cap not enforced", size)
	}
}

func TestExecRequestWithoutToken(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	_, addr := startTestRelayExt(t, share, "s", func(o *relayOptions) { o.execEnabled = true }, "tok")

	client := insecureHTTPClient()
	resp, err := client.Post("https://"+addr+execPath, "application/json", strings.NewReader(`{"cmd":"id"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated exec: got %d, want 401", resp.StatusCode)
	}
}

// startTestRelayExt is like startTestRelay but allows overriding options.
func startTestRelayExt(t *testing.T, share, store string, tune func(*relayOptions), tokens ...string) (*relayServer, string) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "relaydata")
	opts := relayOptions{
		tokens:       tokens,
		store:        store,
		listen:       "127.0.0.1:0",
		share:        share,
		scanInterval: 100 * time.Millisecond,
		settle:       150 * time.Millisecond,
		dataDir:      dataDir,
	}
	if tune != nil {
		tune(&opts)
	}
	r, err := newRelay(opts)
	if err != nil {
		t.Fatalf("newRelay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for r.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.Addr() == nil {
		t.Fatal("relay did not start listening")
	}
	return r, r.Addr().String()
}

