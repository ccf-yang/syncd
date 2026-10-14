package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

// startTestRelay starts a relay bound to a random loopback port with fast
// scan/settle timings and returns it plus its host:port address.
func startTestRelay(t *testing.T, share, store string, tokens ...string) (*relayServer, string) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "relaydata")
	r, err := newRelay(relayOptions{
		tokens:       tokens,
		store:        store,
		listen:       "127.0.0.1:0",
		share:        share,
		scanInterval: 100 * time.Millisecond,
		settle:       150 * time.Millisecond,
		dataDir:      dataDir,
	})
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
			t.Errorf("relay did not shut down in time")
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

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writeLocal(p string, b []byte) error {
	return os.WriteFile(p, b, 0o644)
}

func writeShareFile(t *testing.T, share, rel string, content []byte) {
	t.Helper()
	full := filepath.Join(share, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
	// Respect the relay's settle window.
	backdate := time.Now().Add(-1 * time.Second)
	if err := os.Chtimes(full, backdate, backdate); err != nil {
		t.Fatal(err)
	}
}

func startEngine(t *testing.T, spec serverSpec, opts clientOptions) *engine {
	t.Helper()
	reg := newStoreRegistry()
	e := newEngine(spec, opts, reg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("engine did not stop in time")
		}
	})
	return e
}

func clientOptsFor(root string) clientOptions {
	return clientOptions{
		root:           root,
		heartbeat:      300 * time.Millisecond,
		missThreshold:  3,
		concurrency:    2,
		rescanInterval: time.Hour,
		trashDays:      7,
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// ---------------------------------------------------------------------------
// Function tests.
// ---------------------------------------------------------------------------

func TestEndToEndSyncUpdateDelete(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	root := filepath.Join(base, "root")

	writeShareFile(t, share, "a.txt", []byte("hello v1"))
	writeShareFile(t, share, "sub/b.bin", randBytes(256*1024))
	writeShareFile(t, share, "big.bin", randBytes(2<<20))

	relay, addr := startTestRelay(t, share, "web-data", "secret1")
	_ = relay

	startEngine(t, serverSpec{token: "secret1", addr: addr}, clientOptsFor(root))
	storeDir := filepath.Join(root, "web-data")

	waitFor(t, 10*time.Second, "initial sync", func() bool {
		return fileExists(filepath.Join(storeDir, "a.txt")) &&
			fileExists(filepath.Join(storeDir, "sub/b.bin")) &&
			fileExists(filepath.Join(storeDir, "big.bin"))
	})
	if got := mustRead(t, filepath.Join(storeDir, "a.txt")); got != "hello v1" {
		t.Fatalf("content mismatch: %q", got)
	}
	if sha, _ := sha256File(filepath.Join(storeDir, "big.bin")); len(sha) != 64 {
		t.Fatal("big.bin downloaded but unreadable")
	}

	// Change: update a file, delete one, add one.
	writeShareFile(t, share, "a.txt", []byte("hello v2"))
	writeShareFile(t, share, "c.txt", []byte("new file"))
	if err := os.Remove(filepath.Join(share, "sub/b.bin")); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "update/delete propagate", func() bool {
		return mustRead(t, filepath.Join(storeDir, "a.txt")) == "hello v2" &&
			fileExists(filepath.Join(storeDir, "c.txt")) &&
			!fileExists(filepath.Join(storeDir, "sub/b.bin"))
	})

	// Deleted file must be in trash, not destroyed.
	trash := filepath.Join(root, ".syncd", "trash")
	found := false
	_ = filepath.WalkDir(trash, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "b.bin") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("deleted file not found in trash")
	}
}

func TestDriftIsOverwritten(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	root := filepath.Join(base, "root")

	writeShareFile(t, share, "a.txt", []byte("server content"))
	_, addr := startTestRelay(t, share, "store-a", "tok")
	startEngine(t, serverSpec{token: "tok", addr: addr}, clientOptsFor(root))
	storeDir := filepath.Join(root, "store-a")

	waitFor(t, 10*time.Second, "initial sync", func() bool {
		return fileExists(filepath.Join(storeDir, "a.txt"))
	})

	// Local drift: modify one file, add a rogue one.
	writeLocal(filepath.Join(storeDir, "a.txt"), []byte("locally hacked"))
	writeLocal(filepath.Join(storeDir, "rogue.txt"), []byte("rogue"))

	// Bump the remote seq so the client runs a sync pass.
	writeShareFile(t, share, "b.txt", []byte("trigger"))

	waitFor(t, 10*time.Second, "drift repair", func() bool {
		return mustRead(t, filepath.Join(storeDir, "a.txt")) == "server content" &&
			!fileExists(filepath.Join(storeDir, "rogue.txt")) &&
			fileExists(filepath.Join(storeDir, "b.txt"))
	})
}

func TestResumeDownloadUsesRange(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	root := filepath.Join(base, "root")

	content := randBytes(6 << 20)
	writeShareFile(t, share, "movie.bin", content)
	relay, addr := startTestRelay(t, share, "films", "tok")

	storeDir := filepath.Join(root, "films")
	// Seed a partial download (first 2 MiB correct) as if a previous
	// session died mid-transfer.
	part := filepath.Join(storeDir, "movie.bin.part")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(part, content[:2<<20], 0o644); err != nil {
		t.Fatal(err)
	}

	startEngine(t, serverSpec{token: "tok", addr: addr}, clientOptsFor(root))

	waitFor(t, 15*time.Second, "resumed download", func() bool {
		return fileExists(filepath.Join(storeDir, "movie.bin"))
	})
	got, _ := sha256File(filepath.Join(storeDir, "movie.bin"))
	want, _ := sha256File(filepath.Join(share, "movie.bin"))
	if got != want {
		t.Error("resumed file content mismatch")
	}
	if relay.RangeHits() == 0 {
		t.Error("client did not resume with a Range request")
	}
	if fileExists(part) {
		t.Error(".part file left behind after completion")
	}
}

func TestTwoServersIsolatedStores(t *testing.T) {
	base := t.TempDir()
	shareA := filepath.Join(base, "shareA")
	shareB := filepath.Join(base, "shareB")
	writeShareFile(t, shareA, "fromA.txt", []byte("A"))
	writeShareFile(t, shareB, "fromB.txt", []byte("B"))

	_, addrA := startTestRelay(t, shareA, "web", "tokA")
	_, addrB := startTestRelay(t, shareB, "db", "tokB")

	ctx, cancel := context.WithCancel(context.Background())
	root := filepath.Join(base, "root")
	done := make(chan error, 1)
	go func() {
		done <- runClient(ctx, clientOptions{
			specs: []serverSpec{
				{token: "tokA", addr: addrA},
				{token: "tokB", addr: addrB},
			},
			root:           root,
			heartbeat:      300 * time.Millisecond,
			missThreshold:  3,
			concurrency:    2,
			rescanInterval: time.Hour,
			trashDays:      7,
		})
	}()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, 15*time.Second, "both stores synced", func() bool {
		a := filepath.Join(root, "web", "fromA.txt")
		b := filepath.Join(root, "db", "fromB.txt")
		return fileExists(a) && fileExists(b) &&
			mustRead(t, a) == "A" && mustRead(t, b) == "B"
	})
}

// ---------------------------------------------------------------------------
// Safety tests.
// ---------------------------------------------------------------------------

func TestWrongTokenRejected(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	writeShareFile(t, share, "a.txt", []byte("x"))
	_, addr := startTestRelay(t, share, "store", "right-token")

	root := filepath.Join(base, "root")
	e := startEngine(t, serverSpec{token: "wrong-token", addr: addr}, clientOptsFor(root))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.auth(ctx); err == nil {
		t.Fatal("auth with wrong token succeeded")
	}
	waitFor(t, 3*time.Second, "no store dir created", func() bool {
		entries, _ := os.ReadDir(root)
		for _, en := range entries {
			if en.Name() != ".syncd" {
				return false
			}
		}
		return true
	})
}

func insecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test against self-signed relay cert
		},
	}
}

func TestFilesEndpointRequiresToken(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	writeShareFile(t, share, "a.txt", []byte("secret"))
	_, addr := startTestRelay(t, share, "s", "tok")

	resp, err := insecureHTTPClient().Get("https://" + addr + "/files?path=a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /files: got %d, want 401", resp.StatusCode)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	writeShareFile(t, share, "a.txt", []byte("x"))
	_, addr := startTestRelay(t, share, "s", "tok")

	client := insecureHTTPClient()
	for _, evil := range []string{
		"../../etc/passwd",
		"..%2F..%2Fetc%2Fpasswd",
		"a/../../b",
		"/etc/passwd",
	} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/files?path="+evil, nil)
		req.Header.Set("X-Token", "tok")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", evil, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("path %q: got %d, want 400", evil, resp.StatusCode)
		}
	}
}

func TestManifestRequiresToken(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	writeShareFile(t, share, "a.txt", []byte("x"))
	_, addr := startTestRelay(t, share, "s", "tok")

	resp, err := insecureHTTPClient().Get("https://" + addr + "/ctl/manifest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated manifest: got %d, want 401", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Stability test: churn the share while asserting no goroutine or heap leak.
// ---------------------------------------------------------------------------

func TestStabilityNoLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("stability test skipped in -short mode")
	}
	base := t.TempDir()
	share := filepath.Join(base, "share")
	root := filepath.Join(base, "root")

	writeShareFile(t, share, "seed.txt", []byte("seed"))
	_, addr := startTestRelay(t, share, "churn", "tok")
	startEngine(t, serverSpec{token: "tok", addr: addr}, clientOptsFor(root))
	waitFor(t, 10*time.Second, "initial sync", func() bool {
		return fileExists(filepath.Join(root, "churn", "seed.txt"))
	})

	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()
	var baselineHeap runtime.MemStats
	runtime.ReadMemStats(&baselineHeap)

	const cycles = 8
	for i := 0; i < cycles; i++ {
		writeShareFile(t, share, fmt.Sprintf("f%d.txt", i), randBytes(64*1024))
		writeShareFile(t, share, "rolling.txt", randBytes(128*1024))
		if i > 1 {
			_ = os.Remove(filepath.Join(share, fmt.Sprintf("f%d.txt", i-2)))
		}
		cur := i
		waitFor(t, 15*time.Second, fmt.Sprintf("cycle %d sync", cur), func() bool {
			_, err := os.Stat(filepath.Join(root, "churn", fmt.Sprintf("f%d.txt", cur)))
			return err == nil
		})
	}

	// Let the last settle/scan/heartbeats drain before measuring.
	time.Sleep(2 * time.Second)
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()
	var afterHeap runtime.MemStats
	runtime.ReadMemStats(&afterHeap)

	if afterGoroutines > baselineGoroutines+5 {
		t.Errorf("goroutine leak: baseline %d, after churn %d", baselineGoroutines, afterGoroutines)
	}
	if afterHeap.HeapAlloc > baselineHeap.HeapAlloc*4+(8<<20) {
		t.Errorf("heap growth suspicious: baseline %d bytes, after %d bytes",
			baselineHeap.HeapAlloc, afterHeap.HeapAlloc)
	}
	t.Logf("stability: goroutines %d -> %d, heap %d -> %d bytes",
		baselineGoroutines, afterGoroutines, baselineHeap.HeapAlloc, afterHeap.HeapAlloc)
}
