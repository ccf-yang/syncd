package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type clientOptions struct {
	specs          []serverSpec
	root           string
	tlsInsecure    bool
	heartbeat      time.Duration
	missThreshold  int
	concurrency    int
	rescanInterval time.Duration
	trashDays      int
}

func runClient(ctx context.Context, opts clientOptions) error {
	if err := os.MkdirAll(opts.root, 0o755); err != nil {
		return fmt.Errorf("create root: %w", err)
	}
	// Also stop on SIGINT/SIGTERM even when the caller did not wire signals.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	// A registry that guarantees each sanitized store name maps to exactly
	// one upstream, even if two relays sanitize to the same name.
	registry := newStoreRegistry()
	for _, spec := range opts.specs {
		e := newEngine(spec, opts, registry)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.run(ctx)
		}()
	}
	// Trash cleanup loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		trashLoop(ctx, opts)
	}()

	log.Printf("[client] %d server(s), root=%s", len(opts.specs), opts.root)
	<-ctx.Done()
	stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Printf("[client] forced exit while workers were still draining")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Store registry: avoids two relays colliding into one local directory.
// ---------------------------------------------------------------------------

type storeRegistry struct {
	mu    sync.Mutex
	used  map[string]bool
}

func newStoreRegistry() *storeRegistry { return &storeRegistry{used: map[string]bool{}} }

func (r *storeRegistry) allocate(preferred, engineKey string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := preferred
	for i := 2; r.used[name]; i++ {
		name = fmt.Sprintf("%s_%d", preferred, i)
	}
	r.used[name] = true
	_ = engineKey
	return name
}

// ---------------------------------------------------------------------------
// Engine: one upstream relay.
// ---------------------------------------------------------------------------

type engine struct {
	spec     serverSpec
	opts     clientOptions
	key      string // stable per-server key derived from addr
	dir      string // <root>/.syncd/<key>
	fpFile   string
	stateMu  sync.Mutex
	state    clientState
	syncMu   sync.Mutex
	clientMu sync.Mutex
	http     *http.Client
	registry *storeRegistry

	storeName string // set after auth
	storeDir  string
	pendingFP string
}

func newEngine(spec serverSpec, opts clientOptions, reg *storeRegistry) *engine {
	key := sanitizeStoreName(strings.ReplaceAll(spec.addr, ":", "_"))
	dir := filepath.Join(opts.root, ".syncd", key)
	return &engine{
		spec:     spec,
		opts:     opts,
		key:      key,
		dir:      dir,
		fpFile:   filepath.Join(dir, "fp"),
		registry: reg,
	}
}

func (e *engine) logf(format string, args ...any) {
	log.Printf("[client %s] "+format, append([]any{e.spec.addr}, args...)...)
}

func (e *engine) run(ctx context.Context) {
	backoff := time.Second
	for {
		err := e.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			e.logf("session ended: %v (retry in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// session performs one authenticated connection lifecycle:
// dial -> auth -> start heartbeat + poll -> apply syncs until disconnected.
func (e *engine) session(ctx context.Context) error {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	if err := e.loadState(); err != nil {
		return err
	}
	e.clientMu.Lock()
	e.ensureHTTP()
	e.clientMu.Unlock()
	// Drop idle keep-alive connections when this session ends.
	defer func() {
		e.clientMu.Lock()
		if e.http != nil {
			e.http.CloseIdleConnections()
		}
		e.clientMu.Unlock()
	}()

	// Authenticate. On success, pin the server certificate (TOFU).
	ar, err := e.auth(ctx)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if e.pendingFP != "" {
		if err := os.WriteFile(e.fpFile, []byte(e.pendingFP), 0o600); err == nil {
			e.pendingFP = ""
		}
	}
	store := sanitizeStoreName(ar.Store)
	if e.storeDir == "" {
		name := e.registry.allocate(store, e.key)
		e.storeName = name
		e.storeDir = filepath.Join(e.opts.root, name)
		if err := os.MkdirAll(e.storeDir, 0o755); err != nil {
			return err
		}
		e.logf("authenticated, store=%q -> %s (remote manifest v%d)", ar.Store, e.storeDir, ar.Seq)
	}

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	events := make(chan struct{}, 1)
	trigger := func() {
		select {
		case events <- struct{}{}:
		default:
		}
	}
	go e.heartbeatLoop(sessCtx, cancel, trigger)
	go e.pollLoop(sessCtx, trigger)
	rescan := time.NewTicker(e.opts.rescanInterval)
	defer rescan.Stop()

	trigger() // initial sync
	for {
		select {
		case <-sessCtx.Done():
			return nil
		case <-events:
			e.syncNow(sessCtx)
		case <-rescan.C:
			e.syncNow(sessCtx)
		}
	}
}

// heartbeatLoop sends a ping every heartbeat interval. After missThreshold
// consecutive failures it cancels the session (engine reconnects).
func (e *engine) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, trigger func()) {
	t := time.NewTicker(e.opts.heartbeat)
	defer t.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		hbCtx, hbCancel := context.WithTimeout(ctx, e.opts.heartbeat)
		resp, err := e.ping(hbCtx)
		hbCancel()
		if err != nil {
			misses++
			if misses >= e.opts.missThreshold {
				e.logf("heartbeat lost after %d misses, reconnecting", misses)
				cancel()
				return
			}
			continue
		}
		misses = 0
		if resp.Seq > e.getSeq() {
			trigger()
		}
	}
}

// pollLoop long-polls the relay; a changed seq triggers a sync. This is the
// low-latency push path; the heartbeat path is the safety net.
func (e *engine) pollLoop(ctx context.Context, trigger func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		pollCtx, cancel := context.WithTimeout(ctx, pollWait+10*time.Second)
		resp, err := e.poll(pollCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if resp.Seq > e.getSeq() {
			trigger()
		}
	}
}

func (e *engine) getSeq() int64 {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.state.Seq
}

// ---------------------------------------------------------------------------
// API calls.
// ---------------------------------------------------------------------------

func (e *engine) ensureHTTP() {
	if e.http != nil {
		return
	}
	e.http = &http.Client{
		Transport: &http.Transport{
			DialTLSContext:        e.dialTLS,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   4,
		},
	}
}

func (e *engine) doJSON(ctx context.Context, method, path string, query url.Values, body io.Reader, timeout time.Duration, out any) error {
	e.clientMu.Lock()
	e.ensureHTTP()
	hc := e.http
	e.clientMu.Unlock()
	u := url.URL{Scheme: "https", Host: e.spec.addr, Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set(tokenHeader, e.spec.token)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxManifestBody)).Decode(out)
}

func (e *engine) auth(ctx context.Context) (authResponse, error) {
	var out authResponse
	body, _ := json.Marshal(authRequest{Token: e.spec.token})
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := e.doJSON(cctx, http.MethodPost, authPath, nil, bytes.NewReader(body), 15*time.Second, &out)
	return out, err
}

func (e *engine) ping(ctx context.Context) (pingResponse, error) {
	var out pingResponse
	err := e.doJSON(ctx, http.MethodPost, pingPath, nil, nil, 0, &out)
	return out, err
}

func (e *engine) poll(ctx context.Context) (pollResponse, error) {
	q := url.Values{"seq": []string{fmt.Sprint(e.getSeq())}}
	var out pollResponse
	err := e.doJSON(ctx, http.MethodGet, pollPath, q, nil, 0, &out)
	return out, err
}

func (e *engine) manifest(ctx context.Context) (Manifest, error) {
	var out Manifest
	err := e.doJSON(ctx, http.MethodGet, manifestPath, nil, nil, 0, &out)
	return out, err
}

// ---------------------------------------------------------------------------
// TLS dialing with certificate pinning (trust on first use).
// ---------------------------------------------------------------------------

func (e *engine) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host} //nolint:gosec // pinning handled below
	conn := tls.Client(raw, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hsCtx); err != nil {
		raw.Close()
		return nil, err
	}
	if !e.opts.tlsInsecure {
		pinned, _ := os.ReadFile(e.fpFile)
		pinnedStr := strings.TrimSpace(string(pinned))
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			conn.Close()
			return nil, errors.New("server sent no certificate")
		}
		sum := sha256.Sum256(certs[0].Raw)
		fp := hex.EncodeToString(sum[:])
		switch {
		case pinnedStr == "":
			e.pendingFP = fp // remembered after successful auth
		case pinnedStr != fp:
			conn.Close()
			return nil, fmt.Errorf("server certificate fingerprint changed (pinned %s, got %s)", short(pinnedStr), short(fp))
		}
	}
	return conn, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// State persistence.
// ---------------------------------------------------------------------------

func (e *engine) stateFile() string { return filepath.Join(e.dir, "state.json") }

func (e *engine) loadState() error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	data, err := os.ReadFile(e.stateFile())
	if err != nil {
		if os.IsNotExist(err) {
			e.state = clientState{Files: map[string]FileEntry{}}
			return nil
		}
		return err
	}
	var st clientState
	if err := json.Unmarshal(data, &st); err != nil {
		// Corrupt state: start over rather than fail forever.
		e.logf("state file corrupt, rebuilding: %v", err)
		e.state = clientState{Files: map[string]FileEntry{}}
		return nil
	}
	if st.Files == nil {
		st.Files = map[string]FileEntry{}
	}
	e.state = st
	return nil
}

func (e *engine) saveStateLocked() error {
	data, err := json.MarshalIndent(e.state, "", " ")
	if err != nil {
		return err
	}
	return atomicWriteJSON(e.stateFile(), data, 0o600)
}

// ---------------------------------------------------------------------------
// Sync.
// ---------------------------------------------------------------------------

// syncNow brings the store dir in line with the remote manifest (strict
// mirror: downloads missing/changed files, trashes everything the relay no
// longer publishes, and repairs local drift).
func (e *engine) syncNow(ctx context.Context) {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	m, err := e.manifest(ctx)
	if err != nil {
		e.logf("fetch manifest: %v", err)
		return
	}
	if e.storeDir == "" {
		return // not authenticated yet
	}
	if m.Seq < e.state.Seq {
		e.logf("remote manifest went backwards (v%d < v%d), rebuilding", m.Seq, e.state.Seq)
		e.stateMu.Lock()
		e.state = clientState{Files: map[string]FileEntry{}}
		e.stateMu.Unlock()
	}
	manifestSet := make(map[string]FileEntry, len(m.Files))
	for _, f := range m.Files {
		if _, err := sanitizeRelPath(f.Path); err != nil {
			e.logf("skipping unsafe manifest path %q", f.Path)
			continue
		}
		manifestSet[f.Path] = f
	}

	// 1) Local disk inventory (skip .part temp files).
	disk, err := e.scanLocal()
	if err != nil {
		e.logf("scan local: %v", err)
		return
	}

	// 2) Deletions: anything on disk (or in state) the relay no longer
	//    publishes goes to trash. Strict mirror.
	e.stateMu.Lock()
	for path := range e.state.Files {
		if _, ok := manifestSet[path]; !ok {
			e.trashLocal(filepath.FromSlash(path))
			delete(e.state.Files, path)
		}
	}
	e.stateMu.Unlock()
	for path := range disk {
		if _, ok := manifestSet[path]; !ok {
			e.trashLocal(filepath.FromSlash(path))
		}
	}

	// 3) Downloads: missing, changed, or locally drifted files.
	type task struct{ entry FileEntry }
	var tasks []task
	e.stateMu.Lock()
	for path, entry := range manifestSet {
		st, haveState := e.state.Files[path]
		d, onDisk := disk[path]
		need := !onDisk || !haveState ||
			st.SHA != entry.SHA ||
			d.mtime != entry.Mtime || d.size != entry.Size
		if need {
			tasks = append(tasks, task{entry: entry})
		}
	}
	e.stateMu.Unlock()
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].entry.Path < tasks[j].entry.Path })

	downloaded := 0
	if len(tasks) > 0 {
		sem := make(chan struct{}, max(1, e.opts.concurrency))
		var wg sync.WaitGroup
		var countMu sync.Mutex
	loop:
		for _, t := range tasks {
			select {
			case <-ctx.Done():
				break loop
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(entry FileEntry) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := e.download(ctx, entry); err != nil {
					if ctx.Err() == nil {
						e.logf("download %s: %v", entry.Path, err)
					}
					return
				}
				e.stateMu.Lock()
				e.state.Files[entry.Path] = entry
				e.stateMu.Unlock()
				countMu.Lock()
				downloaded++
				countMu.Unlock()
			}(t.entry)
		}
		wg.Wait()
	}

	// 4) Advance version and persist.
	e.stateMu.Lock()
	e.state.Seq = m.Seq
	err = e.saveStateLocked()
	e.stateMu.Unlock()
	if err != nil {
		e.logf("save state: %v", err)
	}
	if downloaded > 0 || m.Seq != e.getSeq() || len(tasks) > 0 {
		e.logf("synced to v%d: %d downloaded, %d file(s) total", m.Seq, downloaded, len(m.Files))
	}
}

type localFile struct {
	size  int64
	mtime int64
}

// scanLocal inventories the store dir. .part temp files are ignored.
func (e *engine) scanLocal() (map[string]localFile, error) {
	out := map[string]localFile{}
	root := e.storeDir
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if root != p {
				return nil // skip unreadable entries
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		if strings.HasSuffix(rel, ".part") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out[filepath.ToSlash(rel)] = localFile{size: info.Size(), mtime: info.ModTime().UnixNano()}
		return nil
	})
	return out, err
}

// trashLocal moves a store file into <root>/.syncd/trash/<store>/<stamp>/
// instead of deleting it outright (deletion safety net).
func (e *engine) trashLocal(rel string) {
	stamp := time.Now().UTC().Format("20060102T150405")
	dstDir := filepath.Join(e.opts.root, ".syncd", "trash", e.storeName, stamp, filepath.Dir(rel))
	src := filepath.Join(e.storeDir, rel)
	if err := os.MkdirAll(dstDir, 0o755); err == nil {
		dst := filepath.Join(dstDir, filepath.Base(rel))
		if err := os.Rename(src, dst); err == nil {
			e.logf("moved to trash: %s", rel)
			return
		}
	}
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		e.logf("remove %s: %v", rel, err)
	}
}

// ---------------------------------------------------------------------------
// Download with resume.
// ---------------------------------------------------------------------------

// download fetches one file into <final>.part (resuming from any existing
// partial data), verifies its sha256, then atomically renames it into place.
func (e *engine) download(ctx context.Context, entry FileEntry) error {
	final := filepath.Join(e.storeDir, filepath.FromSlash(entry.Path))
	part := final + ".part"
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return err
	}

	var offset int64
	if fi, err := os.Stat(part); err == nil {
		if fi.Size() > entry.Size {
			os.Remove(part) // remote shrank or stale temp
		} else {
			offset = fi.Size()
		}
	}

	q := url.Values{"path": []string{entry.Path}}
	u := url.URL{Scheme: "https", Host: e.spec.addr, Path: filesPath, RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set(tokenHeader, e.spec.token)
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	e.clientMu.Lock()
	hc := e.http
	e.clientMu.Unlock()
	resp, err := hc.Do(req)
	if err != nil {
		return err // keep .part for the next attempt
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent:
		// resuming as expected
	case http.StatusOK:
		if offset > 0 { // server ignored the range; restart cleanly
			offset = 0
		}
	case http.StatusNotFound:
		os.Remove(part)
		return errors.New("file no longer on relay")
	case http.StatusUnauthorized:
		return errUnauthorized
	default:
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if offset > 0 {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(part, flag, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err // keep .part; download resumes later
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Integrity gate: the file only lands when its hash matches.
	sha, err := sha256File(part)
	if err != nil {
		return err
	}
	if sha != entry.SHA {
		os.Remove(part)
		return errors.New("sha256 mismatch after download")
	}
	if err := os.Rename(part, final); err != nil {
		return err
	}
	t := time.Unix(0, entry.Mtime)
	_ = os.Chtimes(final, t, t)
	return nil
}

// ---------------------------------------------------------------------------
// Trash retention.
// ---------------------------------------------------------------------------

func trashLoop(ctx context.Context, opts clientOptions) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cleanTrash(opts)
		}
	}
}

func cleanTrash(opts clientOptions) {
	trashRoot := filepath.Join(opts.root, ".syncd", "trash")
	cutoff := time.Now().AddDate(0, 0, -opts.trashDays)
	stores, err := os.ReadDir(trashRoot)
	if err != nil {
		return
	}
	for _, s := range stores {
		stamps, err := os.ReadDir(filepath.Join(trashRoot, s.Name()))
		if err != nil {
			continue
		}
		for _, stampDir := range stamps {
			ts, err := time.Parse("20060102T150405", stampDir.Name())
			if err != nil || ts.After(cutoff) {
				continue
			}
			_ = os.RemoveAll(filepath.Join(trashRoot, s.Name(), stampDir.Name()))
		}
	}
}
