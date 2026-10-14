package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type relayOptions struct {
	tokens        []string
	store         string
	listen        string
	share         string
	scanInterval  time.Duration
	settle        time.Duration
	dataDir       string // holds the self-signed TLS cert
	execEnabled   bool   // --exec: allow clients to run commands on this host
	execTimeout   time.Duration
	execOutputCap int64 // bytes of captured output before a command is killed
}

type cachedHash struct {
	size  int64
	mtime int64
	sha   string
}

type relayServer struct {
	opts  relayOptions
	hash  [][]byte // accepted token hashes

	mu        sync.Mutex
	seq       int64
	files     map[string]FileEntry
	cache     map[string]cachedHash
	waiters   map[int64]chan struct{}
	waiterSeq int64

	certFile string
	keyFile  string
	srv      *http.Server

	addr      net.Addr // set once listening (test/ops introspection)
	rangeHits int64    // count of Range downloads (resume instrumentation)
}

// Addr returns the bound listener address, or nil if not yet listening.
func (r *relayServer) Addr() net.Addr { return r.addr }

// RangeHits reports how many download requests carried a Range header.
func (r *relayServer) RangeHits() int64 {
	return atomic.LoadInt64(&r.rangeHits)
}

func newRelay(opts relayOptions) (*relayServer, error) {
	if opts.store == "" {
		return nil, errors.New("store name is empty")
	}
	if len(opts.tokens) == 0 {
		return nil, errors.New("at least one --token is required")
	}
	if err := os.MkdirAll(opts.share, 0o755); err != nil {
		return nil, fmt.Errorf("create share dir: %w", err)
	}
	if err := os.MkdirAll(opts.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	certFile := filepath.Join(opts.dataDir, "relay.crt")
	keyFile := filepath.Join(opts.dataDir, "relay.key")
	if err := ensureSelfSignedCert(certFile, keyFile); err != nil {
		return nil, err
	}
	r := &relayServer{
		opts:    opts,
		hash:    tokenHashes(opts.tokens),
		files:   map[string]FileEntry{},
		cache:   map[string]cachedHash{},
		waiters: map[int64]chan struct{}{},
		certFile: certFile,
		keyFile:  keyFile,
	}
	if r.opts.execOutputCap <= 0 {
		r.opts.execOutputCap = defaultExecOutput
	}
	if r.opts.execTimeout <= 0 {
		r.opts.execTimeout = defaultExecTout
	}
	if r.opts.execEnabled {
		log.Printf("[relay] exec enabled: tokens can run commands on this host (--exec-timeout %s)", r.opts.execTimeout)
	}
	return r, nil
}

// Run starts the scanner and the HTTPS server; it blocks until ctx is done.
func (r *relayServer) Run(ctx context.Context) error {
	// Publish an initial manifest before accepting clients.
	r.scanOnce()

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+authPath, r.handleAuth)
	mux.HandleFunc("POST "+pingPath, r.handlePing)
	mux.HandleFunc("GET "+pollPath, r.handlePoll)
	mux.HandleFunc("GET "+manifestPath, r.handleManifest)
	mux.HandleFunc("GET "+filesPath, r.handleFiles)
	mux.HandleFunc("POST "+execPath, r.handleExec)

	r.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	ln, err := net.Listen("tcp", r.opts.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	r.addr = ln.Addr()
	fp, _ := certFingerprint(r.certFile)
	log.Printf("[relay] store=%q share=%q listening on %s (tls sha256 %s)",
		r.opts.store, r.opts.share, ln.Addr(), fp)

	errCh := make(chan error, 1)
	go func() { errCh <- r.srv.ServeTLS(ln, r.certFile, r.keyFile) }()

	scanCtx, stopScan := context.WithCancel(ctx)
	defer stopScan()
	go r.scanLoop(scanCtx)

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.srv.Shutdown(shCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ---------------------------------------------------------------------------
// Manifest scanning.
// ---------------------------------------------------------------------------

func (r *relayServer) scanLoop(ctx context.Context) {
	t := time.NewTicker(r.opts.scanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.scanOnce()
		}
	}
}

// scanOnce walks the share dir and publishes a new manifest version if the
// effective content changed. Files younger than the settle period are
// treated as still-being-written and held back.
func (r *relayServer) scanOnce() {
	found := map[string]FileEntry{}
	cache := map[string]cachedHash{}
	now := time.Now()

	_ = filepath.WalkDir(r.opts.share, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are simply skipped this round
		}
		if !d.Type().IsRegular() {
			return nil // skip dirs and symlinks (never publish outside links)
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if now.Sub(info.ModTime()) < r.opts.settle {
			return nil // still being written; wait for it to go quiet
		}
		rel, err := filepath.Rel(r.opts.share, p)
		if err != nil {
			return nil
		}
		key := filepath.ToSlash(rel)
		mtime := info.ModTime().UnixNano()
		if c, ok := r.cache[key]; ok && c.size == info.Size() && c.mtime == mtime {
			cache[key] = c
			found[key] = FileEntry{Path: key, Size: info.Size(), SHA: c.sha, Mtime: mtime}
			return nil
		}
		sha, err := sha256File(p)
		if err != nil {
			return nil
		}
		cache[key] = cachedHash{size: info.Size(), mtime: mtime, sha: sha}
		found[key] = FileEntry{Path: key, Size: info.Size(), SHA: sha, Mtime: mtime}
		return nil
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = cache
	if sameManifest(r.files, found) {
		return
	}
	r.seq++
	r.files = found
	// Wake every long-poll waiter; they re-check the seq under the lock.
	for id, ch := range r.waiters {
		close(ch)
		delete(r.waiters, id)
	}
	log.Printf("[relay] manifest v%d: %d file(s) published", r.seq, len(found))
}

// sameManifest reports whether two manifests describe identical content.
func sameManifest(a, b map[string]FileEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || va != vb {
			return false
		}
	}
	return true
}

func (r *relayServer) snapshot() (int64, []FileEntry, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	files := make([]FileEntry, 0, len(r.files))
	for _, e := range r.files {
		files = append(files, e)
	}
	sortFileEntries(files)
	return r.seq, files, r.opts.store
}

// ---------------------------------------------------------------------------
// HTTP handlers.
// ---------------------------------------------------------------------------

func tokenFromRequest(r *http.Request) string {
	if t := r.Header.Get(tokenHeader); t != "" {
		return t
	}
	return r.URL.Query().Get("token")
}

func (r *relayServer) authorized(req *http.Request) bool {
	return checkToken(tokenFromRequest(req), r.hash)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (r *relayServer) handleAuth(w http.ResponseWriter, req *http.Request) {
	var a authRequest
	req.Body = http.MaxBytesReader(w, req.Body, maxAuthBody)
	if err := json.NewDecoder(req.Body).Decode(&a); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if !checkToken(a.Token, r.hash) {
		log.Printf("[relay] auth rejected from %s", req.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	seq, _, store := r.snapshot()
	log.Printf("[relay] client authenticated from %s", req.RemoteAddr)
	writeJSON(w, http.StatusOK, authResponse{Store: store, Seq: seq})
}

func (r *relayServer) handlePing(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	seq, _, _ := r.snapshot()
	writeJSON(w, http.StatusOK, pingResponse{Seq: seq})
}

// handlePoll implements the push notification channel: it returns as soon as
// the manifest version moves past the client's seq, or after pollWait.
func (r *relayServer) handlePoll(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	clientSeq, _ := strconv.ParseInt(req.URL.Query().Get("seq"), 10, 64)

	r.mu.Lock()
	if r.seq > clientSeq {
		seq := r.seq
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, pollResponse{Seq: seq})
		return
	}
	id := r.waiterSeq
	r.waiterSeq++
	ch := make(chan struct{})
	r.waiters[id] = ch
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.waiters, id)
		r.mu.Unlock()
	}()

	select {
	case <-ch:
	case <-req.Context().Done():
		return
	case <-time.After(pollWait):
	}
	r.mu.Lock()
	seq := r.seq
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, pollResponse{Seq: seq})
}

func (r *relayServer) handleManifest(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	seq, files, store := r.snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Manifest{Seq: seq, Store: store, Files: files})
}

// handleFiles serves file content with HTTP Range support (resume).
func (r *relayServer) handleFiles(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	raw := req.URL.Query().Get("path")
	clean, err := sanitizeRelPath(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad path"})
		return
	}
	full := filepath.Join(r.opts.share, filepath.FromSlash(clean))
	f, err := os.Open(full)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if req.Header.Get("Range") != "" {
		atomic.AddInt64(&r.rangeHits, 1)
	}
	http.ServeContent(w, req, info.Name(), info.ModTime(), f)
}

// ---------------------------------------------------------------------------
// Self-signed TLS certificate (persisted, so the fingerprint clients pin
// stays stable across restarts).
// ---------------------------------------------------------------------------

func ensureSelfSignedCert(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "syncd-relay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func certFingerprint(certFile string) (string, error) {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("no PEM block in cert")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// keep url import used even if query helpers change.
var _ = url.QueryEscape

// defaultStoreName uses the machine hostname as the default store name.
func defaultStoreName() string {
	h, err := os.Hostname()
	if err != nil {
		return "store"
	}
	return sanitizeStoreName(h)
}

// runRelay wires a relayServer to a signal-aware lifecycle.
func runRelay(opts relayOptions) error {
	r, err := newRelay(opts)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.Run(ctx)
}
