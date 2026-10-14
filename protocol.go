package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Protocol constants and wire types (shared by relay and client).
//
// Transport: one TLS HTTPS endpoint per relay.
//   - control plane: short JSON POSTs (auth, ping) + a 30s long-poll that
//     returns as soon as the manifest version advances (acts as the push
//     notification channel).
//   - data plane: plain GET with Range support for resumable downloads.
// ---------------------------------------------------------------------------

const (
	defaultPort     = "9410"
	defaultShareDir = "/data/share"

	authPath     = "/ctl/auth"
	pingPath     = "/ctl/ping"
	pollPath     = "/ctl/poll"
	manifestPath = "/ctl/manifest"
	filesPath    = "/files"

	tokenHeader = "X-Token"

	pollWait        = 30 * time.Second // server holds a long-poll this long
	maxManifestBody = 1 << 28          // 256 MiB safety cap on manifest responses
	maxAuthBody     = 1 << 12          // 4 KiB cap on auth requests
)

// FileEntry describes one published file.
type FileEntry struct {
	Path  string `json:"path"`  // slash-separated path relative to share dir
	Size  int64  `json:"size"`
	SHA   string `json:"sha"`   // hex sha256 of the full content
	Mtime int64  `json:"mtime"` // unix nanos, also set on the downloaded copy
}

// Manifest is the full listing of a store at version Seq.
type Manifest struct {
	Seq   int64       `json:"seq"`
	Store string      `json:"store"`
	Files []FileEntry `json:"files"`
}

type authRequest struct {
	Token string `json:"token"`
}

type authResponse struct {
	Store string `json:"store"`
	Seq   int64  `json:"seq"`
}

type pingResponse struct {
	Seq int64 `json:"seq"`
}

type pollResponse struct {
	Seq int64 `json:"seq"`
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

var errUnauthorized = errors.New("unauthorized")

// tokenHashes precomputes salted-none sha256 digests of accepted tokens so
// comparisons can be constant time.
func tokenHashes(tokens []string) [][]byte {
	out := make([][]byte, 0, len(tokens))
	for _, t := range tokens {
		h := sha256.Sum256([]byte(t))
		out = append(out, h[:])
	}
	return out
}

// checkToken reports whether the presented token matches any accepted one,
// in constant time per candidate.
func checkToken(presented string, hashes [][]byte) bool {
	sum := sha256.Sum256([]byte(presented))
	ok := 0
	for _, h := range hashes {
		ok |= subtle.ConstantTimeCompare(sum[:], h)
	}
	return ok == 1
}

// sanitizeRelPath validates a path that must stay inside a sync directory:
// relative, no "..", no empty components after cleaning. Returns the clean
// slash-separated path.
func sanitizeRelPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if strings.Contains(p, "\\") {
		return "", errors.New("backslash not allowed")
	}
	if strings.HasPrefix(p, "/") {
		return "", errors.New("absolute path not allowed")
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", errors.New(".. not allowed")
		}
	}
	clean := path.Clean("/" + p) // clean against a virtual root
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", errors.New("empty path")
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." || part == "." || part == "" {
			return "", fmt.Errorf("unsafe path component %q", part)
		}
	}
	return clean, nil
}

// sanitizeStoreName reduces a relay-announced store name to a safe single
// directory name. It never returns "", ".", "..", a dotfile, or anything
// containing separators.
func sanitizeStoreName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	for strings.HasPrefix(out, ".") { // no dotfiles / no "." / no ".."
		out = strings.TrimPrefix(out, ".")
	}
	out = strings.Trim(out, ".")
	if out == "" {
		out = "store"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// parseServerFlag parses "token@host[:port]".
func parseServerFlag(s string) (serverSpec, error) {
	token, host, ok := strings.Cut(s, "@")
	if !ok || token == "" || host == "" {
		return serverSpec{}, errors.New("expected token@host[:port]")
	}
	if strings.ContainsAny(host, "@/ \t") {
		return serverSpec{}, errors.New("host must not contain @ / or whitespace")
	}
	if _, err := url.ParseRequestURI("http://" + host); err != nil {
		return serverSpec{}, fmt.Errorf("bad host:port: %w", err)
	}
	return serverSpec{token: token, addr: host}, nil
}

type serverSpec struct {
	token string
	addr  string // host:port
}

// sortFileEntries orders a manifest deterministically (by path).
func sortFileEntries(files []FileEntry) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
}

// sha256File streams a file through sha256.
func sha256File(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// atomicWriteJSON writes data to name via a temp file + rename in the same
// directory, so readers never observe a partial file.
func atomicWriteJSON(name string, data []byte, perm os.FileMode) error {
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, name)
}

// stateFileEntry is the per-server persisted client state.
type clientState struct {
	Seq   int64                `json:"seq"`
	Files map[string]FileEntry `json:"files"`
}
