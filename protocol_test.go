package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeRelPath(t *testing.T) {
	ok := map[string]string{
		"a.txt":          "a.txt",
		"sub/dir/b.bin":  "sub/dir/b.bin",
		"./a.txt":        "a.txt",
		"sub//x.txt":     "sub/x.txt",
		"a/./b":          "a/b",
		"dir with space": "dir with space",
	}
	for in, want := range ok {
		got, err := sanitizeRelPath(in)
		if err != nil || got != want {
			t.Errorf("sanitizeRelPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "../x", "..\\x", "a/../../x", "/abs/path", "a/../..",
		"sub/../../escape", "..", ".",
	}
	for _, in := range bad {
		if got, err := sanitizeRelPath(in); err == nil {
			t.Errorf("sanitizeRelPath(%q) = %q, want error", in, got)
		}
	}
}

func TestSanitizeStoreName(t *testing.T) {
	cases := map[string]string{
		"web-data": "web-data",
		"my store": "my_store",
		"a/b":      "a_b",
		"../evil":  "_evil",
		".hidden":  "hidden",
		"..data":   "data",
		"中文":       "__",
		"":         "store",
		"..":       "store",
		".":        "store",
	}
	for in, want := range cases {
		got := sanitizeStoreName(in)
		if got != want {
			t.Errorf("sanitizeStoreName(%q) = %q, want %q", in, got, want)
		}
		if got == "." || got == ".." || filepath.IsAbs(got) {
			t.Errorf("sanitizeStoreName(%q) produced unsafe dir %q", in, got)
		}
	}
}

func TestParseServerFlag(t *testing.T) {
	s, err := parseServerFlag("secret@1.2.3.4:9410")
	if err != nil || s.token != "secret" || s.addr != "1.2.3.4:9410" {
		t.Fatalf("parseServerFlag ok case: %+v, %v", s, err)
	}
	s, err = parseServerFlag("secret@host.example")
	if err != nil || s.addr != "host.example" {
		t.Fatalf("default port case: %+v, %v", s, err)
	}
	for _, bad := range []string{"", "@host", "tok@", "noatsign", "tok@@host"} {
		if _, err := parseServerFlag(bad); err == nil {
			t.Errorf("parseServerFlag(%q): want error", bad)
		}
	}
}

func TestCheckToken(t *testing.T) {
	hashes := tokenHashes([]string{"alpha", "beta"})
	if !checkToken("alpha", hashes) || !checkToken("beta", hashes) {
		t.Error("valid tokens rejected")
	}
	if checkToken("gamma", hashes) || checkToken("", hashes) {
		t.Error("invalid token accepted")
	}
}

func TestSameManifest(t *testing.T) {
	a := map[string]FileEntry{"x": {Path: "x", Size: 1, SHA: "s", Mtime: 1}}
	b := map[string]FileEntry{"x": {Path: "x", Size: 1, SHA: "s", Mtime: 1}}
	if !sameManifest(a, b) {
		t.Error("equal manifests reported different")
	}
	b["y"] = FileEntry{Path: "y"}
	if sameManifest(a, b) {
		t.Error("different sizes reported equal")
	}
	b2 := map[string]FileEntry{"x": {Path: "x", Size: 2, SHA: "s", Mtime: 1}}
	if sameManifest(a, b2) {
		t.Error("changed content reported equal")
	}
}

func TestAtomicWriteJSON(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "state.json")
	if err := atomicWriteJSON(name, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil || string(data) != `{"a":1}` {
		t.Fatalf("readback: %q %v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
