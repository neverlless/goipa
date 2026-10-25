// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const userAddFixture = `command: user_add/1
args: 1,6,3
arg: Str('uid', cli_name='login')
option: Flag('all', autofill=True, cli_name='all', default=False)
option: Str('cn', autofill=True)
option: Str('givenname', cli_name='first')
option: Str('mail*', cli_name='email')
option: Str('version?')
output: Entry('result')
output: Output('summary', type=[<type 'unicode'>, <type 'NoneType'>])
default: user_add/1
capability: messages 2.52
`

func TestParse(t *testing.T) {
	cmds, err := parse(strings.NewReader(userAddFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || cmds[0].Name != "user_add" {
		t.Fatalf("commands = %+v", cmds)
	}
	c := cmds[0]
	if len(c.Args) != 1 || c.Args[0] != (param{Name: "uid", Type: "Str", Required: true}) {
		t.Errorf("args = %+v", c.Args)
	}
	want := []param{
		{Name: "all", Type: "Flag"},
		{Name: "cn", Type: "Str"},
		{Name: "givenname", Type: "Str", Required: true},
		{Name: "mail", Type: "Str", Multi: true},
		{Name: "version", Type: "Str"},
	}
	if len(c.Options) != len(want) {
		t.Fatalf("options = %+v", c.Options)
	}
	for i := range want {
		if c.Options[i] != want[i] {
			t.Errorf("option %d = %+v, want %+v", i, c.Options[i], want[i])
		}
	}
}

func TestParse_Malformed(t *testing.T) {
	for _, in := range []string{
		"option: Str('x')\n",             // before any command
		"command: a/1\narg: garbage\n",   // no type/name
		"command: a/1\noption: Str(x)\n", // unquoted name
		"command: /1\n",                  // empty name
	} {
		if _, err := parse(strings.NewReader(in)); err == nil {
			t.Errorf("parse(%q) succeeded", in)
		}
	}
}

// noAllowList runs a test against synthetic data, which has none of the real removals.
func noAllowList(t *testing.T) {
	t.Helper()
	old := allowedRemovals
	allowedRemovals = nil
	t.Cleanup(func() { allowedRemovals = old })
}

func mustParse(t *testing.T, s string) []command {
	t.Helper()
	cmds, err := parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return cmds
}

func TestMerge_Since(t *testing.T) {
	rels := []release{
		{Version: "4.9.7", Commands: mustParse(t, "command: a/1\noption: Int('x?')\noption: Str('y')\ncommand: b/1\n")},
		{Version: "4.9.0", Commands: mustParse(t, "command: a/1\noption: Int('x')\n")},
	}
	cmds, versions, err := merge(rels, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(versions, " ") != "4.9.0 4.9.7" {
		t.Errorf("versions = %v", versions)
	}
	if len(cmds) != 2 || cmds[0].Name != "a" || cmds[1].Name != "b" {
		t.Fatalf("commands = %+v", cmds)
	}
	a, b := cmds[0], cmds[1]
	if a.Since != "4.9.0" || b.Since != "4.9.7" {
		t.Errorf("since a=%s b=%s", a.Since, b.Since)
	}
	if want := (param{Name: "x", Type: "Int", Since: "4.9.0"}); a.Options[0] != want {
		t.Errorf("x = %+v, want %+v", a.Options[0], want)
	}
	if want := (param{Name: "y", Type: "Str", Required: true, Since: "4.9.7"}); a.Options[1] != want {
		t.Errorf("y = %+v, want %+v", a.Options[1], want)
	}
}

func TestMerge_SortsNumerically(t *testing.T) {
	_, versions, err := merge([]release{{Version: "4.10.0"}, {Version: "4.9.14"}, {Version: "4.9.2"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(versions, " ") != "4.9.2 4.9.14 4.10.0" {
		t.Errorf("versions = %v", versions)
	}
}

func TestMerge_RejectsRemoval(t *testing.T) {
	_, _, err := merge([]release{
		{Version: "4.9.0", Commands: mustParse(t, "command: a/1\noption: Int('x')\n")},
		{Version: "4.9.1", Commands: mustParse(t, "command: a/1\n")},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), `"x"`) {
		t.Errorf("err = %v", err)
	}
	_, _, err = merge([]release{
		{Version: "4.9.0", Commands: mustParse(t, "command: gone/1\n")},
		{Version: "4.9.1"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("err = %v", err)
	}
}

func TestMerge_AllowedRemoval(t *testing.T) {
	with := "command: automember_default_group_set/1\noption: Str('description?')\noption: Str('version?')\n"
	without := "command: automember_default_group_set/1\noption: Str('version?')\n"
	allow := map[string]bool{"automember_default_group_set\x00option\x00description": true}
	cmds, _, err := merge([]release{
		{Version: "4.9.8", Commands: mustParse(t, with)},
		{Version: "4.9.9", Commands: mustParse(t, without)},
		{Version: "4.9.10", Commands: mustParse(t, without)},
	}, allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds[0].Options) != 1 || cmds[0].Options[0].Name != "version" {
		t.Errorf("options = %+v", cmds[0].Options)
	}
	_, _, err = merge([]release{
		{Version: "4.9.8", Commands: mustParse(t, with)},
		{Version: "4.9.9", Commands: mustParse(t, without)},
		{Version: "4.9.10", Commands: mustParse(t, with)},
	}, allow)
	if err == nil || !strings.Contains(err.Error(), "reappears") {
		t.Errorf("err = %v", err)
	}
}

func TestMerge_StaleAllowEntry(t *testing.T) {
	_, _, err := merge([]release{{Version: "4.9.0", Commands: mustParse(t, "command: a/1\n")}}, map[string]bool{"a\x00option\x00x": true})
	if err == nil || !strings.Contains(err.Error(), "stale allow-list entry") {
		t.Errorf("err = %v", err)
	}
}

func TestParse_AutofillIsAKwarg(t *testing.T) {
	cmds := mustParse(t, "command: a/1\n"+
		"option: Str('p', autofill=True)\n"+
		"option: Str('q', cli_name='x', autofill=True, default=1)\n"+
		"option: Str('r', cli_name='autofill=True')\n"+
		"option: Str('s', default_from=autofill=True_x)\n")
	for i, want := range []bool{false, false, true, true} {
		if got := cmds[0].Options[i].Required; got != want {
			t.Errorf("option %s Required = %v, want %v", cmds[0].Options[i].Name, got, want)
		}
	}
}

func TestRender(t *testing.T) {
	cmds, versions, err := merge([]release{{Version: "4.9.0", Commands: mustParse(t, userAddFixture)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := render(cmds, versions)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(src, []byte("// Code generated by gencatalogue; DO NOT EDIT.\n")) {
		t.Errorf("header: %.60q", src)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "catalogue_gen.go", src, 0); err != nil {
		t.Fatal(err)
	}
	again, _ := render(cmds, versions)
	if !bytes.Equal(src, again) {
		t.Error("renders differ")
	}
	if !bytes.Contains(src, []byte(`"givenname", "Str", true, false, "4.9.0"`)) {
		t.Errorf("missing givenname param:\n%s", src)
	}
}

func TestRun_Src(t *testing.T) {
	noAllowList(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"API-4.9.0.txt":  userAddFixture,
		"API-4-10-0.txt": userAddFixture + "command: b/1\n",
		"API-4-8-9.txt":  "command: old/1\n", // before 4.9.0, ignored
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "gen.go")
	if err := run(out, dir); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`{Name: "b", Since: "4.10.0"`)) || bytes.Contains(src, []byte(`"old"`)) {
		t.Errorf("unexpected output:\n%s", src)
	}

	empty := filepath.Join(t.TempDir(), "none.go")
	if err := run(empty, t.TempDir()); err == nil {
		t.Error("empty -src succeeded")
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Error("output written on error")
	}
}

func TestRun_SrcDuplicateVersion(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"API-4.9.0.txt", "API-4-9-0.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(userAddFixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := run(filepath.Join(t.TempDir(), "gen.go"), dir)
	if err == nil || !strings.Contains(err.Error(), "API-4.9.0.txt") || !strings.Contains(err.Error(), "API-4-9-0.txt") {
		t.Errorf("err = %v", err)
	}
}

func TestRun_SrcBadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "API-4.9.0.txt"), []byte("option: Str('x')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(t.TempDir(), "gen.go"), dir); err == nil {
		t.Error("unparsable file accepted")
	}
}

func TestFetch(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	remote := t.TempDir()
	env := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	for _, args := range [][]string{
		{"init", "-q"}, {"commit", "-q", "--allow-empty", "-m", "x"},
		{"tag", "release-4-9-0"}, {"tag", "release-4-8-9"}, {"tag", "release-4-13-4"},
		{"tag", "ipa-4-12-2"}, {"tag", "release-4-9-0-rc1"},
	} {
		cmd := exec.Command(git, args...) // #nosec G204 -- fixed test arguments
		cmd.Dir, cmd.Env = remote, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	fail := false
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if strings.Contains(r.URL.Path, "4-13-4") && fail {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, userAddFixture)
	}))
	defer srv.Close()
	oldRepo, oldRaw := repo, rawBase
	defer func() { repo, rawBase = oldRepo, oldRaw }()
	repo, rawBase = remote, srv.URL

	rels, err := fetch()
	if err != nil {
		t.Fatal(err)
	}
	var vs []string
	for _, r := range rels {
		vs = append(vs, r.Version)
	}
	slices.Sort(vs)
	if strings.Join(vs, " ") != "4.13.4 4.9.0" {
		t.Errorf("versions = %v", vs)
	}
	slices.Sort(asked)
	if strings.Join(asked, " ") != "/release-4-13-4/API.txt /release-4-9-0/API.txt" {
		t.Errorf("requests = %v", asked)
	}

	fail = true
	if _, err := fetch(); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("non-200 err = %v", err)
	}

	repo = filepath.Join(remote, "missing")
	if _, err := fetch(); err == nil {
		t.Error("ls-remote failure ignored")
	}
}

func TestFetchOne_BadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "option: Str('x')\n")
	}))
	defer srv.Close()
	if _, err := fetchOne(srv.Client(), srv.URL); err == nil {
		t.Error("unparsable body accepted")
	}
	if _, err := fetchOne(srv.Client(), "http://127.0.0.1:1/"); err == nil {
		t.Error("connection failure ignored")
	}
}

func TestRunErrors(t *testing.T) {
	noAllowList(t)
	// merge failure: the data removes an option no allow-list entry covers.
	dir := t.TempDir()
	for name, body := range map[string]string{
		"API-4.9.0.txt": "command: a/1\noption: Int('x')\n",
		"API-4.9.1.txt": "command: a/1\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(filepath.Join(t.TempDir(), "gen.go"), dir); err == nil {
		t.Error("removal accepted")
	}
	if err := run(filepath.Join(t.TempDir(), "no", "such", "gen.go"), t.TempDir()); err == nil {
		t.Error("empty dir accepted")
	}
}
