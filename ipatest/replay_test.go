// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func recording(summary string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(`{"result":{"cn":["x"]},"value":null,"summary":"` + summary + `"}`)}
}

func summary(t *testing.T, res *ipa.Response) string {
	t.Helper()
	if res.Result == nil || res.Result.Summary == "" {
		t.Fatalf("no summary in %+v", res)
	}
	return res.Result.Summary
}

func TestReplay_Precedence(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jdoe", ipatest.User{First: "J", Last: "Doe"})
	s.SetReplay(fstest.MapFS{
		"4.13.4/user_show.json":   recording("recorded"),
		"4.13.4/config_show.json": recording("recorded"),
	})
	s.Handle("config_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{}, "summary": "handled"}, nil
	})
	c := s.ClientAs("admin")
	res, err := c.RPC("user_show", []string{"jdoe"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Result.Data), "jdoe") {
		t.Errorf("user_show answered %s, want the builtin's entry", res.Result.Data)
	}
	res, err = c.RPC("config_show", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(t, res); got != "handled" {
		t.Errorf("config_show summary = %q, want the Handle override", got)
	}
}

func TestReplay_PicksRelease(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetReplay(fstest.MapFS{
		"README.md":               {Data: []byte("x")},
		"4.9.13/config_show.json": recording("4.9.13"),
		"4.12.2/config_show.json": recording("4.12.2"),
		"4.13.4/other_show.json":  recording("4.13.4"),
	})
	c := s.ClientAs("admin")
	for _, tc := range []struct{ version, want string }{
		{"4.12.5", "4.12.2"},
		{"4.13.4", "4.12.2"},
		{"4.12.2", "4.12.2"},
		{"4.10.0", "4.9.13"},
		{"4.9.0", "4.9.13"},
	} {
		s.SetVersion(tc.version)
		res, err := c.RPC("config_show", nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.version, err)
		}
		if got := summary(t, res); got != tc.want {
			t.Errorf("SetVersion(%s): answered %s, want %s", tc.version, got, tc.want)
		}
	}
}

func TestReplay_Disabled(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetReplay(fstest.MapFS{"4.13.4/config_show.json": recording("recorded")})
	s.SetReplay(nil)
	_, err := s.ClientAs("admin").RPC("config_show", nil, nil)
	var ierr *ipa.IpaError
	if !errors.As(err, &ierr) || ierr.Code != ipa.CodeCommand {
		t.Fatalf("err = %#v, want 905", err)
	}
}

func TestReplay_InBatch(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetReplay(fstest.MapFS{"4.13.4/config_show.json": recording("recorded")})
	var out struct {
		Result struct {
			Results []map[string]any `json:"results"`
		} `json:"result"`
	}
	body := `{"method":"batch","params":[[{"method":"config_show","params":[[],{}]}],{}]}`
	resp := post(t, s, body, s.URL()+"/ipa")
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Result.Results) != 1 || out.Result.Results[0]["summary"] != "recorded" {
		t.Errorf("batch results = %v", out.Result.Results)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeIPA answers every request with envelope and checks the request body
// still reaches it.
func fakeIPA(t *testing.T, envelope string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		if !bytes.Contains(b, []byte(`"method"`)) {
			t.Errorf("request body lost: %q", b)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(envelope)), Request: r}, nil
	})
}

func recordPost(t *testing.T, rt http.RoundTripper, path, method string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://ipa.example"+path, strings.NewReader(`{"method":"`+method+`","params":[[],{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRecorder_Redacts(t *testing.T) {
	dir := t.TempDir()
	envelope := `{"result":{"result":{"uid":["jdoe"],"nested":{"randompassword":"s3cret"},` +
		`"tokens":[{"uri":"otpauth://totp/x?secret=ABC"}],"ipatokenotpkey":[{"__base64__":"AAAA"}]},"value":"jdoe","summary":"ok"},` +
		`"error":null,"id":0,"principal":"admin@X","version":"4.12.2"}`
	rt := ipatest.NewRecorder(fakeIPA(t, envelope), dir)
	if got := recordPost(t, rt, "/ipa/session/json", "user_add"); got != envelope {
		t.Errorf("response changed: %s", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "4.12.2", "user_add.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"s3cret", "otpauth", "AAAA"} {
		if bytes.Contains(b, []byte(leak)) {
			t.Errorf("recording leaks %q: %s", leak, b)
		}
	}
	var rec struct {
		Result struct {
			UID    []string `json:"uid"`
			Nested struct {
				RandomPassword string `json:"randompassword"`
			} `json:"nested"`
			Tokens []struct {
				URI string `json:"uri"`
			} `json:"tokens"`
			OTPKey string `json:"ipatokenotpkey"`
		} `json:"result"`
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	r := rec.Result
	if r.Nested.RandomPassword != "REDACTED" || len(r.Tokens) != 1 || r.Tokens[0].URI != "REDACTED" || r.OTPKey != "REDACTED" {
		t.Errorf("not redacted: %+v", r)
	}
	if len(r.UID) != 1 || r.UID[0] != "jdoe" || rec.Summary != "ok" {
		t.Errorf("other values changed: %s", b)
	}
}

func TestRecorder_SkipsErrors(t *testing.T) {
	for name, tc := range map[string]struct{ path, method, envelope string }{
		"error":       {"/ipa/session/json", "user_show", `{"result":null,"error":{"code":4001,"message":"x"},"version":"4.12.2"}`},
		"no version":  {"/ipa/session/json", "user_show", `{"result":{"summary":"x"},"error":null,"version":""}`},
		"batch":       {"/ipa/session/json", "batch", `{"result":{"count":0,"results":[]},"error":null,"version":"4.12.2"}`},
		"other path":  {"/ipa/session/login_password", "user_show", `{"result":{"summary":"x"},"error":null,"version":"4.12.2"}`},
		"bad method":  {"/ipa/json", "../user_show", `{"result":{"summary":"x"},"error":null,"version":"4.12.2"}`},
		"bad version": {"/ipa/json", "user_show", `{"result":{"summary":"x"},"error":null,"version":"../4"}`},
		"not json":    {"/ipa/json", "user_show", `<html>denied</html>`},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			rt := ipatest.NewRecorder(fakeIPA(t, tc.envelope), dir)
			if got := recordPost(t, rt, tc.path, tc.method); got != tc.envelope {
				t.Errorf("response changed: %s", got)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("recorded %v", entries)
			}
		})
	}
}

// TestRecorder_RoundTrip records from one ipatest server and replays the
// recording on another.
func TestRecorder_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := ipatest.NewServer(t)
	src.SetVersion("4.12.2")
	src.Handle("config_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"ipamaxusernamelength": []any{"32"}}, "value": nil, "summary": nil}, nil
	})
	hc := src.HTTPClient()
	hc.Transport = ipatest.NewRecorder(hc.Transport, dir)
	c := ipa.NewClientCustomHttp(src.Host(), src.Realm(), hc)
	c.SetSessionID(src.Session("admin"))
	if _, err := c.RPC("config_show", nil, nil); err != nil {
		t.Fatal(err)
	}

	dst := ipatest.NewServer(t)
	dst.SetReplay(os.DirFS(dir))
	res, err := dst.ClientAs("admin").RPC("config_show", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Result.Data; !strings.Contains(string(got), `"ipamaxusernamelength":["32"]`) {
		t.Errorf("replayed %s", got)
	}
}
