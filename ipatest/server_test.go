// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestClientWiring(t *testing.T) {
	s := ipatest.NewServer(t)
	if got := s.Client().Host(); got != s.Host() {
		t.Errorf("Client().Host() = %q, want %q", got, s.Host())
	}
	if got := s.Realm(); got != "TEST.LOCAL" {
		t.Errorf("Realm() = %q", got)
	}
	if !strings.HasPrefix(s.URL(), "https://") {
		t.Errorf("URL() = %q", s.URL())
	}
	s.Close()
	s.Close() // and once more from tb.Cleanup
}

func TestNegotiateUser(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.Client()
	if _, err := c.Ping(); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("Ping without negotiate user: err = %v, want ErrUnauthorized", err)
	}
	s.SetNegotiateUser("admin")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.SessionID(), "MagBearerToken=") {
		t.Errorf("SessionID = %q", c.SessionID())
	}
	if got := s.Calls()[0].User; got != "admin" {
		t.Errorf("Calls()[0].User = %q", got)
	}

	req, _ := http.NewRequest(http.MethodPost, s.URL()+"/ipa/json", strings.NewReader(`{"method":"ping","params":[[],{}]}`))
	req.Header.Set("Referer", s.URL()+"/ipa/xml")
	res, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := res.Header.Get("Set-Cookie"); !strings.HasPrefix(got, "ipa_session=MagBearerToken=") || !strings.HasSuffix(got, "; Path=/ipa; Secure; HttpOnly") {
		t.Errorf("Set-Cookie = %q", got)
	}
}

func TestClientAs(t *testing.T) {
	s := ipatest.NewServer(t)
	res, err := s.ClientAs("admin").Ping()
	if err != nil {
		t.Fatal(err)
	}
	if res.Principal != "admin@TEST.LOCAL" || res.Version != "4.13.4" {
		t.Errorf("Principal = %q, Version = %q", res.Principal, res.Version)
	}
}

func TestUnknownCommand(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("nope_cmd", nil, nil)
	var ierr *ipa.IpaError
	if !errors.As(err, &ierr) || ierr.Code != 905 || ierr.Name != "CommandError" {
		t.Fatalf("err = %#v, want 905 CommandError", err)
	}
	if ierr.Message != "unknown command 'nope_cmd'" {
		t.Errorf("Message = %q", ierr.Message)
	}
}

func TestHandleOverrides(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.Handle("ping", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: ipa.CodeACI, Message: "x"}
	})
	_, err := c.Ping()
	if !errors.Is(err, ipa.ErrACI) {
		t.Fatalf("err = %v, want ErrACI", err)
	}
	var ierr *ipa.IpaError
	if errors.As(err, &ierr) && ierr.Name != "ACIError" {
		t.Errorf("Name = %q, want ACIError from the code map", ierr.Name)
	}
	s.Handle("ping", nil)
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestHandleWholeResultObject(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.Handle("hbactest", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"value": true, "matched": []string{"r1"}, "summary": "Access granted: True"}, nil
	})
	res, err := c.RPC("hbactest", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Result.Data) != 0 {
		t.Errorf("Data = %s, want empty (hbactest has no result key)", res.Result.Data)
	}
	if !strings.Contains(string(res.Result.Raw), `"matched":["r1"]`) {
		t.Errorf("Raw = %s", res.Result.Raw)
	}

	s.Handle("group_add_member", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{
			"result":    map[string]any{"cn": []string{"g"}},
			"completed": 0,
			"failed":    map[string]any{"member": map[string]any{"user": [][]string{{"bob", "This entry is already a member"}}}},
		}, nil
	})
	res, err = c.RPC("group_add_member", []string{"g"}, ipa.Options{"user": []string{"bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Result.Completed != 0 || !strings.Contains(string(res.Result.Failed), "bob") {
		t.Errorf("Completed = %d, Failed = %s", res.Result.Completed, res.Result.Failed)
	}
	if strings.Contains(string(res.Result.Data), "failed") {
		t.Errorf("Data = %s, want failed as a sibling of result", res.Result.Data)
	}
}

func TestCallsRecorded(t *testing.T) {
	s := ipatest.NewServer(t)
	if _, err := s.ClientAs("admin").RPC("ping", []string{"a"}, ipa.Options{"x": 1.0}); err != nil {
		t.Fatal(err)
	}
	calls := s.Calls()
	got := calls[len(calls)-1]
	if got.Method != "ping" || !reflect.DeepEqual(got.Args, []string{"a"}) || got.Options["x"] != 1.0 || got.User != "admin" {
		t.Errorf("last call = %+v", got)
	}
	if _, ok := got.Options["version"]; !ok {
		t.Errorf("Options = %v, want version", got.Options)
	}
	got.Options["x"] = 2.0
	if s.Calls()[len(calls)-1].Options["x"] != 1.0 {
		t.Error("Calls() shares Options with the server's log")
	}
}

func TestHandleMayCallAccessors(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.Handle("ping", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"summary": s.Session("x") + s.Calls()[0].Method}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.RPCContext(ctx, "ping", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSessionsNotShared(t *testing.T) {
	a, b := ipatest.NewServer(t), ipatest.NewServer(t)
	c := b.Client()
	c.SetSessionID(a.Session("admin"))
	if _, err := c.Ping(); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func post(t *testing.T, s *ipatest.Server, body, referer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.URL()+"/ipa/session/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "ipa_session="+s.Session("admin"))
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	res, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestBadRequestBody(t *testing.T) {
	s := ipatest.NewServer(t)
	for _, body := range []string{"{", `{"method":"ping","params":"x"}`} {
		if res := post(t, s, body, s.URL()+"/ipa/xml"); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, res.StatusCode)
		}
	}
	// params missing must not panic the server.
	if res := post(t, s, `{"method":"ping"}`, s.URL()+"/ipa/xml"); res.StatusCode != http.StatusOK {
		t.Errorf("no params: status = %d, want 200", res.StatusCode)
	}
}

func TestRefererJSONRPC(t *testing.T) {
	s := ipatest.NewServer(t)
	for referer, want := range map[string]string{
		"":                      "Missing or invalid HTTP Referer, missing",
		"https://evil.test/ipa": "Missing or invalid HTTP Referer, https://evil.test/ipa",
	} {
		res := post(t, s, `{"method":"ping","params":[[],{}],"id":0}`, referer)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", res.StatusCode)
		}
		var env struct {
			Error *ipa.IpaError
		}
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		if env.Error == nil || env.Error.Code != 911 || env.Error.Name != "RefererError" || env.Error.Message != want {
			t.Errorf("referer %q: error = %+v", referer, env.Error)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls recorded, want 0 for rejected requests", n)
	}
}

func TestNewWithoutTB(t *testing.T) {
	s := ipatest.New()
	if _, err := s.ClientAs("admin").Ping(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.Close()
}
