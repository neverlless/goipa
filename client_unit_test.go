// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func newFake(t *testing.T) (*ipatest.Server, *ipa.Client) {
	t.Helper()
	s := ipatest.NewServer(t)
	return s, s.ClientAs("admin")
}

func TestConstructors(t *testing.T) {
	c := ipa.NewClient("h", "R")
	if c.Host() != "h" || c.Realm() != "R" {
		t.Errorf("host/realm = %q/%q", c.Host(), c.Realm())
	}
	if ipa.NewDefaultClient() == nil {
		t.Error("NewDefaultClient() = nil")
	}
	if got := ipa.NewDefaultClientWithSession("sid").SessionID(); got != "sid" {
		t.Errorf("SessionID = %q", got)
	}
}

func TestStickySessionOff(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{Password: "secret123"})
	c := s.Client()
	c.StickySession(false)
	if err := c.RemoteLogin("bob", "secret123"); err != nil {
		t.Fatal(err)
	}
	if got := c.SessionID(); got != "" {
		t.Errorf("SessionID = %q, want empty", got)
	}
}

func TestClearSession(t *testing.T) {
	_, c := newFake(t)
	if c.SessionID() == "" {
		t.Fatal("ClientAs has no session")
	}
	c.ClearSession()
	if got := c.SessionID(); got != "" {
		t.Errorf("SessionID = %q after ClearSession", got)
	}
}

func TestRemoteLoginHTTPStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	t.Cleanup(ts.Close)
	c := ipa.NewClientCustomHttp(strings.TrimPrefix(ts.URL, "https://"), "R", ts.Client())
	if err := c.RemoteLogin("u", "p"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v", err)
	}
}

func TestParseDateTime(t *testing.T) {
	if got, want := ipa.ParseDateTime("20261022090000Z"), time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := ipa.ParseDateTime("bad"); !got.IsZero() {
		t.Errorf("got %v, want zero", got)
	}
}

func TestKerberosLoginErrors(t *testing.T) {
	c := ipa.NewClient("h", "R")
	if err := c.LoginWithKeytab("/nonexistent", "u"); err == nil {
		t.Error("LoginWithKeytab: nil error")
	}
	if err := c.LoginFromCCache("/nonexistent"); err == nil {
		t.Error("LoginFromCCache: nil error")
	}
}
