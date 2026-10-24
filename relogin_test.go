// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// countingRT counts login_password requests and, with deny401, answers 401
// to every /ipa/session/json call itself.
type countingRT struct {
	next    http.RoundTripper
	logins  atomic.Int32
	deny401 bool
}

func (rt *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/login_password"):
		rt.logins.Add(1)
	case rt.deny401 && r.URL.Path == "/ipa/session/json":
		return &http.Response{StatusCode: 401, Status: "401 Unauthorized", Body: http.NoBody, Request: r, Header: http.Header{}}, nil
	}
	return rt.next.RoundTrip(r)
}

const reloginPW = "Relogin-Passw0rd"

func reloginSetup(t *testing.T, relogin bool) (*ipatest.Server, *ipa.Client, *countingRT) {
	t.Helper()
	srv := ipatest.NewServer(t)
	srv.AddUser("rita", ipatest.User{Password: reloginPW})
	hc := srv.HTTPClient()
	rt := &countingRT{next: hc.Transport}
	hc.Transport = rt
	opts := []ipa.Option{ipa.WithHost(srv.Host()), ipa.WithRealm(srv.Realm()), ipa.WithHTTPClient(hc)}
	if relogin {
		opts = append(opts, ipa.WithPasswordRelogin())
	}
	c, err := ipa.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RemoteLogin("rita", reloginPW); err != nil {
		t.Fatal(err)
	}
	return srv, c, rt
}

func TestExpiredSession_NoReloginByDefault(t *testing.T) {
	srv, c, rt := reloginSetup(t, false)
	srv.ExpireSession(c.SessionID())
	if _, err := c.UserShow("rita"); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if c.SessionID() != "" {
		t.Errorf("SessionID = %q, want cleared", c.SessionID())
	}
	if n := rt.logins.Load(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
}

func TestRelogin_Password(t *testing.T) {
	srv, c, rt := reloginSetup(t, true)
	old := c.SessionID()
	srv.ExpireSession(old)
	if _, err := c.UserShow("rita"); err != nil {
		t.Fatal(err)
	}
	if c.SessionID() == old || c.SessionID() == "" {
		t.Errorf("SessionID = %q, want a new one", c.SessionID())
	}
	if n := rt.logins.Load(); n != 2 {
		t.Errorf("logins = %d, want 2", n)
	}
}

func TestRelogin_PasswordChanged(t *testing.T) {
	srv, c, rt := reloginSetup(t, true)
	srv.UpdateUser("rita", func(u *ipatest.User) { u.Password = "other" })
	srv.ExpireSession(c.SessionID())
	if _, err := c.UserShow("rita"); !errors.Is(err, ipa.ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
	if n := rt.logins.Load(); n != 2 {
		t.Errorf("logins = %d, want 2", n)
	}
	// A rejected password is dropped: retrying it would walk the account
	// into lockout.
	c.SetSessionID(srv.Session("rita"))
	srv.ExpireSession(c.SessionID())
	if _, err := c.UserShow("rita"); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("second call: err = %v, want ErrUnauthorized", err)
	}
	if n := rt.logins.Load(); n != 2 {
		t.Errorf("logins after second call = %d, want 2", n)
	}
}

func TestRelogin_OnlyOnce(t *testing.T) {
	_, c, rt := reloginSetup(t, true)
	rt.deny401 = true
	_, err := c.UserShow("rita")
	if !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if n := rt.logins.Load(); n != 2 {
		t.Errorf("logins = %d, want 2 (one re-login)", n)
	}
}

func TestRelogin_ConcurrentExpiry(t *testing.T) {
	srv, c, rt := reloginSetup(t, true)
	srv.ExpireSession(c.SessionID())
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.UserShow("rita")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := rt.logins.Load() - 1; got != 1 {
		t.Errorf("re-logins = %d, want 1", got)
	}
}

// A changed password must cost one failed login, not one per goroutine:
// FreeIPA locks the account after a few failures.
func TestRelogin_ConcurrentPasswordChanged(t *testing.T) {
	srv, c, rt := reloginSetup(t, true)
	srv.UpdateUser("rita", func(u *ipatest.User) { u.Password = "other" })
	srv.ExpireSession(c.SessionID())
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.UserShow("rita"); err == nil {
				t.Error("UserShow succeeded with a changed password")
			}
		}()
	}
	wg.Wait()
	if got := rt.logins.Load() - 1; got != 1 {
		t.Errorf("failed re-logins = %d, want 1", got)
	}
}

func TestRelogin_NotWithoutStickySession(t *testing.T) {
	srv, c, rt := reloginSetup(t, true)
	c.StickySession(false)
	srv.ExpireSession(c.SessionID())
	for range 3 {
		if _, err := c.UserShow("rita"); !errors.Is(err, ipa.ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	}
	if n := rt.logins.Load(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
}

func TestRelogin_ClearSessionForgetsPassword(t *testing.T) {
	_, c, rt := reloginSetup(t, true)
	c.ClearSession()
	if _, err := c.UserShow("rita"); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if n := rt.logins.Load(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
}

func TestSessionLogout(t *testing.T) {
	srv := ipatest.NewServer(t)
	c := srv.ClientAs("admin")
	res, err := c.RPC("session_logout", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Result.Data) != "null" {
		t.Errorf("result = %s, want null", res.Result.Data)
	}
	if sid := c.SessionID(); sid != "" {
		t.Errorf("SessionID = %q after logout, want cleared by the deletion cookie", sid)
	}
	if _, err := c.Ping(); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Fatalf("after logout: err = %v, want ErrUnauthorized", err)
	}
}
