// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

const (
	oldSID = "MagBearerToken=old"
	newSID = "MagBearerToken=new"
)

// expiryServer answers 401 to oldSID on /ipa/session/json, accepts any other
// session, and on /ipa/json accepts "Negotiate x" and issues newSID.
func expiryServer(t *testing.T) (*Client, *atomic.Int32) {
	t.Helper()
	var negotiated atomic.Int32
	ok := func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"result":{"summary":"ok"}}`)) }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipa/session/json":
			if ck, err := r.Cookie("ipa_session"); err != nil || ck.Value == oldSID {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			ok(w)
		case "/ipa/json":
			if r.Header.Get("Authorization") != "Negotiate x" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			negotiated.Add(1)
			w.Header().Set("Set-Cookie", "ipa_session="+newSID+"; Path=/ipa")
			ok(w)
		}
	}))
	t.Cleanup(srv.Close)
	return NewClientCustomHttp(strings.TrimPrefix(srv.URL, "https://"), "EXAMPLE.COM", srv.Client()), &negotiated
}

func TestExpiredSession_KerberosRetry(t *testing.T) {
	orig := setSPNEGOHeader
	t.Cleanup(func() { setSPNEGOHeader = orig })
	setSPNEGOHeader = func(_ *client.Client, r *http.Request, _ string) error {
		r.Header.Set("Authorization", "Negotiate x")
		return nil
	}
	c, negotiated := expiryServer(t)
	c.setKrbClient(client.NewWithPassword("u", "EXAMPLE.COM", "p", config.New()))
	c.SetSessionID(oldSID)
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if c.SessionID() != newSID {
		t.Errorf("SessionID = %q, want %q", c.SessionID(), newSID)
	}
	if negotiated.Load() != 1 {
		t.Errorf("SPNEGO calls = %d, want 1", negotiated.Load())
	}
}

// swapRT runs fn before the first request, standing in for another goroutine
// that stores a fresh session while this one's request is in flight.
type swapRT struct {
	next http.RoundTripper
	fn   func()
	done atomic.Bool
}

func (rt *swapRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if !rt.done.Swap(true) {
		rt.fn()
	}
	return rt.next.RoundTrip(r)
}

func TestExpiredSession_CompareAndClear(t *testing.T) {
	const fresh = "MagBearerToken=fresh"
	// start "" is a request sent after another goroutine's 401 cleared the
	// session; its 401 is retried on the session that goroutine then stored.
	for _, start := range []string{oldSID, ""} {
		t.Run("start="+start, func(t *testing.T) {
			c, _ := expiryServer(t)
			c.httpClient.Transport = &swapRT{next: c.httpClient.Transport, fn: func() { c.SetSessionID(fresh) }}
			c.SetSessionID(start)
			// The 401 must not clear the fresh session; the retry uses it.
			if _, err := c.Ping(); err != nil {
				t.Fatal(err)
			}
			if c.SessionID() != fresh {
				t.Errorf("SessionID = %q, want %q", c.SessionID(), fresh)
			}
		})
	}
}

func TestSetSessionID_LogoutCookieClears(t *testing.T) {
	c := &Client{sticky: true, sessionID: oldSID}
	res := &http.Response{Header: http.Header{"Set-Cookie": {"ipa_session=MagBearerToken=; Path=/ipa"}}}
	if err := c.setSessionID(res); err != nil {
		t.Fatal(err)
	}
	if c.SessionID() != "" {
		t.Errorf("SessionID = %q, want cleared", c.SessionID())
	}
}

func TestSPNEGO401NotRetried(t *testing.T) {
	orig := setSPNEGOHeader
	t.Cleanup(func() { setSPNEGOHeader = orig })
	var calls atomic.Int32
	setSPNEGOHeader = func(_ *client.Client, r *http.Request, _ string) error {
		calls.Add(1)
		r.Header.Set("Authorization", "Negotiate rejected")
		return nil
	}
	c, _ := expiryServer(t)
	c.setKrbClient(client.NewWithPassword("u", "EXAMPLE.COM", "p", config.New()))
	if _, err := c.Ping(); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if calls.Load() != 1 {
		t.Errorf("SPNEGO attempts = %d, want 1", calls.Load())
	}
}

func TestSetSessionID_DeletionCookieClearsSession(t *testing.T) {
	for name, hdr := range map[string]string{
		"empty value":  "ipa_session=; Path=/ipa; Secure; HttpOnly",
		"max-age zero": "ipa_session=abc; Max-Age=0; Path=/ipa",
		"past expires": "ipa_session=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/ipa",
	} {
		t.Run(name, func(t *testing.T) {
			c := &Client{sticky: true, sessionID: "0123456789abcdef0123456789abcdef"}
			res := &http.Response{Header: http.Header{"Set-Cookie": {hdr}}}
			if err := c.setSessionID(res); err != nil {
				t.Fatal(err)
			}
			if c.sessionID != "" {
				t.Errorf("sessionID = %q, want cleared", c.sessionID)
			}
		})
	}
}

// slowLoginServer answers 401 to oldSID and to requests without a session,
// and holds each password login until release is called; started is closed
// when the first login arrives. unauth counts the 401s.
func slowLoginServer(t *testing.T) (c *Client, started chan struct{}, release func(), unauth *atomic.Int32) {
	t.Helper()
	started, unauth = make(chan struct{}), new(atomic.Int32)
	released := make(chan struct{})
	var once sync.Once
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipa/session/login_password":
			once.Do(func() { close(started) })
			<-released
			w.Header().Set("Set-Cookie", "ipa_session="+newSID+"; Path=/ipa")
		case "/ipa/session/json":
			if ck, err := r.Cookie("ipa_session"); err == nil && ck.Value == newSID {
				_, _ = w.Write([]byte(`{"result":{"summary":"ok"}}`))
				return
			}
			fallthrough
		default:
			unauth.Add(1)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	var releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(released) }) }
	t.Cleanup(release) // runs before srv.Close
	c = NewClientCustomHttp(strings.TrimPrefix(srv.URL, "https://"), "EXAMPLE.COM", srv.Client())
	c.relogin = true
	c.reloginUser, c.reloginPass = "u", "p"
	c.sessionID = oldSID
	return c, started, release, unauth
}

func waitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("call did not return")
		return nil
	}
}

func TestRelogin_WaiterCancelled(t *testing.T) {
	c, started, release, unauth := slowLoginServer(t)
	errA := make(chan error, 1)
	go func() { _, err := c.Ping(); errA <- err }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errB := make(chan error, 1)
	go func() { _, err := c.PingContext(ctx); errB <- err }()
	for unauth.Load() < 2 { // B got its 401 and goes on to wait for A's login
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := waitErr(t, errB); !errors.Is(err, context.Canceled) {
		t.Errorf("waiter: err = %v, want context.Canceled", err)
	}

	release()
	if err := waitErr(t, errA); err != nil {
		t.Errorf("login owner: %v", err)
	}
	if c.SessionID() != newSID {
		t.Errorf("SessionID = %q, want %q", c.SessionID(), newSID)
	}
}

func TestClearSession_DuringRelogin(t *testing.T) {
	c, started, release, _ := slowLoginServer(t)
	errA := make(chan error, 1)
	go func() { _, err := c.Ping(); errA <- err }()
	<-started
	c.ClearSession()
	release()
	if err := waitErr(t, errA); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
	if sid := c.SessionID(); sid != "" {
		t.Errorf("SessionID = %q, want cleared", sid)
	}
	c.mu.Lock()
	user := c.reloginUser
	c.mu.Unlock()
	if user != "" {
		t.Errorf("relogin user = %q, want forgotten", user)
	}
}
