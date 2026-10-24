// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
	c, _ := expiryServer(t)
	const fresh = "MagBearerToken=fresh"
	c.httpClient.Transport = &swapRT{next: c.httpClient.Transport, fn: func() { c.SetSessionID(fresh) }}
	c.SetSessionID(oldSID)
	// The old session's 401 must not clear the fresh one; the retry uses it.
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if c.SessionID() != fresh {
		t.Errorf("SessionID = %q, want %q", c.SessionID(), fresh)
	}
}
