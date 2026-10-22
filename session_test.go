// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ipa "github.com/neverlless/goipa"
)

const testSession = "0123456789abcdef0123456789abcdef"

func newPingServer(t *testing.T, cookies ...string) *ipa.Client {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range cookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.Write([]byte(`{"error":null,"id":0,"principal":"admin@EXAMPLE.COM","version":"4.12.2","result":{"summary":"IPA server version 4.12.2"}}`))
	}))
	t.Cleanup(ts.Close)
	return ipa.NewClientCustomHttp(strings.TrimPrefix(ts.URL, "https://"), "EXAMPLE.COM", ts.Client())
}

func TestSessionCookieAfterOtherCookie(t *testing.T) {
	c := newPingServer(t,
		"lb=backend1; Path=/",
		"ipa_session=MagBearerToken="+testSession+"; Path=/ipa; Secure; HttpOnly",
	)

	if _, err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got := c.SessionID(); got != "MagBearerToken="+testSession {
		t.Errorf("SessionID = %q", got)
	}
}

func TestSessionCookieOnlyOtherCookies(t *testing.T) {
	c := newPingServer(t, "lb=backend1; Path=/")

	if _, err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got := c.SessionID(); got != "" {
		t.Errorf("SessionID = %q, want empty", got)
	}
}

func TestSessionCookieInvalid(t *testing.T) {
	c := newPingServer(t, "ipa_session=short; Path=/ipa")

	if _, err := c.Ping(); err == nil {
		t.Fatal("Ping: want error for an invalid ipa_session cookie")
	}
}

// Run with -race: a Client is shared across goroutines (as mokey does).
func TestClientConcurrentUse(t *testing.T) {
	c := newPingServer(t, "ipa_session="+testSession+"; Path=/ipa")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Ping(); err != nil {
				t.Error(err)
			}
			_ = c.SessionID()
			c.StickySession(true)
		}()
	}
	wg.Wait()
}
