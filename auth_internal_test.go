// The cgo resolver used by SPNEGO's CNAME lookup adds happens-before edges
// that hide the race from the detector.
//go:debug netdns=go

// Copyright 2026 goipa Authors.
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
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// Run with -race: replacing the Kerberos client must not race with an rpc
// still inside SPNEGO on the old one.
func TestSetKrbClientConcurrentWithSPNEGO(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"summary":"ok"}}`))
	}))
	defer srv.Close()

	c := NewClientCustomHttp(strings.TrimPrefix(srv.URL, "https://"), "EXAMPLE.COM", srv.Client())
	newKrb := func() *client.Client { return client.NewWithPassword("u", "EXAMPLE.COM", "pw", config.New()) }
	c.setKrbClient(newKrb())

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				// No KDC: SPNEGO fails, but only after reading the client's credentials.
				_, _ = c.rpc(context.Background(), "ping", nil, nil)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-done:
			c.setKrbClient(nil)
			return
		default:
			c.setKrbClient(newKrb())
		}
	}
}

func TestLoginKeytab_NoCanonicalize(t *testing.T) {
	c := NewClient("h", "EXAMPLE.COM")
	c.krb5Data = "[libdefaults]\n default_realm = EXAMPLE.COM\n canonicalize = true\n"
	cl, err := c.keytabClient(keytab.New(), "u")
	if err != nil {
		t.Fatal(err)
	}
	if cl.Config.LibDefaults.Canonicalize {
		t.Fatal("canonicalize must be off for keytab login")
	}
}

func TestCanonicalNameError(t *testing.T) {
	base := errors.New("CName in response does not match what was requested")
	err := canonicalNameError("alias", base)
	if !errors.Is(err, base) || !strings.Contains(err.Error(), `"alias"`) {
		t.Fatalf("got %v", err)
	}
	other := errors.New("other")
	if canonicalNameError("a", other) != other || canonicalNameError("a", nil) != nil {
		t.Fatal("unrelated errors must pass through")
	}
}
