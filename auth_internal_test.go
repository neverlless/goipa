// The cgo resolver used by SPNEGO's CNAME lookup adds happens-before edges
// that hide the race from the detector.
//go:debug netdns=go

// Copyright 2026 goipa Authors.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
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
