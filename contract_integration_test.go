//go:build integration

// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

func init() { extraBackends = realBackends }

var (
	realOnce sync.Once
	realB    backend
	realSkip string
)

// realBackends connects once per test binary: a wrong IPA_ADMIN_PASS must
// cost one failed login, not one per test (FreeIPA locks at 6).
func realBackends(t *testing.T) []backend {
	realOnce.Do(func() { realB, realSkip = connectReal() })
	if realSkip != "" {
		// In CI a missing server is a broken nightly, not a reason to skip.
		if os.Getenv("CI") != "" {
			t.Fatal("real FreeIPA unavailable: " + realSkip)
		}
		t.Run("freeipa", func(t *testing.T) { t.Skip(realSkip) })
		return nil
	}
	return []backend{realB}
}

func connectReal() (backend, string) {
	pass := getenv("IPA_ADMIN_PASS", "")
	if pass == "" {
		return backend{}, "IPA_ADMIN_PASS not set"
	}
	ca, err := os.ReadFile("/etc/ipa/ca.crt")
	if err != nil {
		return backend{}, "/etc/ipa/ca.crt missing"
	}
	def := ipa.NewDefaultClient()
	if def.Host() == "" {
		return backend{}, "/etc/ipa/default.conf missing"
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	b := backend{name: "freeipa", host: def.Host(), realm: def.Realm(), http: hc}
	b.admin = b.client()
	if err := b.admin.RemoteLogin(getenv("IPA_ADMIN_USER", "admin"), pass); err != nil {
		return backend{}, "admin login failed: " + err.Error()
	}
	return b, ""
}
