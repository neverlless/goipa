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
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

func init() { extraBackends = realBackends }

func skipped(t *testing.T, why string) []backend {
	t.Run("freeipa", func(t *testing.T) { t.Skip(why) })
	return nil
}

// realBackends returns the FreeIPA the IPA_* environment points at, or skips.
func realBackends(t *testing.T) []backend {
	pass := getenv("IPA_ADMIN_PASS", "")
	if pass == "" {
		return skipped(t, "IPA_ADMIN_PASS not set")
	}
	ca, err := os.ReadFile("/etc/ipa/ca.crt")
	if err != nil {
		return skipped(t, "/etc/ipa/ca.crt missing")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	def := ipa.NewDefaultClient()
	b := backend{name: "freeipa", host: def.Host(), realm: def.Realm(), http: hc}
	b.admin = b.client()
	if err := b.admin.RemoteLogin(getenv("IPA_ADMIN_USER", "admin"), pass); err != nil {
		t.Fatal(err)
	}
	return []backend{b}
}
