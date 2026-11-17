// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMain fails when package init (or an init()) already read /etc/ipa.
func TestMain(m *testing.M) {
	if n := defaultsLoads.Load(); n != 0 {
		fmt.Fprintf(os.Stderr, "defaults loaded %d times before tests: import-time I/O\n", n)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestLoadIPADefaults(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "default.conf")
	ca := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(conf, []byte("[global]\nxmlrpc_uri = https://ipa.t.test/ipa/xml\nrealm = T.TEST\n"), 0o600))

	d := loadIPADefaults(conf, filepath.Join(dir, "missing"))
	require.Equal(t, "ipa.t.test", d.host)
	require.Equal(t, "T.TEST", d.realm)
	require.Nil(t, d.pool)

	z := loadIPADefaults(filepath.Join(dir, "no"), filepath.Join(dir, "no"))
	require.Equal(t, ipaDefaults{}, z)

	require.NoError(t, os.WriteFile(ca, []byte("garbage"), 0o600))
	require.Nil(t, loadIPADefaults(conf, ca).pool)

	require.NoError(t, os.WriteFile(ca, []byte(testCAPEM(t)), 0o600))
	require.NotNil(t, loadIPADefaults(conf, ca).pool)
}

func swapDefaults(t *testing.T, d ipaDefaults) {
	t.Helper()
	old := systemDefaults
	systemDefaults = func() ipaDefaults { return d }
	t.Cleanup(func() { systemDefaults = old })
}

func TestDefaults_OldConstructorsUseLoadedFiles(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h.t.test", realm: "T.TEST"})
	c := NewDefaultClient()
	require.Equal(t, "h.t.test", c.Host())
	require.Equal(t, "T.TEST", c.Realm())
	require.True(t, c.sticky)
	require.Equal(t, "s", NewDefaultClientWithSession("s").SessionID())
}

func TestNew_NoHost(t *testing.T) {
	swapDefaults(t, ipaDefaults{})
	_, err := New()
	require.EqualError(t, err, "ipa: no FreeIPA host: use WithHost or /etc/ipa/default.conf")
}

func TestNew_FillsFromDefaults(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h.t.test", realm: "T.TEST"})
	c, err := New(WithKrb5Config("/k"), WithPasswordRelogin())
	require.NoError(t, err)
	require.Equal(t, "h.t.test", c.Host())
	require.Equal(t, "T.TEST", c.Realm())
	require.Equal(t, "/k", c.krb5Path)
	require.True(t, c.relogin)
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
}

func TestDomain_Option(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h", realm: "T.TEST", domain: "conf.test"})
	c, err := New(WithDomain("opt.test"))
	require.NoError(t, err)
	require.Equal(t, "opt.test", c.Domain())
}

func TestDomain_FromDefaultConf(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h", realm: "T.TEST", domain: "conf.test"})
	c, err := New()
	require.NoError(t, err)
	require.Equal(t, "conf.test", c.Domain())
	require.Equal(t, "conf.test", NewDefaultClient().Domain())
	require.Equal(t, "conf.test", NewDefaultClientWithSession("s").Domain())
}

func TestDomain_FallbackLowerRealm(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h", realm: "T.TEST"})
	c, err := New()
	require.NoError(t, err)
	require.Equal(t, "t.test", c.Domain())
	require.Equal(t, "x.test", NewClient("h", "X.TEST").Domain())
}

func TestDomain_WithRealmIgnoresConfDomain(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h", realm: "T.TEST", domain: "conf.test"})
	c, err := New(WithRealm("OTHER.TEST"))
	require.NoError(t, err)
	require.Equal(t, "other.test", c.Domain())
}

func TestLoadIPADefaults_Domain(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "default.conf")
	require.NoError(t, os.WriteFile(conf, []byte("[global]\nxmlrpc_uri = https://h/ipa/xml\nrealm = T.TEST\ndomain = d.test\n"), 0o600))
	require.Equal(t, "d.test", loadIPADefaults(conf, "").domain)
}

func TestWithDomain_Empty(t *testing.T) {
	_, err := New(WithHost("h"), WithDomain(""))
	require.EqualError(t, err, "ipa: WithDomain needs a value")
}

func TestNew_SharesDefaultTransport(t *testing.T) {
	pool := x509.NewCertPool()
	forgetShared(t, pool)
	swapDefaults(t, ipaDefaults{host: "h", realm: "T.TEST", pool: pool})
	a, err := New()
	require.NoError(t, err)
	b, err := New(WithRealm("X"))
	require.NoError(t, err)
	require.Same(t, a.httpClient.Transport, b.httpClient.Transport)
	require.Nil(t, a.httpClient.Jar)
	require.Equal(t, 100, a.httpClient.Transport.(*http.Transport).MaxIdleConnsPerHost)
}

func forgetShared(t *testing.T, pools ...*x509.CertPool) {
	t.Helper()
	t.Cleanup(func() {
		sharedMu.Lock()
		defer sharedMu.Unlock()
		for _, p := range pools {
			delete(sharedClients, p)
		}
	})
}

func TestSharedHTTPClient_Cap(t *testing.T) {
	var pools []*x509.CertPool
	for range maxSharedClients + 1 {
		pools = append(pools, x509.NewCertPool())
	}
	forgetShared(t, pools...)
	sharedMu.Lock()
	room := maxSharedClients - len(sharedClients)
	sharedMu.Unlock()
	for i := 0; i < room; i++ { // fill the cache to the cap
		sharedHTTPClient(pools[i])
	}
	extra := pools[room]
	a, b := sharedHTTPClient(extra), sharedHTTPClient(extra)
	require.NotSame(t, a, b)
	sharedMu.Lock()
	defer sharedMu.Unlock()
	require.Len(t, sharedClients, maxSharedClients)
}

func TestNew_CACertOwnTransport(t *testing.T) {
	swapDefaults(t, ipaDefaults{host: "h"})
	pem := []byte(testCAPEM(t))
	n := len(sharedClients)
	a, err := New(WithCACert(pem))
	require.NoError(t, err)
	b, err := New(WithCACert(pem))
	require.NoError(t, err)
	require.NotSame(t, a.httpClient.Transport, b.httpClient.Transport)
	require.Len(t, sharedClients, n)
}

func TestSharedTransport_SessionsSeparate(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("Cookie"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"result":{"summary":"ok"}}`))
	}))
	defer srv.Close()
	hc := srv.Client()
	swapDefaults(t, ipaDefaults{host: strings.TrimPrefix(srv.URL, "https://"), realm: "T"})
	// the shared client must trust the test server
	sharedMu.Lock()
	sharedClients[nil] = hc
	sharedMu.Unlock()
	t.Cleanup(func() { sharedMu.Lock(); delete(sharedClients, nil); sharedMu.Unlock() })
	a, err := New()
	require.NoError(t, err)
	b, err := New()
	require.NoError(t, err)
	a.SetSessionID("A")
	b.SetSessionID("B")
	for _, c := range []*Client{a, b, a} {
		if _, err := c.Ping(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"ipa_session=A", "ipa_session=B", "ipa_session=A"}, got)
}
