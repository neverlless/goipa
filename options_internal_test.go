// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
