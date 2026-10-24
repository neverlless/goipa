// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/stretchr/testify/require"
)

func TestKrb5Config_Source(t *testing.T) {
	c := &Client{krb5Data: "[libdefaults]\n default_realm = D.TEST\n"}
	cfg, err := c.krb5Config()
	require.NoError(t, err)
	require.Equal(t, "D.TEST", cfg.LibDefaults.DefaultRealm)

	p := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(p, []byte("[libdefaults]\n default_realm = P.TEST\n"), 0o600))
	cfg, err = (&Client{krb5Path: p}).krb5Config()
	require.NoError(t, err)
	require.Equal(t, "P.TEST", cfg.LibDefaults.DefaultRealm)

	c.krb5Path = p
	cfg, _ = c.krb5Config()
	require.Equal(t, "D.TEST", cfg.LibDefaults.DefaultRealm, "data wins over path")
}

func TestLoginWithKeytabData_BadData(t *testing.T) {
	err := (&Client{realm: "R.TEST"}).LoginWithKeytabData([]byte("x"), "u")
	require.ErrorContains(t, err, "keytab")
}

func TestLoginFromCCacheData_BadData(t *testing.T) {
	err := (&Client{realm: "R.TEST"}).LoginFromCCacheData([]byte("x"))
	require.ErrorContains(t, err, "ccache")
}

func TestKerberosLogin_NeedsRealm(t *testing.T) {
	kt := keytab.New()
	require.NoError(t, kt.AddEntry("u", "R.TEST", "secret", time.Now(), 1, 18))
	b, err := kt.Marshal()
	require.NoError(t, err)

	c := &Client{}
	want := "ipa: realm is required for Kerberos login"
	require.EqualError(t, c.Login("u", "p"), want)
	require.EqualError(t, c.LoginWithKeytabData(b, "u"), want)
}
