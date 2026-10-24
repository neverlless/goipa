//go:build integration

// Copyright 2018 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"fmt"
	"os"
	"os/user"
	"testing"

	_ "github.com/joho/godotenv/autoload"
	"github.com/neverlless/goipa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	TestEnvAdminUser  = getenv("IPA_ADMIN_USER", "admin")
	TestEnvAdminPass  = getenv("IPA_ADMIN_PASS", "")
	TestEnvKeytabFile = getenv("IPA_KEYTAB", "")
	TestEnvKeytabUser = getenv("IPA_KEYTAB_USER", "")
)

func getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func newTestClientUserPassword() (*ipa.Client, error) {
	c := ipa.NewDefaultClient()

	err := c.Login(TestEnvAdminUser, TestEnvAdminPass)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func newTestClientKeytab() (*ipa.Client, error) {
	c := ipa.NewDefaultClient()

	err := c.LoginWithKeytab(TestEnvKeytabFile, TestEnvKeytabUser)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func newTestClientCCache() (*ipa.Client, error) {
	c := ipa.NewDefaultClient()
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	err = c.LoginFromCCache(fmt.Sprintf("/tmp/krb5cc_%s", user.Uid))
	if err != nil {
		return nil, err
	}

	return c, nil
}

func TestLoginWithPassword(t *testing.T) {
	if TestEnvAdminUser == "" || TestEnvAdminPass == "" {
		t.Skip("Admin user/pass not set. Skipping")
	}

	_, err := newTestClientUserPassword()
	assert.NoError(t, err)
}

func TestLoginWithKeytab(t *testing.T) {
	if TestEnvKeytabFile == "" || TestEnvKeytabUser == "" {
		t.Skip("Admin user/keytab not set. Skipping")
	}

	_, err := newTestClientKeytab()
	assert.NoError(t, err)
}

func TestLoginWithCCache(t *testing.T) {
	user, err := user.Current()
	require.NoError(t, err)
	require.FileExistsf(t, fmt.Sprintf("/tmp/krb5cc_%s", user.Uid), "Missing KRB5CCACHE file")

	_, err = newTestClientCCache()
	assert.NoError(t, err)
}

func TestRemoteLogin(t *testing.T) {
	if TestEnvAdminUser == "" || TestEnvAdminPass == "" {
		t.Skip("Admin user/pass not set. Skipping")
	}

	c := ipa.NewDefaultClient()
	err := c.RemoteLogin(TestEnvAdminUser, TestEnvAdminPass)
	require.NoError(t, err)
	assert.NotEmptyf(t, c.SessionID(), "Missing sessionID")
}

func TestPing(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	res, err := c.Ping()
	require.NoError(err)

	assert.Containsf(res.Principal, c.Realm(), "Realm not found in principal")
	assert.NotEmptyf(c.SessionID(), "Missing sessionID")
}

func TestLoginWithKeytabData(t *testing.T) {
	if TestEnvKeytabFile == "" || TestEnvKeytabUser == "" {
		t.Skip("Admin user/keytab not set. Skipping")
	}
	b, err := os.ReadFile(TestEnvKeytabFile)
	require.NoError(t, err)

	c := ipa.NewDefaultClient()
	require.NoError(t, c.LoginWithKeytabData(b, TestEnvKeytabUser))
	who, err := c.WhoAmI()
	require.NoError(t, err)
	assert.Equal(t, []string{TestEnvKeytabUser}, who.Arguments)
}

func TestLoginFromCCacheData(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err)
	b, err := os.ReadFile(fmt.Sprintf("/tmp/krb5cc_%s", u.Uid))
	require.NoError(t, err)

	c := ipa.NewDefaultClient()
	require.NoError(t, c.LoginFromCCacheData(b))
	_, err = c.WhoAmI()
	assert.NoError(t, err)
}

func TestWithKrb5ConfigData(t *testing.T) {
	if TestEnvKeytabFile == "" || TestEnvKeytabUser == "" {
		t.Skip("Admin user/keytab not set. Skipping")
	}
	conf, err := os.ReadFile(ipa.DefaultKerbConf)
	require.NoError(t, err)
	c, err := ipa.New(ipa.WithKrb5ConfigData(conf))
	require.NoError(t, err)
	assert.NoError(t, c.LoginWithKeytab(TestEnvKeytabFile, TestEnvKeytabUser))
}
