// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestNew_WithHTTPClient(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("alice", ipatest.User{Password: "pw"})
	c, err := ipa.New(ipa.WithHost(s.Host()), ipa.WithRealm(s.Realm()), ipa.WithHTTPClient(s.HTTPClient()))
	require.NoError(t, err)
	require.NoError(t, c.RemoteLogin("alice", "pw"))
	u, err := c.UserShow("alice")
	require.NoError(t, err)
	require.Equal(t, "alice", u.Username)
}

func TestNew_WithCACert(t *testing.T) {
	s := ipatest.NewServer(t)
	c, err := ipa.New(ipa.WithHost(s.Host()), ipa.WithCACert(s.CACert()))
	require.NoError(t, err)
	c.SetSessionID(s.Session("admin"))
	_, err = c.Ping()
	require.NoError(t, err)
}

func TestNew_Sticky(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("alice", ipatest.User{Password: "pw"})
	c, err := ipa.New(ipa.WithHost(s.Host()), ipa.WithHTTPClient(s.HTTPClient()))
	require.NoError(t, err)
	require.NoError(t, c.RemoteLogin("alice", "pw"))
	require.NotEmpty(t, c.SessionID())
	_, err = c.Ping()
	require.NoError(t, err)
}

func TestNew_Errors(t *testing.T) {
	s := ipatest.NewServer(t)
	tests := []struct {
		name string
		opts []ipa.Option
		want string
	}{
		{"bad ca", []ipa.Option{ipa.WithHost("h"), ipa.WithCACert([]byte("x"))}, "ipa: no certificate in CA PEM"},
		{"ca and http", []ipa.Option{ipa.WithHost("h"), ipa.WithCACert(s.CACert()), ipa.WithHTTPClient(s.HTTPClient())}, "ipa: WithCACert and WithHTTPClient are mutually exclusive"},
		{"nil ca", []ipa.Option{ipa.WithCACert(nil), ipa.WithHTTPClient(s.HTTPClient())}, "ipa: WithCACert needs a value"},
		{"nil http client", []ipa.Option{ipa.WithHTTPClient(nil)}, "ipa: WithHTTPClient needs a value"},
		{"empty host", []ipa.Option{ipa.WithHost("")}, "ipa: WithHost needs a value"},
		{"empty krb5 path", []ipa.Option{ipa.WithKrb5Config("")}, "ipa: WithKrb5Config needs a value"},
		{"nil krb5 data", []ipa.Option{ipa.WithKrb5ConfigData(nil)}, "ipa: WithKrb5ConfigData needs a value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ipa.New(tt.opts...)
			require.EqualError(t, err, tt.want)
		})
	}
}
