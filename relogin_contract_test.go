// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"os"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContractSessionLogoutGives401 pins W2 and Q39: after session_logout
// the old session cookie gets HTTP 401.
func TestContractSessionLogoutGives401(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		if _, err := c.RPC("session_logout", nil, nil); err != nil {
			t.Fatal(err)
		}
		_, err := c.Ping()
		wantIs(t, err, ipa.ErrUnauthorized)
	})
}

// TestContractPasswordRelogin pins W3: WithPasswordRelogin renews a session
// ended by session_logout.
func TestContractPasswordRelogin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c, err := ipa.New(ipa.WithHost(b.host), ipa.WithRealm(b.realm), ipa.WithHTTPClient(b.http), ipa.WithPasswordRelogin())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.RemoteLogin(uid, goodPW); err != nil {
			t.Fatal(err)
		}
		old := c.SessionID()
		if _, err := c.RPC("session_logout", nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := c.UserShow(uid); err != nil {
			t.Fatal(err)
		}
		if c.SessionID() == old {
			t.Error("session not renewed")
		}
	})
}

// TestContractKerberosRelogin pins W4: a Kerberos client whose session ended
// gets a new one through SPNEGO. ipatest has no KDC.
func TestContractKerberosRelogin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		if b.name == "ipatest" {
			t.Skip("needs a KDC")
		}
		kt, user := os.Getenv("IPA_KEYTAB"), os.Getenv("IPA_KEYTAB_USER")
		if kt == "" || user == "" {
			t.Skip("IPA_KEYTAB/IPA_KEYTAB_USER not set")
		}
		c := b.client()
		if err := c.LoginWithKeytab(kt, user); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Ping(); err != nil {
			t.Fatal(err)
		}
		old := c.SessionID()
		if old == "" {
			t.Fatal("no session after Ping")
		}
		if _, err := c.RPC("session_logout", nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Ping(); err != nil {
			t.Fatal(err)
		}
		if c.SessionID() == old {
			t.Error("session not renewed")
		}
	})
}
