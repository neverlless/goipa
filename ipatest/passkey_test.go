// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

const spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgJ0OGh7RCx0W7lUgaq4bbkS5+r9uuEXFc8lWWhNH0uphy0Xv4/2mTD9h4KbXWYcpr0bxLYvifagCSgDbVZZlcg=="

func TestPasskeyCommands(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")
	m := "passkey:Z29pcGEtdGVzdC1pZA==," + spki

	res := rpc(t, c, "user_add_passkey", []string{"bob", m}, nil)
	if got := string(res.Result.Data); got != `{"ipapasskey":["`+m+`"],"uid":["bob"]}` {
		t.Errorf("result = %s", got)
	}
	if res.Result.Summary != `Added passkey mappings to user "bob"` {
		t.Errorf("summary = %q", res.Result.Summary)
	}
	if u, err := c.UserShow("bob"); err != nil || len(u.Passkeys) != 1 {
		t.Fatalf("show = %+v, %v", u, err)
	}
	_, err := c.RPC("user_add_passkey", []string{"bob", m}, nil)
	if got := ipaCode(t, err); got != ipa.CodeAlreadyContainsValue {
		t.Errorf("duplicate code = %d", got)
	}
	for _, bad := range []string{"x", "passkey:!!,", "passkey:aa,aa", "passkey:aa==,!!"} {
		_, err := c.RPC("user_add_passkey", []string{"bob", bad}, nil)
		if got := ipaCode(t, err); got != ipa.CodeValidation {
			t.Errorf("%q code = %d", bad, got)
		}
	}
	res = rpc(t, c, "user_remove_passkey", []string{"bob", m}, nil)
	if res.Result.Summary != `Removed passkey mappings from user "bob"` {
		t.Errorf("summary = %q", res.Result.Summary)
	}
	_, err = c.RPC("user_remove_passkey", []string{"bob", m}, nil)
	if got := ipaCode(t, err); got != ipa.CodeAttrValueNotFound {
		t.Errorf("absent code = %d", got)
	}
	_, err = c.RPC("user_add_passkey", []string{"nobody", m}, nil)
	if got := ipaCode(t, err); got != ipa.CodeNotFound {
		t.Errorf("missing user code = %d", got)
	}
}
