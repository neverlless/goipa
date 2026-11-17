// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tidwall/gjson"

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

// TestService_AuthIndVersion checks what 4.11 added: the passkey commands
// and the passkey auth indicator.
func TestService_AuthIndVersion(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	s.SetVersion("4.9.13")
	c := s.ClientAs("admin")
	_, err := c.RPC("user_add_passkey", []string{"bob", "passkey:Z29pcGEtdGVzdC1pZA==," + spki}, nil)
	if got := ipaCode(t, err); got != ipa.CodeCommand {
		t.Errorf("user_add_passkey on 4.9.13: code %d", got)
	}
	_, err = c.RPC("service_add", []string{"HTTP/ipa.test.local"}, ipa.Options{"krbprincipalauthind": []string{"passkey"}})
	if got := ipaCode(t, err); got != ipa.CodeValidation {
		t.Errorf("passkey indicator on 4.9.13: code %d", got)
	}
	s.SetVersion("4.12.2")
	if _, err := c.RPC("service_add", []string{"HTTP/ipa.test.local"}, ipa.Options{"krbprincipalauthind": []string{"passkey"}}); err != nil {
		t.Errorf("passkey indicator on 4.12.2: %v", err)
	}
	if v, ok := s.Service("HTTP/ipa.test.local"); !ok || len(v.AuthIndicators) != 1 || v.AuthIndicators[0] != "passkey" {
		t.Errorf("Service = %+v, %v", v, ok)
	}
}

const ownMapping = "passkey:Z29pcGEtdGVzdC1pZA==," + spki

// TestOwnPasskey_NeedsClass pins Q195.
func TestOwnPasskey_NeedsClass(t *testing.T) {
	for _, v := range []string{"4.12.2", "4.13.4"} {
		s := ipatest.NewServer(t)
		s.SetVersion(v)
		s.AddUser("bob", ipatest.User{})
		err := s.ClientAs("bob").UserAddPasskey("bob", ownMapping)
		if v == "4.12.2" {
			if err != nil {
				t.Errorf("%s: %v", v, err)
			}
			continue
		}
		if !errors.Is(err, ipa.ErrACI) || !strings.Contains(err.Error(), "not allowed to perform this operation") {
			t.Fatalf("%s: err = %v", v, err)
		}
		if err := s.ClientAs("admin").UserAddObjectClass("bob", "ipapasskeyuser"); err != nil {
			t.Fatal(err)
		}
		if err := s.ClientAs("bob").UserAddPasskey("bob", ownMapping); err != nil {
			t.Errorf("%s after class: %v", v, err)
		}
	}
}

// TestAdminPasskey_AddsClass pins Q195.
func TestAdminPasskey_AddsClass(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")
	if err := c.UserAddPasskey("bob", ownMapping); err != nil {
		t.Fatal(err)
	}
	res := rpc(t, c, "user_show", []string{"bob"}, ipa.Options{"all": true})
	if !strings.Contains(string(res.Result.Data), `"ipapasskeyuser"`) {
		t.Errorf("objectclass: %s", res.Result.Data)
	}
}

// TestUserShow_ObjectClassWithAll pins Q196 and Q197.
func TestUserShow_ObjectClassWithAll(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")
	oc := func(all bool) string {
		o := ipa.Options{}
		if all {
			o["all"] = true
		}
		return gjson.GetBytes(rpc(t, c, "user_show", []string{"bob"}, o).Result.Data, "objectclass").Raw
	}
	if got := oc(false); got != "" {
		t.Errorf("without all: %s", got)
	}
	if got := oc(true); !strings.Contains(got, `"posixaccount"`) || strings.Contains(got, "ipapasskeyuser") {
		t.Errorf("with all: %s", got)
	}
	if err := c.UserAddObjectClass("bob", "IPAPasskeyUser"); err != nil {
		t.Fatal(err)
	}
	if err := c.UserAddObjectClass("bob", "ipapasskeyuser"); err != nil { // Q198
		t.Errorf("again: %v", err)
	}
	if got := oc(true); strings.Count(strings.ToLower(got), "ipapasskeyuser") != 1 {
		t.Errorf("after add: %s", got)
	}
	rpc(t, c, "user_mod", []string{"bob"}, ipa.Options{"delattr": "objectclass=IPAPASSKEYUSER"})
	if got := oc(true); strings.Contains(got, "ipapasskeyuser") {
		t.Errorf("after del: %s", got)
	}
}
