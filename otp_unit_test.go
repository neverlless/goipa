// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

const otpAddBody = `{"result":{"ipatokenuniqueid":["u"]},"value":"u","summary":"Added OTP token \"u\""}`

func TestAddOTPTokenNilKeepsDefaults(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(otpAddBody))
	before := *ipa.DefaultTOTPToken

	if _, err := c.AddOTPToken(nil); err != nil {
		t.Fatal(err)
	}
	if *ipa.DefaultTOTPToken != before {
		t.Fatalf("DefaultTOTPToken changed: %+v -> %+v", before, *ipa.DefaultTOTPToken)
	}
	o := f.Calls()[0].Options
	if o["type"] != "totp" || o["ipatokenotpalgorithm"] != "sha1" || o["ipatokenotpdigits"] != 6.0 || o["ipatokentotptimestep"] != 30.0 {
		t.Fatalf("options = %v", o)
	}
}

func TestAddOTPTokenDoesNotModifyCaller(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(otpAddBody))
	tok := &ipa.OTPToken{Description: "phone"}

	if _, err := c.AddOTPToken(tok); err != nil {
		t.Fatal(err)
	}
	if tok.Type != "" || tok.Algorithm != "" || tok.Digits != 0 || tok.TimeStep != 0 {
		t.Fatalf("caller token modified: %+v", *tok)
	}
	o := f.Calls()[0].Options
	if o["description"] != "phone" || o["type"] != "totp" {
		t.Fatalf("options = %v", o)
	}
}

func TestAddOTPTokenDatesInUTC(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(otpAddBody))
	loc := time.FixedZone("UTC+3", 3*3600)
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, loc)

	if _, err := c.AddOTPToken(&ipa.OTPToken{NotBefore: at, NotAfter: at}); err != nil {
		t.Fatal(err)
	}
	o := f.Calls()[0].Options
	for _, k := range []string{"ipatokennotbefore", "ipatokennotafter"} {
		m, _ := o[k].(map[string]any)
		if m["__datetime__"] != "20261022090000Z" {
			t.Errorf("%s = %v", k, o[k])
		}
	}
}

func TestAddOTPTokenNilUsesDefaults(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	before := *ipa.DefaultTOTPToken
	tok, err := s.ClientAs("bob").AddOTPToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Type != "totp" || tok.Digits != 6 || tok.TimeStep != 30 || tok.Algorithm != "sha1" {
		t.Errorf("token = %+v", tok)
	}
	if *ipa.DefaultTOTPToken != before {
		t.Error("DefaultTOTPToken changed")
	}
}

func TestOTPTokenFieldsRoundTrip(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	nb := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	na := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	c := s.ClientAs("bob")
	added, err := c.AddOTPToken(&ipa.OTPToken{Description: "phone", Vendor: "V", Model: "M", Serial: "S1", NotBefore: nb, NotAfter: na})
	if err != nil {
		t.Fatal(err)
	}
	toks, err := c.FetchOTPTokens("bob")
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens = %v, %v", toks, err)
	}
	for name, g := range map[string]*ipa.OTPToken{"added": added, "fetched": toks[0]} {
		if g.Description != "phone" || g.Vendor != "V" || g.Model != "M" || g.Serial != "S1" || !g.NotBefore.Equal(nb) || !g.NotAfter.Equal(na) || g.ManagedBy != "bob" || g.Owner != "bob" {
			t.Errorf("%s = %+v", name, g)
		}
	}
}

func TestOTPDisplayName(t *testing.T) {
	uuid := "0b0a5f4c-1111-2222-3333-444455556666"
	if got := (&ipa.OTPToken{Owner: "bob", UUID: uuid}).DisplayName(); got != "bob-556666" {
		t.Errorf("got %q", got)
	}
	if got := (&ipa.OTPToken{Owner: "bob", UUID: "short"}).DisplayName(); got != "short" {
		t.Errorf("got %q", got)
	}
}

// Q7 counts enabled tokens only: a disabled spare does not make the last
// enabled one removable.
func TestLastEnabledOTPTokenGuard(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{AuthTypes: []string{"otp"}})
	last := s.AddOTPToken(ipatest.OTPToken{Owner: "bob"})
	spare := s.AddOTPToken(ipatest.OTPToken{Owner: "bob", Disabled: true})
	c := s.ClientAs("admin")

	for name, err := range map[string]error{"disable": c.DisableOTPToken(last.UUID), "remove": c.RemoveOTPToken(last.UUID)} {
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != ipa.CodeDatabase {
			t.Errorf("%s: err = %v, want 4203", name, err)
		}
	}
	if err := c.RemoveOTPToken(spare.UUID); err != nil {
		t.Errorf("removing the disabled spare: %v", err)
	}
}
