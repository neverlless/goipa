// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"reflect"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestAddOTPTokenNumericOptions(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	tok, err := s.ClientAs("bob").AddOTPToken(&ipa.OTPToken{Digits: 8, TimeStep: 60, Algorithm: ipa.AlgorithmSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Digits != 8 || tok.TimeStep != 60 || tok.Algorithm != "sha256" || tok.Owner != "bob" || tok.URI == "" {
		t.Errorf("token = %+v", tok)
	}
}

func TestOTPTokenSeedAndInspect(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	seed := s.AddOTPToken(ipatest.OTPToken{Owner: "bob"})
	if len(seed.UUID) != 36 || seed.Type != "totp" || seed.Algorithm != "sha1" || seed.Digits != 6 || seed.TimeStep != 30 {
		t.Errorf("seed = %+v", seed)
	}
	if got := s.OTPTokens("bob"); len(got) != 1 || len(s.OTPTokens("")) != 1 || len(s.OTPTokens("eve")) != 0 {
		t.Errorf("OTPTokens = %+v", got)
	}
	toks, err := s.ClientAs("admin").FetchOTPTokens("bob")
	if err != nil || len(toks) != 1 || !toks[0].Enabled || toks[0].URI != "" {
		t.Errorf("FetchOTPTokens = %+v, %v", toks, err)
	}
}

func TestOTPNotBeforeRecorded(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	// +02:00 must reach the wire as UTC.
	nb := time.Date(2026, 1, 2, 5, 4, 5, 0, time.FixedZone("x", 2*3600))
	if _, err := s.ClientAs("bob").AddOTPToken(&ipa.OTPToken{NotBefore: nb}); err != nil {
		t.Fatal(err)
	}
	var got any
	for _, c := range s.Calls() {
		if c.Method == "otptoken_add" {
			got = c.Options["ipatokennotbefore"]
		}
	}
	if want := map[string]any{"__datetime__": "20260102030405Z"}; !reflect.DeepEqual(got, want) {
		t.Errorf("option = %v, want %v", got, want)
	}
	if got := s.OTPTokens("bob")[0].NotBefore; !got.Equal(nb) || got.Location() != time.UTC {
		t.Errorf("NotBefore = %v", got)
	}
}

func TestOTPBadDatetime(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("otptoken_add", nil, ipa.Options{"ipatokennotbefore": map[string]any{"__datetime__": "2026-01-02"}})
	if got := ipaCode(t, err); got != ipa.CodeValidation {
		t.Errorf("code = %d", got)
	}
}

func TestOTPModDelFind(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	s.AddUser("eve", ipatest.User{})
	a := s.AddOTPToken(ipatest.OTPToken{Owner: "bob"})
	s.AddOTPToken(ipatest.OTPToken{Owner: "eve"})
	c := s.ClientAs("admin")

	if err := c.DisableOTPToken(a.UUID); err != nil {
		t.Fatal(err)
	}
	toks, _ := c.FetchOTPTokens("bob")
	if len(toks) != 1 || toks[0].Enabled {
		t.Errorf("after disable: %+v", toks)
	}
	if err := c.EnableOTPToken(a.UUID); err != nil {
		t.Fatal(err)
	}
	if s.OTPTokens("bob")[0].Disabled {
		t.Error("still disabled")
	}
	if err := c.RemoveOTPToken(a.UUID); err != nil {
		t.Fatal(err)
	}
	if len(s.OTPTokens("")) != 1 {
		t.Errorf("tokens = %+v", s.OTPTokens(""))
	}
	for _, err := range []error{c.RemoveOTPToken(a.UUID), c.DisableOTPToken("nope")} {
		if got := ipaCode(t, err); got != ipa.CodeNotFound {
			t.Errorf("code = %d", got)
		}
	}
	if _, err := c.RPC("otptoken_mod", nil, nil); ipaCode(t, err) != ipa.CodeRequirement {
		t.Error("missing key accepted")
	}
}

func TestOTPLastTokenGuard(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{AuthTypes: []string{"otp"}})
	s.AddUser("amy", ipatest.User{AuthTypes: []string{"password", "otp"}})
	a := s.AddOTPToken(ipatest.OTPToken{Owner: "bob"})
	only := s.AddOTPToken(ipatest.OTPToken{Owner: "amy"})
	c := s.ClientAs("admin")

	if got := ipaCode(t, c.DisableOTPToken(a.UUID)); got != ipa.CodeDatabase {
		t.Errorf("disable code = %d", got)
	}
	if got := ipaCode(t, c.RemoveOTPToken(a.UUID)); got != ipa.CodeDatabase {
		t.Errorf("delete code = %d", got)
	}
	// Only AuthTypes == ["otp"] is guarded.
	if err := c.RemoveOTPToken(only.UUID); err != nil {
		t.Errorf("amy: %v", err)
	}
	// A second enabled token lifts the guard.
	b := s.AddOTPToken(ipatest.OTPToken{Owner: "bob"})
	if err := c.RemoveOTPToken(a.UUID); err != nil {
		t.Errorf("with spare: %v", err)
	}
	if got := ipaCode(t, c.RemoveOTPToken(b.UUID)); got != ipa.CodeDatabase {
		t.Errorf("last code = %d", got)
	}
}

func TestOTPNumbersAsStringsAndBadNumber(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	_, err := c.RPC("otptoken_add", nil, ipa.Options{"ipatokenotpdigits": "8", "ipatokentotptimestep": "45", "ipatokenowner": "zed"})
	if err != nil {
		t.Fatal(err)
	}
	if tk := s.OTPTokens("zed"); len(tk) != 1 || tk[0].Digits != 8 || tk[0].TimeStep != 45 {
		t.Errorf("tokens = %+v", tk)
	}
	_, err = c.RPC("otptoken_add", nil, ipa.Options{"ipatokenotpdigits": "x"})
	if got := ipaCode(t, err); got != ipa.CodeValidation {
		t.Errorf("code = %d", got)
	}
}
