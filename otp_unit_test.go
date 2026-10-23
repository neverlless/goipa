// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
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
