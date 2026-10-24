// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestStageUserAdd_OmitsEmpty(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"result":{"uid":["eve"]},"value":"eve","summary":""}`))
	if _, err := c.StageUserAdd(&ipa.User{Username: "eve", First: "Eve", Last: "E"}); err != nil {
		t.Fatal(err)
	}
	opts := f.Calls()[0].Options
	for _, k := range []string{"mail", "homedirectory", "telephonenumber"} {
		if _, ok := opts[k]; ok {
			t.Errorf("option %q sent: %v", k, opts)
		}
	}
	if opts["givenname"] != "Eve" {
		t.Errorf("givenname = %v", opts["givenname"])
	}
}

func TestStageUserAdd_Required(t *testing.T) {
	_, c := newFake(t)
	_, err := c.StageUserAdd(&ipa.User{Username: "eve", Last: "E"})
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeRequirement {
		t.Fatalf("err = %v, want *IpaError %d", err, ipa.CodeRequirement)
	}
}

func TestStageUserDelete_NoNames(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if err := c.StageUserDelete(); err == nil {
		t.Error("nil error")
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestStageUserShow_EmptyName(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.StageUserShow(""); err == nil {
		t.Error("nil error")
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestStageUserFind_DoesNotModifyOptions(t *testing.T) {
	_, c := newFake(t)
	opts := ipa.Options{"uid": "x"}
	if _, err := c.StageUserFind(opts); err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
}
