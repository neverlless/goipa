// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"encoding/json"
	"testing"
)

func TestUserAddPasskey_Args(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if err := c.UserAddPasskey("bob", "passkey:a,b"); err != nil {
		t.Fatal(err)
	}
	if err := c.UserRemovePasskey("bob", "passkey:a,b"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 || calls[0].Method != "user_add_passkey" || calls[1].Method != "user_remove_passkey" {
		t.Fatalf("calls = %+v", calls)
	}
	for _, call := range calls {
		var args []string
		if err := json.Unmarshal(call.Args, &args); err != nil || len(args) != 2 || args[0] != "bob" || args[1] != "passkey:a,b" {
			t.Errorf("%s args = %s", call.Method, call.Args)
		}
	}
}

func TestUserAddPasskey_Empty(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	for _, a := range [][2]string{{"", "m"}, {"bob", ""}} {
		if err := c.UserAddPasskey(a[0], a[1]); err == nil {
			t.Errorf("add %q: nil error", a)
		}
		if err := c.UserRemovePasskey(a[0], a[1]); err == nil {
			t.Errorf("remove %q: nil error", a)
		}
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestUserAddObjectClass_SendsAddattr(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if err := c.UserAddObjectClass("bob", "ipapasskeyuser"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Method != "user_mod" {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Args) != `["bob"]` || calls[0].Options["addattr"] != "objectclass=ipapasskeyuser" {
		t.Errorf("args %s options %v", calls[0].Args, calls[0].Options)
	}
}

func TestUserAddObjectClass_AlreadyPresentIsNil(t *testing.T) {
	c, _ := newFakeIPA(t, 200, errorBody(4202, "EmptyModlist", "no modifications to be performed"))
	if err := c.UserAddObjectClass("bob", "ipapasskeyuser"); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestUserAddObjectClass_RequiresArgs(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if err := c.UserAddObjectClass("", "x"); err == nil || err.Error() != "ipa: username is required" {
		t.Errorf("err = %v", err)
	}
	if err := c.UserAddObjectClass("bob", ""); err == nil || err.Error() != "ipa: object class is required" {
		t.Errorf("err = %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}
