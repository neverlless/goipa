// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func methodSent(s *ipatest.Server, method string) bool {
	for _, c := range s.Calls() {
		if c.Method == method {
			return true
		}
	}
	return false
}

func TestServerVersion(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	if v := c.ServerVersion(); v != "" {
		t.Fatalf("before first call = %q", v)
	}
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if v := c.ServerVersion(); v != "4.13.4" {
		t.Errorf("version = %q", v)
	}
	s.SetVersion("4.10.1")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if v := c.ServerVersion(); v != "4.10.1" {
		t.Errorf("version = %q", v)
	}
}

func TestServerVersion_KeptOnErrorAndEmpty(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	s.SetVersion("4.10.1")
	if _, err := c.UserShow("ghost"); !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if v := c.ServerVersion(); v != "4.13.4" {
		t.Errorf("after an error envelope = %q", v)
	}
	s.SetVersion("")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if v := c.ServerVersion(); v != "4.13.4" {
		t.Errorf("after an empty version = %q", v)
	}
}

func TestGate_Passkey(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetVersion("4.10.1")
	c := s.ClientAs("admin")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{c.UserAddPasskey("bob", testPasskey), c.UserRemovePasskey("bob", testPasskey)} {
		if !errors.Is(err, ipa.ErrNotSupported) {
			t.Fatalf("err = %v", err)
		}
	}
	if err := c.UserAddPasskey("bob", testPasskey); !strings.Contains(err.Error(), "user_add_passkey needs FreeIPA 4.11") {
		t.Errorf("message = %v", err)
	}
	if methodSent(s, "user_add_passkey") || methodSent(s, "user_remove_passkey") {
		t.Error("gated call was sent")
	}
}

func TestGate_SubID(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.SetVersion("4.9.6")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubIDGenerate(""); !errors.Is(err, ipa.ErrNotSupported) {
		t.Errorf("generate err = %v", err)
	}
	if _, err := c.SubIDFind(nil); !errors.Is(err, ipa.ErrNotSupported) {
		t.Errorf("find err = %v", err)
	}
	if methodSent(s, "subid_generate") || methodSent(s, "subid_find") {
		t.Error("gated call was sent")
	}
	s.SetVersion("4.9.7")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	_, _ = c.SubIDGenerate("")
	if !methodSent(s, "subid_generate") {
		t.Error("4.9.7 call was not sent")
	}
}

func TestGate_UnknownVersionSends(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetVersion("4.10.1") // would be gated, but this client has not seen it
	_ = s.ClientAs("admin").UserAddPasskey("bob", testPasskey)
	if !methodSent(s, "user_add_passkey") {
		t.Error("call was not sent")
	}
}

func TestGate_UnparsableVersionSends(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetVersion("weird")
	c := s.ClientAs("admin")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	_ = c.UserAddPasskey("bob", testPasskey)
	if !methodSent(s, "user_add_passkey") {
		t.Error("call was not sent")
	}
}
