// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestSubIDGenerate_SelfOmitsOwner(t *testing.T) {
	s, _ := newFake(t)
	s.AddUser("u1", ipatest.User{})
	sub, err := s.ClientAs("u1").SubIDGenerate("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Calls()[0].Options["ipaowner"]; ok {
		t.Errorf("ipaowner sent: %v", s.Calls()[0].Options)
	}
	if sub.Owner != "u1" || sub.UIDCount != 65536 || sub.UIDStart != 2147483648 || sub.GIDStart != sub.UIDStart || sub.ID == "" {
		t.Errorf("sub = %+v", sub)
	}
}

func TestSubIDGenerate_Disabled(t *testing.T) {
	s, c := newFake(t)
	s.Handle("subid_generate", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: ipa.CodeValidation, Message: "Support for subordinate IDs is disabled"}
	})
	_, err := c.SubIDGenerate("u1")
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeValidation || ie != err {
		t.Fatalf("err = %v (%T), want bare *IpaError %d", err, err, ipa.CodeValidation)
	}
}

func TestSubIDFind_DoesNotModifyOptions(t *testing.T) {
	_, c := newFake(t)
	opts := ipa.Options{"ipaowner": "x"}
	if _, err := c.SubIDFind(opts); err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
}

func TestSubID_FindAndUserDelete(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("a", ipatest.User{})
	s.AddUser("b", ipatest.User{})
	for _, u := range []string{"a", "b"} {
		if _, err := c.SubIDGenerate(u); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := s.SubID("a")
	b, _ := s.SubID("b")
	if b.UIDStart != a.UIDStart+65536 {
		t.Errorf("ranges %d, %d", a.UIDStart, b.UIDStart)
	}
	if all, err := c.SubIDFind(nil); err != nil || len(all) != 2 {
		t.Fatalf("find all = %v, %v", all, err)
	}
	if got, err := c.SubIDFind(ipa.Options{"ipauniqueid": b.ID}); err != nil || len(got) != 1 || got[0].Owner != "b" || got[0].UIDStart != b.UIDStart {
		t.Fatalf("find by id = %+v, %v", got, err)
	}
	if err := c.UserDelete(true, false, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.SubID("a"); !ok {
		t.Error("preserve dropped the sub-ID")
	}
	if err := c.UserDelete(false, false, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.SubIDFind(nil); len(got) != 0 {
		t.Errorf("left after delete: %+v", got)
	}
}

func TestSubIDGenerate_Errors(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.SubIDGenerate("ghost"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("unknown owner = %v", err)
	}
	s.AddUser("a", ipatest.User{})
	if _, err := c.SubIDGenerate("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubIDGenerate("a"); !errors.Is(err, ipa.ErrDuplicateEntry) {
		t.Errorf("second generate = %v", err)
	}
}
