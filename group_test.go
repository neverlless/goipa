// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestGroupShow(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	s.AddUser("u2", ipatest.User{})
	s.AddGroup("g", ipatest.Group{Description: "d", GID: "5000", Members: []string{"u1"}, MemberGroups: []string{"g2"}, ManagerUsers: []string{"m"}})
	s.AddGroup("g2", ipatest.Group{Members: []string{"u2"}})
	s.AddGroup("p", ipatest.Group{MemberGroups: []string{"g"}})
	g, err := c.GroupShow("g")
	if err != nil {
		t.Fatal(err)
	}
	want := &ipa.Group{Name: "g", Description: "d", GID: "5000", Users: []string{"u1"}, Groups: []string{"g2"},
		IndirectUsers: []string{"u2"}, MemberOf: []string{"p"}, ManagerUsers: []string{"m"}}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("got %+v, want %+v", g, want)
	}
}

func TestGroupShow_NotFound(t *testing.T) {
	_, c := newFake(t)
	_, err := c.GroupShow("nope")
	if !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("err is %T, want bare *IpaError", err)
	}
}

func TestGroupShow_EmptyName(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.GroupShow(""); err == nil {
		t.Fatal("nil error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestGroupFind(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	s.AddGroup("a", ipatest.Group{Members: []string{"u1"}})
	s.AddGroup("b", ipatest.Group{})
	gs, err := c.GroupFind(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 2 || gs[0].Name != "a" || !reflect.DeepEqual(gs[0].Users, []string{"u1"}) {
		t.Errorf("got %+v", gs)
	}
	calls := s.Calls()
	o := calls[len(calls)-1].Options
	if o["all"] != true || o["no_members"] != false {
		t.Errorf("options = %v", o)
	}
}

func TestGroupFind_DoesNotModifyOptions(t *testing.T) {
	_, c := newFake(t)
	opts := ipa.Options{"cn": "g"}
	if _, err := c.GroupFind(opts); err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
}

func TestGroupShowContext_Canceled(t *testing.T) {
	_, c := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GroupShowContext(ctx, "g"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestGroupAdd(t *testing.T) {
	s, c := newFake(t)
	g, err := c.GroupAdd(&ipa.Group{Name: "g", Description: "d", GID: "7000"})
	if err != nil {
		t.Fatal(err)
	}
	calls := s.Calls()
	if got := calls[len(calls)-1].Options["gidnumber"]; got != "7000" {
		t.Errorf("gidnumber option = %v", got)
	}
	if g.GID != "7000" || g.NonPOSIX {
		t.Errorf("got %+v", g)
	}
	if _, ok := s.Group("g"); !ok {
		t.Error("group not created")
	}
}

func lastOpts(s *ipatest.Server) map[string]any {
	calls := s.Calls()
	return calls[len(calls)-1].Options
}

func TestGroupAdd_ZeroIsPOSIX(t *testing.T) {
	s, c := newFake(t)
	g, err := c.GroupAdd(&ipa.Group{Name: "g"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lastOpts(s)["nonposix"]; ok {
		t.Error("nonposix sent")
	}
	if g.NonPOSIX || g.GID == "" {
		t.Errorf("got %+v", g)
	}
}

func TestGroupAdd_NonPOSIX(t *testing.T) {
	s, c := newFake(t)
	g, err := c.GroupAdd(&ipa.Group{Name: "g", NonPOSIX: true})
	if err != nil {
		t.Fatal(err)
	}
	if lastOpts(s)["nonposix"] != true {
		t.Errorf("options = %v", lastOpts(s))
	}
	if !g.NonPOSIX || g.GID != "" {
		t.Errorf("got %+v", g)
	}
}

func TestGroupAdd_External(t *testing.T) {
	s, c := newFake(t)
	g, err := c.GroupAdd(&ipa.Group{Name: "g", External: true})
	if err != nil {
		t.Fatal(err)
	}
	o := lastOpts(s)
	if _, ok := o["nonposix"]; o["external"] != true || ok {
		t.Errorf("options = %v", o)
	}
	if !g.External || !g.NonPOSIX {
		t.Errorf("got %+v", g)
	}
}

func TestGroupAdd_Duplicate(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g", ipatest.Group{})
	if _, err := c.GroupAdd(&ipa.Group{Name: "g"}); !errors.Is(err, ipa.ErrDuplicateEntry) {
		t.Errorf("err = %v", err)
	}
}

func TestGroupAdd_NoName(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.GroupAdd(&ipa.Group{}); err == nil || len(s.Calls()) != 0 {
		t.Errorf("err = %v, calls = %d", err, len(s.Calls()))
	}
}

func TestGroupMod(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g", ipatest.Group{Description: "old"})
	g, err := c.GroupMod(&ipa.Group{Name: "g", Description: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Description != "new" {
		t.Errorf("got %+v", g)
	}
}

func TestGroupMod_NoChange(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g", ipatest.Group{Description: "same", GID: "5000"})
	in := &ipa.Group{Name: "g", Description: "same", GID: "5000"}
	g, err := c.GroupMod(in)
	if err != nil || g != in {
		t.Errorf("g = %p (in %p), err = %v", g, in, err)
	}
}

func TestGroupDelete(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("a", ipatest.Group{})
	s.AddGroup("b", ipatest.Group{})
	if err := c.GroupDelete("a", "b"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Group("a"); ok {
		t.Error("a still exists")
	}
	if _, ok := s.Group("b"); ok {
		t.Error("b still exists")
	}
	calls := s.Calls()
	if got := calls[len(calls)-1]; got.Method != "group_del" || !reflect.DeepEqual(got.Args, []string{"a", "b"}) {
		t.Errorf("call = %+v", got)
	}
}

func TestGroupDelete_NotFound(t *testing.T) {
	_, c := newFake(t)
	if err := c.GroupDelete("nope"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestGroupDelete_NoNames(t *testing.T) {
	s, c := newFake(t)
	if err := c.GroupDelete(); err == nil || len(s.Calls()) != 0 {
		t.Errorf("err = %v, calls = %d", err, len(s.Calls()))
	}
}
