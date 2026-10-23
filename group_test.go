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
