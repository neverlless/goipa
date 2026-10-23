// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
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

func memberSetup(t *testing.T) (*ipatest.Server, *ipa.Client) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	s.AddUser("bob", ipatest.User{})
	s.AddGroup("g", ipatest.Group{})
	s.AddGroup("g2", ipatest.Group{})
	return s, c
}

func TestGroupAddMember(t *testing.T) {
	_, c := memberSetup(t)
	g, err := c.GroupAddMember("g", []string{"u1"}, []string{"g2"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Users, []string{"u1"}) || !reflect.DeepEqual(g.Groups, []string{"g2"}) {
		t.Errorf("got %+v", g)
	}
}

func TestGroupAddMember_PartialFailure(t *testing.T) {
	_, c := memberSetup(t)
	g, err := c.GroupAddMember("g", []string{"u1", "ghost"}, nil)
	var me *ipa.MemberError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v", err)
	}
	want := []ipa.MemberFailure{{Kind: "member", Type: "user", Name: "ghost", Message: "no such entry"}}
	if !reflect.DeepEqual(me.Failures, want) {
		t.Errorf("failures = %+v", me.Failures)
	}
	if g == nil || !reflect.DeepEqual(g.Users, []string{"u1"}) {
		t.Errorf("group = %+v", g)
	}
}

func TestGroupAddMember_NotManagerIsMemberError(t *testing.T) {
	s, _ := memberSetup(t)
	_, err := s.ClientAs("bob").GroupAddMember("g", []string{"u1"}, nil)
	var me *ipa.MemberError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(me.Failures[0].Message, "Insufficient access") {
		t.Errorf("message = %q", me.Failures[0].Message)
	}
	if errors.Is(err, ipa.ErrACI) {
		t.Error("err is ErrACI")
	}
}

func TestGroupAddMember_GroupNotFound(t *testing.T) {
	_, c := memberSetup(t)
	g, err := c.GroupAddMember("nope", []string{"u1"}, nil)
	if g != nil || !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("g = %v, err = %v", g, err)
	}
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("err is %T", err)
	}
}

func TestGroupAddMember_NoMembers(t *testing.T) {
	s, c := memberSetup(t)
	if _, err := c.GroupAddMember("g", nil, nil); err == nil || len(s.Calls()) != 0 {
		t.Errorf("err = %v, calls = %d", err, len(s.Calls()))
	}
}

func TestGroupRemoveMember_NotMember(t *testing.T) {
	_, c := memberSetup(t)
	_, err := c.GroupRemoveMember("g", []string{"u1"}, nil)
	var me *ipa.MemberError
	if !errors.As(err, &me) || me.Failures[0].Message != "This entry is not a member" {
		t.Fatalf("err = %v", err)
	}
}

func TestGroupAddMemberManager(t *testing.T) {
	s, c := memberSetup(t)
	g, err := c.GroupAddMemberManager("g", []string{"bob"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.ManagerUsers, []string{"bob"}) {
		t.Errorf("got %+v", g)
	}
	if _, err := s.ClientAs("bob").GroupAddMember("g", []string{"u1"}, nil); err != nil {
		t.Errorf("manager add: %v", err)
	}
}

func TestGroupRemoveMemberManager_Kind(t *testing.T) {
	_, c := memberSetup(t)
	_, err := c.GroupRemoveMemberManager("g", []string{"bob"}, nil)
	var me *ipa.MemberError
	if !errors.As(err, &me) || me.Failures[0].Kind != "membermanager" {
		t.Fatalf("err = %v", err)
	}
}

func TestMemberError_Error(t *testing.T) {
	one := &ipa.MemberError{Failures: []ipa.MemberFailure{{Kind: "member", Type: "user", Name: "bob", Message: "This entry is already a member"}}}
	if got, want := one.Error(), "ipa: 1 member failure: user bob: This entry is already a member"; got != want {
		t.Errorf("got %q", got)
	}
	two := &ipa.MemberError{Failures: append(one.Failures, ipa.MemberFailure{Kind: "member", Type: "group", Name: "g2", Message: "no such entry"})}
	if got, want := two.Error(), "ipa: 2 member failures: user bob: This entry is already a member; group g2: no such entry"; got != want {
		t.Errorf("got %q", got)
	}
}

func TestParseMemberFailures_NullAndEmpty(t *testing.T) {
	_, c := memberSetup(t)
	// ipatest answers {"member":{"user":[],"group":[],...}}: empty lists must not fail the call.
	if _, err := c.GroupAddMember("g", []string{"u1"}, nil); err != nil {
		t.Fatal(err)
	}
	s := ipatest.NewServer(t)
	s.Handle("group_add_member", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"cn": []string{"g"}}, "completed": 1, "failed": nil}, nil
	})
	if _, err := s.ClientAs("admin").GroupAddMember("g", []string{"u1"}, nil); err != nil {
		t.Errorf("null failed: %v", err)
	}
}
