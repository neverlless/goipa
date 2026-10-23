// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func rpc(t *testing.T, c *ipa.Client, method string, args []string, opts ipa.Options) *ipa.Response {
	t.Helper()
	res, err := c.RPC(method, args, opts)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return res
}

func strList(r gjson.Result) []string {
	var out []string
	for _, v := range r.Array() {
		out = append(out, v.String())
	}
	return out
}

func memberServer(t *testing.T) *ipatest.Server {
	s := ipatest.NewServer(t)
	s.AddUser("u1", ipatest.User{})
	s.AddUser("bob", ipatest.User{})
	s.AddGroup("g", ipatest.Group{})
	return s
}

func TestGroupAddMember_FailedIsSiblingOfResult(t *testing.T) {
	s := memberServer(t)
	res := rpc(t, s.ClientAs("admin"), "group_add_member", []string{"g"}, ipa.Options{"user": []string{"u1", "ghost"}})
	r := res.Result
	if r.Completed != 1 {
		t.Errorf("Completed = %d", r.Completed)
	}
	if got := gjson.GetBytes(r.Failed, "member.user.0").Raw; got != `["ghost","no such entry"]` {
		t.Errorf("failed = %s", got)
	}
	if got := gjson.GetBytes(r.Data, "member_user").Raw; got != `["u1"]` {
		t.Errorf("member_user = %s", got)
	}
	if gjson.GetBytes(r.Data, "failed").Exists() {
		t.Error("result has a failed key")
	}
	if got := gjson.GetBytes(r.Failed, "member.group").Raw; got != `[]` {
		t.Errorf("failed group = %s", got)
	}
	if !gjson.GetBytes(r.Failed, "member.service").Exists() || !gjson.GetBytes(r.Failed, "member.idoverrideuser").Exists() {
		t.Errorf("member failed lacks service/idoverrideuser: %s", r.Failed)
	}
}

func TestGroupAddMember_AlreadyMember(t *testing.T) {
	s := memberServer(t)
	s.AddGroup("g", ipatest.Group{Members: []string{"u1"}})
	res := rpc(t, s.ClientAs("admin"), "group_add_member", []string{"g"}, ipa.Options{"user": []string{"u1"}})
	if got := gjson.GetBytes(res.Result.Failed, "member.user.0.1").String(); got != "This entry is already a member" {
		t.Errorf("message = %q", got)
	}
	if res.Result.Completed != 0 {
		t.Errorf("Completed = %d", res.Result.Completed)
	}
}

func TestGroupAddMember_DeniedGoesToFailed(t *testing.T) {
	s := memberServer(t)
	res := rpc(t, s.ClientAs("bob"), "group_add_member", []string{"g"}, ipa.Options{"user": []string{"u1"}, "group": []string{"g"}})
	if res.Result.Completed != 0 {
		t.Errorf("Completed = %d", res.Result.Completed)
	}
	for _, k := range []string{"member.user.0.1", "member.group.0.1"} {
		if got := gjson.GetBytes(res.Result.Failed, k).String(); !strings.HasPrefix(got, "Insufficient access") {
			t.Errorf("%s = %q", k, got)
		}
	}
	if g, _ := s.Group("g"); len(g.Members) != 0 || len(g.MemberGroups) != 0 {
		t.Errorf("denied call changed the group: %+v", g)
	}
}

func TestGroupAddMember_ManagerAllowed(t *testing.T) {
	s := memberServer(t)
	s.AddGroup("g", ipatest.Group{ManagerUsers: []string{"bob"}})
	res := rpc(t, s.ClientAs("bob"), "group_add_member", []string{"g"}, ipa.Options{"user": []string{"u1"}})
	if res.Result.Completed != 1 {
		t.Errorf("Completed = %d, failed %s", res.Result.Completed, res.Result.Failed)
	}
}

func TestGroupAddMember_ManagerGroupAndAdminsAllowed(t *testing.T) {
	s := memberServer(t)
	s.AddGroup("mgrs", ipatest.Group{Members: []string{"bob"}})
	s.AddGroup("g", ipatest.Group{ManagerGroups: []string{"mgrs"}})
	if res := rpc(t, s.ClientAs("bob"), "group_add_member", []string{"g"}, ipa.Options{"user": []string{"u1"}}); res.Result.Completed != 1 {
		t.Errorf("manager group member: Completed = %d", res.Result.Completed)
	}
	s.AddGroup("admins", ipatest.Group{Members: []string{"u1"}})
	if res := rpc(t, s.ClientAs("u1"), "group_add_member", []string{"g"}, ipa.Options{"group": []string{"mgrs"}}); res.Result.Completed != 1 {
		t.Errorf("admins member: Completed = %d", res.Result.Completed)
	}
}

func TestGroupRemoveMember(t *testing.T) {
	s := memberServer(t)
	s.AddUser("u2", ipatest.User{Groups: []string{"g"}})
	s.AddGroup("g", ipatest.Group{Members: []string{"u1"}, MemberGroups: []string{"g"}})
	c := s.ClientAs("admin")
	res := rpc(t, c, "group_remove_member", []string{"g"}, ipa.Options{"user": []string{"u1", "u2", "bob", "ghost"}, "group": []string{"g"}})
	if res.Result.Completed != 3 {
		t.Errorf("Completed = %d", res.Result.Completed)
	}
	if got := gjson.GetBytes(res.Result.Failed, "member.user").Raw; got != `[["bob","This entry is not a member"],["ghost","no such entry"]]` {
		t.Errorf("failed users = %s", got)
	}
	if u, _ := s.User("u2"); len(u.Groups) != 0 {
		t.Errorf("u2.Groups = %v", u.Groups)
	}
	if g, _ := s.Group("g"); len(g.Members) != 0 || len(g.MemberGroups) != 0 {
		t.Errorf("group = %+v", g)
	}
}

func TestGroupAddMemberManager_FailedKey(t *testing.T) {
	s := memberServer(t)
	res := rpc(t, s.ClientAs("admin"), "group_add_member_manager", []string{"g"}, ipa.Options{"user": []string{"bob", "ghost"}})
	f := gjson.ParseBytes(res.Result.Failed)
	if f.Get("member").Exists() || !f.Get("membermanager").Exists() || f.Get("membermanager.service").Exists() {
		t.Errorf("failed = %s", res.Result.Failed)
	}
	if res.Result.Completed != 1 {
		t.Errorf("Completed = %d", res.Result.Completed)
	}
	if got := gjson.GetBytes(res.Result.Data, "membermanager_user").Raw; got != `["bob"]` {
		t.Errorf("membermanager_user = %s", got)
	}
	// A group manager may change members but not managers.
	res = rpc(t, s.ClientAs("bob"), "group_add_member_manager", []string{"g"}, ipa.Options{"user": []string{"u1"}})
	if res.Result.Completed != 0 || !strings.HasPrefix(gjson.GetBytes(res.Result.Failed, "membermanager.user.0.1").String(), "Insufficient access") {
		t.Errorf("manager changed managers: %s", res.Result.Failed)
	}
	res = rpc(t, s.ClientAs("admin"), "group_remove_member_manager", []string{"g"}, ipa.Options{"user": []string{"bob"}})
	if res.Result.Completed != 1 {
		t.Errorf("remove manager: Completed = %d", res.Result.Completed)
	}
}

func TestGroupMember_MissingGroup(t *testing.T) {
	s := memberServer(t)
	_, err := s.ClientAs("admin").RPC("group_add_member", []string{"nope"}, ipa.Options{"user": []string{"u1"}})
	if !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestGroupFind_HidesMembersByDefault(t *testing.T) {
	s := memberServer(t)
	s.AddGroup("g", ipatest.Group{Members: []string{"u1"}})
	c := s.ClientAs("admin")
	for _, tc := range []struct {
		opts ipa.Options
		want bool
	}{{nil, false}, {ipa.Options{"no_members": false}, true}, {ipa.Options{"all": true}, true}} {
		res := rpc(t, c, "group_find", nil, tc.opts)
		var recs []map[string]any
		if err := json.Unmarshal(res.Result.Data, &recs); err != nil {
			t.Fatal(err)
		}
		_, has := recs[0]["member_user"]
		if has != tc.want {
			t.Errorf("opts %v: member_user present = %v", tc.opts, has)
		}
	}
	res := rpc(t, c, "group_find", []string{"G"}, ipa.Options{"cn": "g"})
	if res.Result.Count != 1 {
		t.Errorf("Count = %d", res.Result.Count)
	}
}

func TestGroupShow_NotFound(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("group_show", []string{"nope"}, nil)
	if !errors.Is(err, ipa.ErrNotFound) || !strings.Contains(err.Error(), "nope: group not found") {
		t.Errorf("err = %v", err)
	}
}

func TestGroupShow_Shape(t *testing.T) {
	s := memberServer(t)
	s.AddGroup("g1", ipatest.Group{Description: "d", MemberGroups: []string{"g2"}, Members: []string{"u1"}})
	s.AddGroup("g2", ipatest.Group{Members: []string{"bob"}})
	s.AddGroup("g0", ipatest.Group{MemberGroups: []string{"g1"}})
	c := s.ClientAs("admin")

	d := rpc(t, c, "group_show", []string{"g1"}, nil).Result.Data
	for k, want := range map[string]string{
		"cn": `["g1"]`, "description": `["d"]`, "member_user": `["u1"]`, "member_group": `["g2"]`,
		"memberindirect_user": `["bob"]`, "memberof_group": `["g0"]`,
	} {
		if got := gjson.GetBytes(d, k).Raw; got != want {
			t.Errorf("%s = %s, want %s", k, got, want)
		}
	}
	for _, k := range []string{"memberindirect_group", "membermanager_user", "objectclass", "dn", "ipauniqueid"} {
		if gjson.GetBytes(d, k).Exists() {
			t.Errorf("%s present without all", k)
		}
	}
	if gid := gjson.GetBytes(d, "gidnumber.0").String(); gid == "" {
		t.Error("no gidnumber")
	}
	if gjson.GetBytes(rpc(t, c, "group_show", []string{"g1"}, ipa.Options{"no_members": true}).Result.Data, "member_user").Exists() {
		t.Error("no_members ignored")
	}

	d = rpc(t, c, "group_show", []string{"g0"}, ipa.Options{"all": true, "no_members": true}).Result.Data
	if got := gjson.GetBytes(d, "memberindirect_group").Raw; got != `["g2"]` {
		t.Errorf("memberindirect_group = %s", got)
	}
	if got := strList(gjson.GetBytes(d, "objectclass")); !slices.Contains(got, "posixgroup") || !gjson.GetBytes(d, "dn").Exists() || !gjson.GetBytes(d, "ipauniqueid").Exists() {
		t.Errorf("all: %s", d)
	}
}

func TestGroupObjectClasses(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("posix", ipatest.Group{})
	s.AddGroup("plain", ipatest.Group{NonPOSIX: true})
	s.AddGroup("ext", ipatest.Group{External: true})
	c := s.ClientAs("admin")
	for cn, tc := range map[string]struct{ posix, ext bool }{"posix": {true, false}, "plain": {false, false}, "ext": {false, true}} {
		d := rpc(t, c, "group_show", []string{cn}, ipa.Options{"all": true}).Result.Data
		oc := strList(gjson.GetBytes(d, "objectclass"))
		if slices.Contains(oc, "posixgroup") != tc.posix || slices.Contains(oc, "ipaexternalgroup") != tc.ext || gjson.GetBytes(d, "gidnumber").Exists() != tc.posix {
			t.Errorf("%s: objectclass %v, result %s", cn, oc, d)
		}
	}
}

func TestGroupAddModDel(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	a := rpc(t, c, "group_add", []string{"a"}, ipa.Options{"description": "x"})
	b := rpc(t, c, "group_add", []string{"b"}, nil)
	if gjson.GetBytes(a.Result.Data, "gidnumber.0").String() != "1000000" || gjson.GetBytes(b.Result.Data, "gidnumber.0").String() != "1000001" {
		t.Errorf("gids: %s %s", a.Result.Data, b.Result.Data)
	}
	rpc(t, c, "group_add", []string{"n"}, ipa.Options{"nonposix": true, "external": true, "gidnumber": 77})
	rpc(t, c, "group_add", []string{"p"}, ipa.Options{"gidnumber": 4242})
	if g, _ := s.Group("n"); !g.External || g.NonPOSIX || g.GID != "" {
		t.Errorf("n = %+v", g)
	}
	if g, _ := s.Group("p"); g.GID != "4242" {
		t.Errorf("p = %+v", g)
	}

	_, err := c.RPC("group_add", []string{"a"}, nil)
	if !errors.Is(err, ipa.ErrDuplicateEntry) || !strings.Contains(err.Error(), `group with name "a" already exists`) {
		t.Errorf("duplicate err = %v", err)
	}

	rpc(t, c, "group_mod", []string{"a"}, ipa.Options{"description": "y", "gidnumber": "5"})
	if g, _ := s.Group("a"); g.Description != "y" || g.GID != "5" {
		t.Errorf("a = %+v", g)
	}
	if _, err := c.RPC("group_mod", []string{"a"}, ipa.Options{"description": "y"}); !errors.Is(err, ipa.ErrEmptyModlist) {
		t.Errorf("mod err = %v", err)
	}
	if _, err := c.RPC("group_mod", []string{"zz"}, ipa.Options{"description": "y"}); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("mod missing err = %v", err)
	}
}

func TestGroupDel_Shape(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("u", ipatest.User{Groups: []string{"g"}})
	s.AddGroup("g", ipatest.Group{})
	s.AddGroup("parent", ipatest.Group{MemberGroups: []string{"g"}, ManagerGroups: []string{"g"}})
	c := s.ClientAs("admin")
	if _, err := c.RPC("group_del", []string{"g", "nope"}, nil); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	res := rpc(t, c, "group_del", []string{"g"}, nil)
	if got := gjson.GetBytes(res.Result.Raw, "value").Raw; got != `["g"]` {
		t.Errorf("value = %s", got)
	}
	if got := gjson.GetBytes(res.Result.Data, "failed").Raw; got != `[]` {
		t.Errorf("failed = %s", got)
	}
	if res.Result.Summary != `Deleted group "g"` {
		t.Errorf("summary = %q", res.Result.Summary)
	}
	if _, ok := s.Group("g"); ok {
		t.Error("g still exists")
	}
	if p, _ := s.Group("parent"); len(p.MemberGroups) != 0 || len(p.ManagerGroups) != 0 {
		t.Errorf("parent = %+v", p)
	}
	if u, _ := s.User("u"); len(u.Groups) != 0 {
		t.Errorf("u.Groups = %v", u.Groups)
	}
}

func TestUserShow_IndirectGroups(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("u", ipatest.User{})
	s.AddGroup("g1", ipatest.Group{Members: []string{"u"}})
	s.AddGroup("g2", ipatest.Group{MemberGroups: []string{"g1"}})
	d := rpc(t, s.ClientAs("admin"), "user_show", []string{"u"}, nil).Result.Data
	if gjson.GetBytes(d, "memberof_group").Raw != `["g1"]` || gjson.GetBytes(d, "memberofindirect_group").Raw != `["g2"]` {
		t.Errorf("user_show = %s", d)
	}
}

func TestUserFind_NestedGroupsFlattened(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("u", ipatest.User{Groups: []string{"g1"}})
	s.AddGroup("g1", ipatest.Group{})
	s.AddGroup("g2", ipatest.Group{MemberGroups: []string{"g1"}})
	c := s.ClientAs("admin")
	res := rpc(t, c, "user_find", nil, ipa.Options{"all": true})
	rec := gjson.GetBytes(res.Result.Data, "0")
	got := strList(rec.Get("memberof_group"))
	if !slices.Contains(got, "g1") || !slices.Contains(got, "g2") || rec.Get("memberofindirect_group").Exists() {
		t.Errorf("user_find all = %s", rec.Raw)
	}
	rec = gjson.GetBytes(rpc(t, c, "user_find", nil, nil).Result.Data, "0")
	if rec.Get("memberof_group").Raw != `["g1"]` {
		t.Errorf("user_find = %s", rec.Raw)
	}
}

func TestGroupAccessorsReturnCopies(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("g", ipatest.Group{Members: []string{"a"}})
	g, _ := s.Group("g")
	g.Members[0] = "z"
	if again, _ := s.Group("g"); again.Members[0] != "a" {
		t.Errorf("Members = %v", again.Members)
	}
	if _, ok := s.Group("nope"); ok {
		t.Error("Group(nope) ok")
	}
}
