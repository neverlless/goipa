// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func ruleServer(t *testing.T) (*ipatest.Server, *ipa.Client) {
	s := ipatest.NewServer(t)
	s.AddUser("alice", ipatest.User{})
	s.AddHBACRule("h1", ipatest.HBACRule{Description: "web access", Users: []string{"alice"}})
	s.AddHBACRule("h2", ipatest.HBACRule{Description: "db", Disabled: true})
	s.AddSudoRule("s1", ipatest.SudoRule{Description: "web admins", Users: []string{"alice"}})
	s.AddSudoRule("s2", ipatest.SudoRule{Description: "db", Disabled: true})
	return s, s.ClientAs("admin")
}

func cns(r *ipa.Response) []string {
	var out []string
	for _, e := range gjson.ParseBytes(r.Result.Data).Array() {
		out = append(out, e.Get("cn.0").String())
	}
	return out
}

func TestRuleFindMembersVisibility(t *testing.T) {
	_, c := ruleServer(t)
	for _, m := range []string{"hbacrule_find", "sudorule_find"} {
		for name, tc := range map[string]struct {
			opts ipa.Options
			want bool
		}{
			"none":       {ipa.Options{"cn": m[:1] + "1"}, false},
			"no_members": {ipa.Options{"cn": m[:1] + "1", "no_members": false}, true},
			"all":        {ipa.Options{"cn": m[:1] + "1", "all": true}, true},
		} {
			res := rpc(t, c, m, []string{""}, tc.opts)
			got := gjson.ParseBytes(res.Result.Data).Get("0.memberuser_user").Exists()
			if got != tc.want {
				t.Errorf("%s %s: memberuser_user present = %v", m, name, got)
			}
		}
	}
	// add and add_user renders follow the same rule
	rpc(t, c, "hbacrule_add", []string{"h3"}, nil)
	rpc(t, c, "sudorule_add", []string{"s3"}, nil)
	for _, m := range []string{"hbacrule", "sudorule"} {
		cn := m[:1] + "3"
		res := rpc(t, c, m+"_add_user", []string{cn}, ipa.Options{"user": []string{"alice"}})
		if !gjson.GetBytes(res.Result.Data, "memberuser_user").Exists() {
			t.Errorf("%s_add_user hides members", m)
		}
	}
	res := rpc(t, c, "hbacrule_add", []string{"h4"}, ipa.Options{"all": true})
	if gjson.GetBytes(res.Result.Data, "memberuser_user").Exists() || !gjson.GetBytes(res.Result.Data, "dn").Exists() {
		t.Errorf("hbacrule_add render: %s", res.Result.Data)
	}
}

func TestRuleFindFilters(t *testing.T) {
	_, c := ruleServer(t)
	for _, m := range []string{"hbacrule_find", "sudorule_find"} {
		p := m[:1]
		for name, tc := range map[string]struct {
			args []string
			opts ipa.Options
			want []string
		}{
			"needle cn":          {[]string{p + "2"}, nil, []string{p + "2"}},
			"needle description": {[]string{"WEB"}, nil, []string{p + "1"}},
			"description option": {[]string{""}, ipa.Options{"description": "db"}, []string{p + "2"}},
			"disabled":           {[]string{""}, ipa.Options{"ipaenabledflag": false}, []string{p + "2"}},
			"enabled string":     {[]string{""}, ipa.Options{"ipaenabledflag": "TRUE", "cn": p + "1"}, []string{p + "1"}},
		} {
			if got := cns(rpc(t, c, m, tc.args, tc.opts)); !slices.Equal(got, tc.want) {
				t.Errorf("%s %s: got %v, want %v", m, name, got, tc.want)
			}
		}
		// enabled filter must not return the disabled rule
		if got := cns(rpc(t, c, m, []string{""}, ipa.Options{"ipaenabledflag": true})); slices.Contains(got, p+"2") {
			t.Errorf("%s: enabled filter returned disabled rule: %v", m, got)
		}
	}
}

func TestRuleAddUserFailures(t *testing.T) {
	s, c := ruleServer(t)
	s.AddGroup("devs", ipatest.Group{})
	for _, m := range []string{"hbacrule_add_user"} { // sudo: TestSudoMember_External
		cn := m[:1] + "1" // alice is already a member
		res := rpc(t, c, m, []string{cn}, ipa.Options{
			"user": []string{"alice", "ghost"}, "group": []string{"devs", "nogroup"},
		})
		r := gjson.ParseBytes(res.Result.Raw)
		if got := r.Get("completed").Int(); got != 1 { // only devs
			t.Errorf("%s: completed = %d", m, got)
		}
		f := r.Get("failed.memberuser")
		if u := f.Get("user.#").Int(); u != 2 {
			t.Errorf("%s: failed users = %s", m, f.Get("user").Raw)
		}
		if f.Get("user.0.1").String() != "This entry is already a member" || f.Get("user.1.1").String() != "no such entry" {
			t.Errorf("%s: failed users = %s", m, f.Get("user").Raw)
		}
		if f.Get("group.#").Int() != 1 || f.Get("group.0.0").String() != "nogroup" || f.Get("group.0.1").String() != "no such entry" {
			t.Errorf("%s: failed groups = %s", m, f.Get("group").Raw)
		}
	}
}

func TestUserDel_LeavesRules(t *testing.T) {
	_, c := ruleServer(t)
	rpc(t, c, "user_del", []string{"alice"}, nil)
	h, err := c.HBACRuleFind(ipa.Options{"cn": "h1"})
	if err != nil || len(h) != 1 || len(h[0].Users) != 0 {
		t.Errorf("hbac h1 = %+v, %v", h, err)
	}
	r, err := c.SudoRuleFind(ipa.Options{"cn": "s1"})
	if err != nil || len(r) != 1 || len(r[0].Users) != 0 {
		t.Errorf("sudo s1 = %+v, %v", r, err)
	}
}

func TestGroupDel_LeavesRulesAndPolicy(t *testing.T) {
	s, c := ruleServer(t)
	s.AddGroup("ops", ipatest.Group{})
	s.AddHBACRule("h3", ipatest.HBACRule{Groups: []string{"ops"}})
	s.AddSudoRule("s3", ipatest.SudoRule{Groups: []string{"ops"}})
	s.SetPwPolicy("ops", ipatest.PwPolicy{Priority: 1})
	rpc(t, c, "group_del", []string{"ops"}, nil)
	h, err := c.HBACRuleFind(ipa.Options{"cn": "h3"})
	if err != nil || len(h) != 1 || len(h[0].Groups) != 0 {
		t.Errorf("hbac h3 = %+v, %v", h, err)
	}
	r, err := c.SudoRuleFind(ipa.Options{"cn": "s3"})
	if err != nil || len(r) != 1 || len(r[0].Groups) != 0 {
		t.Errorf("sudo s3 = %+v, %v", r, err)
	}
	s.AddGroup("ops", ipatest.Group{})
	if _, err := c.PwPolicyShow("ops"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("policy of a deleted group survived: %v", err)
	}
}
