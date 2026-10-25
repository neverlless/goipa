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

func wantIpaCode(t *testing.T, what string, err error, code int) {
	t.Helper()
	var ierr *ipa.IpaError
	if !errors.As(err, &ierr) || ierr.Code != code {
		t.Errorf("%s: err = %v, want code %d", what, err, code)
	}
}

func TestAutomember_RuleLifecycle(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("devs", ipatest.Group{})
	s.AddHostGroup("Web", ipatest.HostGroup{})
	c := s.ClientAs("admin")

	_, err := c.AutomemberAdd(ipa.AutomemberGroup, "nogroup", "")
	if err == nil || err.Error() != `ipa: error 4001 - group "nogroup" not found` {
		t.Errorf("add without target: %v", err)
	}
	r, err := c.AutomemberAdd(ipa.AutomemberGroup, "devs", "developers")
	if err != nil || r.Name != "devs" || r.Description != "developers" {
		t.Fatalf("add = %+v, %v", r, err)
	}
	_, err = c.AutomemberAdd(ipa.AutomemberGroup, "devs", "")
	wantIpaCode(t, "duplicate add", err, ipa.CodeDuplicateEntry)
	if r, err := c.AutomemberAdd(ipa.AutomemberHostGroup, "WEB", ""); err != nil || r.Name != "web" {
		t.Errorf("host group add = %+v, %v", r, err) // named after the lower-cased group (Q51)
	}

	r, err = c.AutomemberAddCondition(ipa.AutomemberGroup, "devs", "mail", []string{"@dev\\.example$"}, []string{"^root@"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Inclusive, []ipa.AutomemberCondition{{Key: "mail", Regex: "@dev\\.example$"}}) ||
		!slices.Equal(r.Exclusive, []ipa.AutomemberCondition{{Key: "mail", Regex: "^root@"}}) {
		t.Errorf("conditions = %+v / %+v", r.Inclusive, r.Exclusive)
	}

	got, err := c.AutomemberShow(ipa.AutomemberGroup, "devs")
	if err != nil || len(got.Inclusive) != 1 || got.Description != "developers" {
		t.Errorf("show = %+v, %v", got, err)
	}
	_, err = c.AutomemberShow(ipa.AutomemberGroup, "none")
	wantIpaCode(t, "show missing", err, ipa.CodeNotFound)

	res := rpc(t, c, "automember_show", []string{"devs"}, ipa.Options{"type": "group", "all": true})
	e := gjson.ParseBytes(res.Result.Data)
	if e.Get("dn").String() != "cn=devs,cn=group,cn=automember,cn=etc,dc=test,dc=local" || e.Get("objectclass.1").String() != "automemberregexrule" {
		t.Errorf("show all = %s", res.Result.Data)
	}
	if got := e.Get("automembertargetgroup.0").String(); got != "cn=devs,cn=groups,cn=accounts,dc=test,dc=local" {
		t.Errorf("target = %s", got)
	}

	list, err := c.AutomemberFind(ipa.AutomemberGroup, nil)
	if err != nil || len(list) != 1 || list[0].Name != "devs" {
		t.Errorf("find = %+v, %v", list, err)
	}
	if list, _ := c.AutomemberFind(ipa.AutomemberGroup, ipa.Options{"description": "other"}); len(list) != 0 {
		t.Errorf("find by description = %+v", list)
	}
	res = rpc(t, c, "automember_find", []string{"DEVEL"}, ipa.Options{"type": "group"})
	if gjson.ParseBytes(res.Result.Raw).Get("summary").String() != "1 rules matched" {
		t.Errorf("find by needle = %s", res.Result.Raw)
	}
	res = rpc(t, c, "automember_find", []string{"zzz"}, ipa.Options{"type": "group"})
	if gjson.ParseBytes(res.Result.Raw).Get("count").Int() != 0 {
		t.Errorf("find no match = %s", res.Result.Raw)
	}

	if err := c.AutomemberDelete(ipa.AutomemberGroup, "devs", "missing"); err == nil {
		t.Error("delete with a missing rule succeeded")
	}
	if _, err := c.AutomemberShow(ipa.AutomemberGroup, "devs"); err == nil {
		t.Error("rule before the missing one survived (Q114)")
	}
	if err := c.AutomemberDelete(ipa.AutomemberHostGroup, "Web"); err != nil {
		t.Error(err)
	}
}

func TestAutomember_TypeOption(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	for _, m := range []string{"automember_show", "automember_find", "automember_add", "automember_del",
		"automember_add_condition", "automember_default_group_show", "automember_default_group_set",
		"automember_default_group_remove"} {
		_, err := c.RPC(m, []string{"x"}, nil)
		wantIpaCode(t, m+" without type", err, ipa.CodeRequirement)
		_, err = c.RPC(m, []string{"x"}, ipa.Options{"type": "user"})
		if err == nil || err.Error() != "ipa: error 3009 - invalid 'type': must be one of 'group', 'hostgroup'" {
			t.Errorf("%s bad type: %v", m, err)
		}
	}
	for _, m := range []string{"automember_show", "automember_add"} {
		_, err := c.RPC(m, nil, ipa.Options{"type": "group"})
		wantIpaCode(t, m+" without cn", err, ipa.CodeRequirement)
	}
}

func TestAutomember_Conditions(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("devs", ipatest.Group{})
	c := s.ClientAs("admin")
	_, err := c.RPC("automember_add_condition", []string{"devs"}, ipa.Options{"type": "group", "key": "uid"})
	if err == nil || err.Error() != "ipa: error 4001 - Auto member rule: devs not found!" {
		t.Errorf("no rule: %v", err)
	}
	rpc(t, c, "automember_add", []string{"devs"}, ipa.Options{"type": "group"})
	_, err = c.RPC("automember_add_condition", []string{"devs"}, ipa.Options{"type": "group"})
	wantIpaCode(t, "no key", err, ipa.CodeRequirement)

	opts := ipa.Options{"type": "group", "key": "uid", "automemberinclusiveregex": []string{"^dev"}}
	res := gjson.ParseBytes(rpc(t, c, "automember_add_condition", []string{"devs"}, opts).Result.Raw)
	if res.Get("completed").Int() != 1 || res.Get("result.cn.0").String() != "devs" || res.Get("summary").String() != `Added condition(s) to "devs"` {
		t.Errorf("add = %s", res.Raw)
	}
	// Adding it again completes nothing; the result is only the touched attribute (Q111).
	res = gjson.ParseBytes(rpc(t, c, "automember_add_condition", []string{"devs"}, opts).Result.Raw)
	if res.Get("completed").Int() != 0 || res.Get("result.cn").Exists() || res.Get("result.automemberinclusiveregex").Raw != `["uid=^dev"]` {
		t.Errorf("re-add = %s", res.Raw)
	}

	opts["automemberinclusiveregex"] = []string{"^dev", "^nope"}
	res = gjson.ParseBytes(rpc(t, c, "automember_remove_condition", []string{"devs"}, opts).Result.Raw)
	if res.Get("completed").Int() != 1 || res.Get("failed.failed.automemberinclusiveregex").Raw != `["uid=^nope"]` ||
		res.Get("summary").String() != `Removed condition(s) from "devs"` {
		t.Errorf("remove = %s", res.Raw)
	}
	r, err := c.AutomemberShow(ipa.AutomemberGroup, "devs")
	if err != nil || len(r.Inclusive) != 0 {
		t.Errorf("after remove = %+v, %v", r, err)
	}
	if _, err := c.AutomemberRemoveCondition(ipa.AutomemberGroup, "devs", "uid", []string{"^x"}, nil); err == nil {
		t.Error("removing an absent condition reported no failure")
	}
}

func TestAutomember_DefaultGroup(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("everyone", ipatest.Group{})
	c := s.ClientAs("admin")
	if g, err := c.AutomemberDefaultGroup(ipa.AutomemberGroup); err != nil || g != "" {
		t.Errorf("default before set = %q, %v", g, err)
	}
	wantIpaCode(t, "remove unset", c.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup), ipa.CodeNotFound)
	_, err := c.RPC("automember_default_group_set", nil, ipa.Options{"type": "group"})
	wantIpaCode(t, "set without group", err, ipa.CodeRequirement)
	wantIpaCode(t, "set missing group", c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "nope"), ipa.CodeNotFound)
	if err := c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "everyone"); err != nil {
		t.Fatal(err)
	}
	wantIpaCode(t, "set same group", c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "everyone"), ipa.CodeEmptyModlist)
	if g, err := c.AutomemberDefaultGroup(ipa.AutomemberGroup); err != nil || g != "everyone" {
		t.Errorf("default = %q, %v", g, err)
	}
	res := gjson.ParseBytes(rpc(t, c, "automember_default_group_show", nil, ipa.Options{"type": "group"}).Result.Data)
	if res.Get("dn").String() != "cn=Group,cn=automember,cn=etc,dc=test,dc=local" {
		t.Errorf("show = %s", res.Raw)
	}
	if err := c.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.AutomemberDefaultGroup(ipa.AutomemberGroup); g != "" {
		t.Errorf("default after remove = %q", g)
	}
}

func TestAutomember_AppliesToNewAndRebuiltUsers(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("devs", ipatest.Group{})
	s.AddGroup("everyone", ipatest.Group{})
	s.AddUser("devold", ipatest.User{Email: "devold@dev.example"})
	c := s.ClientAs("admin")
	rpc(t, c, "automember_add", []string{"devs"}, ipa.Options{"type": "group"})
	rpc(t, c, "automember_add_condition", []string{"devs"}, ipa.Options{"type": "group", "key": "mail",
		"automemberinclusiveregex": []string{"@dev\\.example$", "("}, "automemberexclusiveregex": []string{"^root@"}})
	rpc(t, c, "automember_add_condition", []string{"devs"}, ipa.Options{"type": "group", "key": "uid",
		"automemberexclusiveregex": []string{"^bot"}})
	if err := c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "everyone"); err != nil {
		t.Fatal(err)
	}

	for uid, mail := range map[string]string{"ann": "ann@dev.example", "root": "root@dev.example", "bot1": "bot1@dev.example", "zed": "zed@else.example"} {
		rpc(t, c, "user_add", []string{uid}, ipa.Options{"givenname": "A", "sn": "B", "mail": mail})
	}
	if g, _ := s.Group("devs"); !slices.Equal(g.Members, []string{"ann"}) {
		t.Errorf("devs = %v", g.Members)
	}
	if g, _ := s.Group("everyone"); len(g.Members) != 3 {
		t.Errorf("everyone = %v", g.Members) // root, bot1 and zed fall back to the default group
	}

	if err := c.AutomemberRebuild(ipa.AutomemberHostGroup); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Group("devs"); slices.Contains(g.Members, "devold") {
		t.Error("host group rebuild touched user groups")
	}
	res := gjson.ParseBytes(rpc(t, c, "automember_rebuild", nil, ipa.Options{"type": "group"}).Result.Raw)
	if res.Get("summary").String() != "Automember rebuild task finished. Processed (5) entries in 0 seconds" {
		t.Errorf("rebuild = %s", res.Raw)
	}
	if g, _ := s.Group("devs"); !slices.Equal(g.Members, []string{"ann", "devold"}) {
		t.Errorf("devs after rebuild = %v", g.Members)
	}
}
