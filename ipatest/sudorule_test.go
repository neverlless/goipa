// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestSudoMember_External(t *testing.T) {
	s, c := ruleServer(t)
	s.AddGroup("devs", ipatest.Group{})
	res := rpc(t, c, "sudorule_add_user", []string{"s1"}, ipa.Options{
		"user": []string{"alice", "Ghost"}, "group": []string{"devs", "nogroup"},
	})
	r := gjson.ParseBytes(res.Result.Raw)
	if got := r.Get("completed").Int(); got != 3 {
		t.Errorf("completed = %d", got)
	}
	if f := r.Get("failed.memberuser.user").Raw; f != `[["alice","This entry is already a member"]]` {
		t.Errorf("failed users = %s", f)
	}
	if got := r.Get("result.externaluser").Raw; got != `["ghost","nogroup"]` {
		t.Errorf("externaluser = %s", got)
	}
	res = rpc(t, c, "sudorule_remove_user", []string{"s1"}, ipa.Options{"user": []string{"ghost", "nobody"}})
	r = gjson.ParseBytes(res.Result.Raw)
	if r.Get("completed").Int() != 1 || r.Get("failed.memberuser.user.0.1").String() != "no such entry" {
		t.Errorf("remove = %s", res.Result.Raw)
	}
	if got := r.Get("result.externaluser").Raw; got != `["nogroup"]` {
		t.Errorf("externaluser = %s", got)
	}
}

func TestSudoCmd_AddDel(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	rpc(t, c, "sudocmd_add", []string{"/bin/x"}, ipa.Options{"description": "d"})
	if _, err := c.RPC("sudocmd_add", []string{"/bin/x"}, nil); err == nil {
		t.Error("duplicate sudocmd_add succeeded")
	}
	rpc(t, c, "sudocmd_del", []string{"/bin/x"}, nil)
	if _, err := c.RPC("sudocmd_del", []string{"/bin/x"}, nil); err == nil {
		t.Error("sudocmd_del of a missing command succeeded")
	}
}

func TestSudoOption_ListAt49(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetVersion("4.9.13")
	s.AddSudoRule("r", ipatest.SudoRule{})
	c := s.ClientAs("admin")
	_, err := c.RPC("sudorule_add_option", []string{"r"}, ipa.Options{"ipasudoopt": []string{"!authenticate"}})
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeConversion {
		t.Fatalf("list at 4.9: err = %v", err)
	}
	if r, err := c.SudoRuleAddOption("r", "!authenticate"); err != nil || len(r.Options) != 1 {
		t.Fatalf("scalar at 4.9: %+v, %v", r, err)
	}
}
