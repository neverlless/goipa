// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// TestContractHBACTestServiceGroup pins Q150: hbactest expands the default
// service group Sudo to its members.
func TestContractHBACTestServiceGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		r := newHBACRule(t, b, ipa.HBACRule{UserCategory: "all", HostCategory: "all"})
		if _, err := b.admin.HBACRuleAddService(r.Name, nil, []string{"Sudo"}); err != nil {
			t.Fatal(err)
		}
		host := serverHost(t, b)
		for svc, want := range map[string]bool{"sudo": true, "sudo-i": true, "sshd": false} {
			got, err := b.admin.HBACTest("admin", host, svc, r.Name)
			if err != nil || got.Granted != want {
				t.Errorf("%s = %+v, %v; want granted %v", svc, got, err, want)
			}
		}
	})
}

// TestContractHBACTestNestedHostGroup pins Q35's nested host groups: a rule
// naming a parent host group matches a host of its child group.
func TestContractHBACTestNestedHostGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		host := serverHost(t, b)
		parent, child := newHostGroup(t, b), newHostGroup(t, b)
		if _, err := b.admin.HostGroupAddMember(parent, nil, []string{child}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.HostGroupAddMember(child, []string{host}, nil); err != nil {
			t.Fatal(err)
		}
		r := newHBACRule(t, b, ipa.HBACRule{UserCategory: "all", ServiceCategory: "all"})
		if _, err := b.admin.HBACRuleAddHost(r.Name, nil, []string{parent}); err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.HBACTest("admin", host, "sshd", r.Name)
		if err != nil || !got.Granted {
			t.Errorf("hbactest = %+v, %v", got, err)
		}
	})
}

// TestContractSudoOrderUnique pins Q151: a sudoorder another rule holds is
// refused on add and on mod.
func TestContractSudoOrderUnique(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		n, _ := strconv.ParseUint(randHex(t, 2), 16, 32)
		order := 2000 + int(n)
		first := "gs" + randHex(t, 4)
		if _, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: first, Order: order}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.SudoRuleDelete(first) })
		want := fmt.Sprintf("ipa: error 3009 - invalid 'order': order must be a unique value (%d already used by %s)", order, first)

		second := "gs" + randHex(t, 4)
		t.Cleanup(func() { _ = b.admin.SudoRuleDelete(second) })
		_, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: second, Order: order})
		if err == nil || err.Error() != want {
			t.Errorf("add: %v\nwant %s", err, want)
		}
		_, err = b.admin.SudoRuleAdd(&ipa.SudoRule{Name: first, Order: order})
		wantCode(t, "add with the holder's name", err, ipa.CodeDuplicateEntry)
		_, err = b.admin.RPC("sudorule_mod", []string{first}, ipa.Options{"sudoorder": "seven"})
		if want := "ipa: error 3008 - invalid 'order': must be an integer"; err == nil || err.Error() != want {
			t.Errorf("mod to a non-number: %v\nwant %s", err, want)
		}
		if _, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: second, Order: order + 1}); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.RPC("sudorule_mod", []string{second}, ipa.Options{"sudoorder": order})
		if err == nil || err.Error() != want {
			t.Errorf("mod: %v\nwant %s", err, want)
		}
		got, err := b.admin.SudoRuleShow(second)
		if err != nil || got.Order != order+1 {
			t.Errorf("after mod: %+v, %v", got, err)
		}
		if _, err := b.admin.RPC("sudorule_mod", []string{second}, ipa.Options{"sudoorder": order + 2}); err != nil {
			t.Errorf("mod to a free order: %v", err)
		}
		_, err = b.admin.RPC("sudorule_mod", []string{second}, ipa.Options{"sudoorder": order + 2})
		wantCode(t, "mod to its own order", err, 4202)
	})
}

// TestContractSudoRuleCategoryConflict pins Q152, the sudo twin of Q73.
func TestContractSudoRuleCategoryConflict(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cmd := newSudoCmd(t, b)
		uid := newSudoUser(t, b)
		cn := "gs" + randHex(t, 4)
		if _, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: cn, UserCategory: "all", HostCategory: "all", CmdCategory: "all",
			RunAsUserCategory: "all", RunAsGroupCategory: "all"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.SudoRuleDelete(cn) })
		for _, c := range []struct {
			name string
			call func() error
			want string
		}{
			{"user", func() error { _, err := b.admin.SudoRuleAddUser(cn, []string{uid}, nil); return err },
				"users cannot be added when user category='all'"},
			{"host", func() error { _, err := b.admin.SudoRuleAddHost(cn, []string{serverHost(t, b)}, nil); return err },
				"hosts cannot be added when host category='all'"},
			{"allow", func() error { _, err := b.admin.SudoRuleAddAllowCommand(cn, []string{cmd}, nil); return err },
				"commands cannot be added when command category='all'"},
			{"deny", func() error { _, err := b.admin.SudoRuleAddDenyCommand(cn, []string{cmd}, nil); return err }, ""},
			{"runasuser", func() error { _, err := b.admin.SudoRuleAddRunAsUser(cn, []string{uid}, nil); return err },
				"users cannot be added when runAs user or runAs group category='all'"},
			{"runasgroup", func() error { _, err := b.admin.SudoRuleAddRunAsGroup(cn, []string{"admins"}); return err },
				"users cannot be added when runAs user or runAs group category='all'"},
		} {
			err := c.call()
			if c.want == "" {
				if err != nil {
					t.Errorf("%s: %v, want success", c.name, err)
				}
				continue
			}
			if want := "ipa: error 4303 - " + c.want; err == nil || err.Error() != want {
				t.Errorf("%s: %v\nwant %s", c.name, err, want)
			}
		}
	})
}

// TestContractRBACFindCNExact pins Q153: the cn option matches the whole
// name in any case; the criteria match a substring.
func TestContractRBACFindCNExact(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		for cn, want := range map[string]int{builtinRole: 1, strings.ToLower(builtinRole): 1, builtinRole[:8]: 0} {
			roles, err := b.admin.RoleFind(ipa.Options{"cn": cn})
			if err != nil || len(roles) != want {
				t.Errorf("cn %q: %d roles, %v; want %d", cn, len(roles), err, want)
			}
		}
		res := mustRPC(t, b.admin, "role_find", []string{"user administrat"}, nil)
		if res.Result.Count < 1 {
			t.Errorf("criteria: %d roles", res.Result.Count)
		}
	})
}

// TestContractAutomemberStageActivate pins Q112 for stage users: activation
// runs the automember rules, stageuser_add does not.
func TestContractAutomemberStageActivate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newRule(t, b)
		title := "goipa-" + randHex(t, 4)
		if _, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "title", []string{"^" + title + "$"}, nil); err != nil {
			t.Fatal(err)
		}
		uid := newStageUID(t, b)
		mustRPC(t, b.admin, "stageuser_add", []string{uid}, ipa.Options{"givenname": "Go", "sn": "Test", "title": title})
		if inGroup(t, b, uid, cn) {
			t.Error("stage user already in the group")
		}
		if _, err := b.admin.StageUserActivate(uid); err != nil {
			t.Fatal(err)
		}
		if !inGroup(t, b, uid, cn) {
			t.Error("activated user not in the group")
		}
	})
}

// TestContractOTPDeleteAsUser pins Q154: a plain user deleting a token that
// does not exist, or another user's, gets 2100.
func TestContractOTPDeleteAsUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ownerUID := newUserWithPassword(t, b, goodPW)
		owner := mustLogin(t, b, ownerUID, goodPW)
		tok, err := owner.AddOTPToken(nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.RemoveOTPToken(tok.UUID) })
		c := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		if err := c.RemoveOTPToken("goipa-missing-" + randHex(t, 4)); err == nil || err.Error() != "ipa: error 2100 - Insufficient access: " {
			t.Errorf("missing: %v", err)
		}
		want := "ipa: error 2100 - Insufficient access: Insufficient 'delete' privilege to delete the entry 'ipatokenuniqueid=" + tok.UUID + ",cn=otp,"
		if err := c.RemoveOTPToken(tok.UUID); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("foreign: %v", err)
		}
		if toks, err := owner.FetchOTPTokens(ownerUID); err != nil || len(toks) != 1 {
			t.Errorf("owner's tokens: %d, %v", len(toks), err)
		}
	})
}

// sessionPost sends user_show uid with session cookie sid ("" for none),
// bypassing the client.
func sessionPost(t *testing.T, b backend, sid, uid string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest("POST", "https://"+b.host+"/ipa/session/json",
		strings.NewReader(`{"method":"user_show","params":[["`+uid+`"],{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://"+b.host+"/ipa")
	if sid != "" {
		req.Header.Set("Cookie", "ipa_session="+sid)
	}
	res, err := b.http.Do(req)
	if err != nil {
		t.Fatalf("session/json: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return res.StatusCode, res.Header, string(body)
}

// TestContractStaleSessionCookie pins Q155: session_logout only tells the
// client to drop its cookie; the old cookie still works.
func TestContractStaleSessionCookie(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)
		old := c.SessionID()
		if _, err := c.RPC("session_logout", nil, nil); err != nil {
			t.Fatal(err)
		}
		if c.SessionID() != "" {
			t.Errorf("client kept %q", c.SessionID())
		}
		code, h, body := sessionPost(t, b, old, uid)
		if code != http.StatusOK || gjson.Get(body, "error").Type != gjson.Null || !strings.HasPrefix(gjson.Get(body, "principal").String(), uid+"@") {
			t.Errorf("old cookie: HTTP %d, headers %v, body %q", code, h, body)
		}
		stale := b.client()
		stale.SetSessionID(old)
		if _, err := stale.UserShow(uid); err != nil {
			t.Errorf("old cookie through the client: %v", err)
		}
	})
}

// TestContractNoSession pins Q13's answer without a session, which
// ExpireSession gives too.
func TestContractNoSession(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		code, h, body := sessionPost(t, b, "", "admin")
		if code != http.StatusUnauthorized || h.Get("WWW-Authenticate") != "Negotiate" || h.Get("Content-Type") != "text/html; charset=UTF-8" ||
			!strings.Contains(body, "<title>Identity Management</title>") {
			t.Errorf("HTTP %d, headers %v, body %q", code, h, body)
		}
		stale := b.client()
		_, err := stale.UserShow("admin")
		wantIs(t, err, ipa.ErrUnauthorized)
	})
}
