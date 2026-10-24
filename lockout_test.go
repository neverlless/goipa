// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestUserStatus_ValueForms(t *testing.T) {
	s, c := newFake(t)
	s.Handle("user_status", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": []map[string]any{
			{"dn": "x", "server": "r1", "now": "2026-10-22T10:00:01Z", "krbloginfailedcount": "0", "krblastfailedauth": []string{"N/A"}, "krblastsuccessfulauth": []string{"N/A"}},
			{"dn": "x", "server": "r2", "now": "2026-10-22T10:00:01Z", "krbloginfailedcount": []string{"3"}, "krblastsuccessfulauth": []string{"2026-10-21T09:00:00Z"}, "krblastfailedauth": []string{"2026-10-22T10:00:00Z"}},
			{"dn": "x", "server": "r3", "now": "2026-10-22T10:00:01Z", "krbloginfailedcount": []string{"2"}, "krblastsuccessfulauth": []map[string]string{{"__datetime__": "20261021090000Z"}}, "krblastfailedauth": []map[string]string{{"__datetime__": "20261022100000Z"}}},
		}}, nil
	})
	sts, err := c.UserStatus("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 3 {
		t.Fatalf("len = %d", len(sts))
	}
	if sts[0].FailedLogins != 0 || !sts[0].LastFailure.IsZero() || sts[0].Now.IsZero() || !sts[0].LastSuccess.IsZero() {
		t.Errorf("r1 = %+v", sts[0])
	}
	if want := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC); sts[1].FailedLogins != 3 || !sts[1].LastSuccess.Equal(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)) || !sts[1].LastFailure.Equal(want) {
		t.Errorf("r2 = %+v", sts[1])
	}
	if want := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC); sts[2].FailedLogins != 2 || !sts[2].LastSuccess.Equal(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)) || !sts[2].LastFailure.Equal(want) {
		t.Errorf("r3 (__datetime__) = %+v", sts[2])
	}
	calls := s.Calls()
	if calls[len(calls)-1].Options["all"] != true {
		t.Errorf("options = %v", calls[len(calls)-1].Options)
	}
}

func TestUserStatus_UnreachableReplica(t *testing.T) {
	s, c := newFake(t)
	s.Handle("user_status", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": []map[string]any{
			{"dn": "x", "server": "r1", "now": "2026-10-22T10:00:01Z", "krbloginfailedcount": "0"},
			{"dn": "x", "server": "r2.test.local failed: timed out"},
		}}, nil
	})
	sts, err := c.UserStatus("bob")
	if err != nil {
		t.Fatal(err)
	}
	if got := sts[1]; got.Server != "r2.test.local" || got.Err != "timed out" || got.FailedLogins != 0 {
		t.Errorf("r2 = %+v", got)
	}
	if sts[0].Err != "" {
		t.Errorf("r1 = %+v", sts[0])
	}
}

func TestUserStatus_EmptyName(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.UserStatus(""); err == nil {
		t.Error("UserStatus: nil error")
	}
	if err := c.UserUnlock(""); err == nil {
		t.Error("UserUnlock: nil error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestUserStatusUnlock_Fake(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("bob", ipatest.User{Password: "Secret123!"})
	_ = c.RemoteLogin("bob", "wrong")
	sts, err := c.UserStatus("bob")
	if err != nil || len(sts) != 1 || sts[0].Server != "ipa.test.local" || sts[0].FailedLogins != 1 || sts[0].LastFailure.IsZero() {
		t.Fatalf("sts = %+v, err %v", sts, err)
	}
	raw, err := c.RPC("user_status", []string{"bob"}, ipa.Options{"all": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := gjson.GetBytes(raw.Result.Data, "0.krblastfailedauth.0.__datetime__").String(); !strings.HasSuffix(got, "Z") || len(got) != 15 {
		t.Errorf("krblastfailedauth = %s", gjson.GetBytes(raw.Result.Data, "0.krblastfailedauth").Raw)
	}
	if got := gjson.GetBytes(raw.Result.Data, "0.krblastsuccessfulauth").Raw; got != `["N/A"]` {
		t.Errorf("krblastsuccessfulauth = %s", got)
	}
	if err := c.UserUnlock("bob"); err != nil {
		t.Fatal(err)
	}
	if sts, _ = c.UserStatus("bob"); sts[0].FailedLogins != 0 {
		t.Errorf("after unlock: %+v", sts[0])
	}
}
