// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net"
	"reflect"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// V11
func TestContractHBACTest(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		host := "ipa.test.local" // ipatest's own host; b.host is its 127.0.0.1 address
		if b.name != "ipatest" {
			host = b.host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.HBACTest("admin", host, "sshd")
		if err != nil || !got.Granted || !slices.Contains(got.Matched, "allow_all") {
			t.Fatalf("admin = %+v, %v", got, err)
		}
		raw, err := b.admin.RPC("hbactest", nil, ipa.Options{"user": "admin", "targethost": host, "service": "sshd", "sizelimit": 0})
		if err != nil {
			t.Fatal(err)
		}
		if gjson.GetBytes(raw.Result.Raw, "result").Exists() || gjson.GetBytes(raw.Result.Raw, "value").Type != gjson.True ||
			gjson.GetBytes(raw.Result.Raw, "warning").Type != gjson.Null {
			t.Errorf("raw = %s", raw.Result.Raw)
		}
		if got, err := b.admin.HBACTest("nosuchuser-"+randHex(t, 4), host, "sshd"); err != nil || !got.Granted {
			t.Errorf("unknown user = %+v, %v", got, err)
		}

		r := "gr" + randHex(t, 4)
		if _, err := b.admin.RPC("hbacrule_add", []string{r}, ipa.Options{"servicecategory": "all", "hostcategory": "all"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("hbacrule_del", []string{r}, nil) })
		got, err = b.admin.HBACTest(uid, host, "sshd", r)
		if err != nil || got.Granted || !reflect.DeepEqual(got.NotMatched, []string{r}) {
			t.Errorf("rule without users = %+v, %v", got, err)
		}
		missing := "nosuchrule-" + randHex(t, 4)
		got, err = b.admin.HBACTest(uid, host, "sshd", missing)
		if err != nil || !slices.Contains(got.Errors, missing) {
			t.Errorf("unknown rule = %+v, %v", got, err)
		}
	})
}
