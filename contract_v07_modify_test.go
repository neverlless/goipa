// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// X4
func TestContractModify(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test", Email: uid + "@example.test"}, false); err != nil {
			t.Fatal(err)
		}
		extra := "x" + uid + "@example.test"
		show := func() gjson.Result {
			t.Helper()
			r, err := b.admin.RPC("user_show", []string{uid}, ipa.Options{"all": true})
			if err != nil {
				t.Fatal(err)
			}
			return gjson.ParseBytes(r.Result.Data)
		}
		run := func(m *ipa.Modification) error {
			_, err := m.Run(ctx)
			return err
		}
		if err := run(b.admin.Modify("user_mod", uid).Set("title", "T")); err != nil {
			t.Fatal(err)
		}
		if got := show().Get("title.0").String(); got != "T" {
			t.Errorf("title = %q", got)
		}
		if err := run(b.admin.Modify("user_mod", uid).Add("mail", extra)); err != nil {
			t.Fatal(err)
		}
		if n := len(show().Get("mail").Array()); n != 2 {
			t.Errorf("mail count = %d, want 2", n)
		}
		// On the real server these only record the code; ipatest must match the brief.
		record := func(what string, err error, code int) {
			t.Helper()
			var ie *ipa.IpaError
			if !errors.As(err, &ie) {
				if b.name == "ipatest" {
					t.Fatalf("%s err = %v", what, err)
				}
				t.Logf("%s: err = %v", what, err)
				return
			}
			t.Logf("%s: %d %s %q", what, ie.Code, ie.Name, ie.Message)
			if b.name == "ipatest" && ie.Code != code {
				t.Errorf("%s code = %d, want %d", what, ie.Code, code)
			}
		}
		record("duplicate add", run(b.admin.Modify("user_mod", uid).Add("mail", extra)), ipa.CodeAlreadyContainsValue)
		if err := run(b.admin.Modify("user_mod", uid).Del("mail", extra)); err != nil {
			t.Fatal(err)
		}
		if n := len(show().Get("mail").Array()); n != 1 {
			t.Errorf("mail count = %d, want 1", n)
		}
		record("absent del", run(b.admin.Modify("user_mod", uid).Del("mail", extra)), ipa.CodeAttrValueNotFound)
		record("unknown attr", run(b.admin.Modify("user_mod", uid).Set("nosuchattr", "v")), ipa.CodeValidation)
		record("two title values", run(b.admin.Modify("user_mod", uid).Set("title", "A").Set("title", "B")), ipa.CodeOnlyOneValueAllowed)
	})
}
