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
		// Asserted on every backend, so a FreeIPA release that answers differently fails the nightly with its code.
		record := func(what string, err error, code int) {
			t.Helper()
			var ie *ipa.IpaError
			if !errors.As(err, &ie) {
				t.Errorf("%s: err = %v, want code %d", what, err, code)
				return
			}
			if ie.Code != code {
				t.Errorf("%s: %d %s %q, want code %d", what, ie.Code, ie.Name, ie.Message, code)
			}
		}
		record("delattr of an attribute the entry lacks", run(b.admin.Modify("user_mod", uid).Del("title", "x")), ipa.CodeValidation)
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
