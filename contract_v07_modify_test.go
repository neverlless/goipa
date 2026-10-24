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
		err := run(b.admin.Modify("user_mod", uid).Add("mail", extra))
		var ie *ipa.IpaError
		if !errors.As(err, &ie) {
			t.Fatalf("duplicate add err = %v", err)
		}
		t.Logf("duplicate add: %d %s %q", ie.Code, ie.Name, ie.Message)
		if err := run(b.admin.Modify("user_mod", uid).Del("mail", extra)); err != nil {
			t.Fatal(err)
		}
		if n := len(show().Get("mail").Array()); n != 1 {
			t.Errorf("mail count = %d, want 1", n)
		}
		err = run(b.admin.Modify("user_mod", uid).Del("mail", extra))
		if !errors.As(err, &ie) {
			t.Fatalf("absent del err = %v", err)
		}
		t.Logf("absent del: %d %s %q", ie.Code, ie.Name, ie.Message)
		err = run(b.admin.Modify("user_mod", uid).Set("nosuchattr", "v"))
		if !errors.As(err, &ie) {
			t.Fatalf("unknown attr err = %v", err)
		}
		t.Logf("unknown attr: %d %s %q", ie.Code, ie.Name, ie.Message)
		if b.name == "ipatest" {
			return
		}
		// Real server: the codes above are recorded for aligning the fake.
	})
}
