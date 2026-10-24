// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestModify_Options(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	_, err := c.Modify("user_mod", "bob").Add("mail", "a@x").Add("mail", "b@x").Set("ou", "T").
		Del("mail", "c@x").Set("ou", "U").Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Method != "user_mod" || string(calls[0].Args) != `["bob"]` {
		t.Fatalf("calls = %+v", calls)
	}
	want := map[string]any{
		"addattr": []any{"mail=a@x", "mail=b@x"},
		"setattr": []any{"ou=T", "ou=U"},
		"delattr": []any{"mail=c@x"},
		"all":     true,
	}
	for k, v := range want {
		if !reflect.DeepEqual(calls[0].Options[k], v) {
			t.Errorf("%s = %v, want %v", k, calls[0].Options[k], v)
		}
	}
}

func TestModify_Keys(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	keys := []string{"example.test.", "www"}
	m := c.Modify("dnsrecord_mod", keys...).Set("arecord", "192.0.2.1")
	keys[1] = "changed"
	if _, err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := string(f.Calls()[0].Args); got != `["example.test.","www"]` {
		t.Errorf("args = %s", got)
	}
}

func TestModify_Apply(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "Bob", Last: "B", Email: "bob@x"})
	c := s.ClientAs("admin")
	run := func(m *ipa.Modification) {
		t.Helper()
		if _, err := m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	run(c.Modify("user_mod", "bob").Set("title", "T"))
	run(c.Modify("user_mod", "bob").Add("mail", "b2@x"))
	u, _ := s.User("bob")
	if u.Title != "T" || !reflect.DeepEqual(u.Emails, []string{"bob@x", "b2@x"}) {
		t.Fatalf("after set+add: %+v", u)
	}
	run(c.Modify("user_mod", "bob").Del("mail", "bob@x").Set("loginshell", "/bin/zsh"))
	u, _ = s.User("bob")
	if u.Email != "b2@x" || u.Shell != "/bin/zsh" {
		t.Fatalf("after del: %+v", u)
	}

	for _, tc := range []struct {
		name string
		m    *ipa.Modification
		code int
	}{
		{"duplicate", c.Modify("user_mod", "bob").Add("mail", "b2@x"), ipa.CodeAlreadyContainsValue},
		{"absent", c.Modify("user_mod", "bob").Del("mail", "nope@x"), ipa.CodeAttrValueNotFound},
		{"unknown", c.Modify("user_mod", "bob").Set("nosuch", "v"), ipa.CodeValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.m.Run(context.Background())
			var ie *ipa.IpaError
			if !errors.As(err, &ie) || ie.Code != tc.code {
				t.Fatalf("err = %v, want code %d", err, tc.code)
			}
		})
	}
}

func TestModify_ClearWithEmptySet(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "Bob", Last: "B", Title: "T"})
	if _, err := s.ClientAs("admin").Modify("user_mod", "bob").Set("title", "").Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User("bob"); u.Title != "" {
		t.Errorf("title = %q", u.Title)
	}
}

func TestModify_Validation(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	for name, m := range map[string]*ipa.Modification{
		"empty command": c.Modify("", "bob").Set("a", "b"),
		"no key":        c.Modify("user_mod").Set("a", "b"),
		"empty key":     c.Modify("dnsrecord_mod", "zone", "").Set("a", "b"),
		"empty attr":    c.Modify("user_mod", "bob").Set("", "b"),
		"attr with =":   c.Modify("user_mod", "bob").Add("a=b", "c"),
		"nothing to do": c.Modify("user_mod", "bob"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Run(context.Background()); err == nil {
				t.Fatal("no error")
			}
		})
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls sent", n)
	}
}

func TestModify_EmptyModlist(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "Bob", Last: "B", Title: "T"})
	_, err := s.ClientAs("admin").Modify("user_mod", "bob").Set("title", "T").Run(context.Background())
	if err != ipa.ErrEmptyModlist && !errors.Is(err, ipa.ErrEmptyModlist) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("err %T is wrapped", err)
	}
}

func TestModify_SingleValued(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "Bob", Last: "B", Title: "T"})
	c := s.ClientAs("admin")
	for name, m := range map[string]*ipa.Modification{
		"two sets":     c.Modify("user_mod", "bob").Set("title", "A").Set("title", "B"),
		"add to a set": c.Modify("user_mod", "bob").Add("title", "B"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := m.Run(context.Background())
			var ie *ipa.IpaError
			if !errors.As(err, &ie) || ie.Code != ipa.CodeOnlyOneValueAllowed || ie.Message != "title: Only one value allowed." {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if u, _ := s.User("bob"); u.Title != "T" {
		t.Errorf("title = %q", u.Title)
	}
}
