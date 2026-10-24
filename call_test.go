// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func addUsers(t *testing.T, c *ipa.Client, uids ...string) {
	t.Helper()
	for _, uid := range uids {
		if _, err := c.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCall_EntryAndStruct(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1")
	ctx := context.Background()
	e, res, err := ipa.Call[ipa.Entry](ctx, c, "user_show", []string{"u1"}, ipa.Options{"all": true})
	if err != nil || res == nil {
		t.Fatal(err)
	}
	if e.Str("uid") != "u1" {
		t.Errorf("uid = %q", e.Str("uid"))
	}
	st, _, err := ipa.Call[struct {
		UID []string `json:"uid"`
	}](ctx, c, "user_show", []string{"u1"}, nil)
	if err != nil || !reflect.DeepEqual(st.UID, []string{"u1"}) {
		t.Errorf("struct: %+v, %v", st, err)
	}
}

func TestCall_List(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1", "u2")
	es, _, err := ipa.Call[[]ipa.Entry](context.Background(), c, "user_find", []string{""}, nil)
	if err != nil || len(es) < 2 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
}

func TestCall_NoResultKey(t *testing.T) {
	s := ipatest.NewServer(t)
	e, _, err := ipa.Call[ipa.Entry](context.Background(), s.ClientAs("u1"), "whoami", nil, nil)
	if err != nil || e.Str("object") != "user" {
		t.Fatalf("%s, %v", e.Raw(), err)
	}
}

func TestCall_ErrorBare(t *testing.T) {
	s := ipatest.NewServer(t)
	_, _, err := ipa.Call[ipa.Entry](context.Background(), s.ClientAs("admin"), "user_show", []string{"nobody"}, nil)
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || err != error(ie) {
		t.Fatalf("err = %#v", err)
	}
}

func TestCall_DecodeError(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1")
	_, _, err := ipa.Call[int](context.Background(), c, "user_show", []string{"u1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "ipa: decode user_show result") {
		t.Fatalf("err = %v", err)
	}
}

func lastFind(s *ipatest.Server) ipatest.Call {
	cs := s.Calls()
	return cs[len(cs)-1]
}

func TestFindEntries_Truncated(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1", "u2", "u3")
	es, err := ipa.FindEntries(context.Background(), c, "user_find", "u", nil, 2)
	if err != ipa.ErrTruncated {
		t.Fatalf("err = %v", err)
	}
	if len(es) != 2 || es[0].Str("uid") != "u1" {
		t.Errorf("entries = %d", len(es))
	}
	o := lastFind(s).Options
	if o["sizelimit"] != float64(2) || o["all"] != true {
		t.Errorf("options = %v", o)
	}
}

func TestFindEntries_NotTruncated(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1", "u2")
	es, err := ipa.FindEntries(context.Background(), c, "user_find", "u", nil, 0)
	if err != nil || len(es) < 2 {
		t.Fatalf("%d, %v", len(es), err)
	}
	if _, ok := lastFind(s).Options["sizelimit"]; ok {
		t.Error("sizelimit sent")
	}
	// sizelimit above the match count is not a truncation
	if _, err := ipa.FindEntries(context.Background(), c, "user_find", "u", nil, 50); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestFindEntries_DoesNotModifyOptions(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	opts := ipa.Options{"uid": "u1"}
	if _, err := ipa.FindEntries(context.Background(), c, "user_find", "", opts, 5); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, ipa.Options{"uid": "u1"}) {
		t.Errorf("opts = %v", opts)
	}
	// the caller's own all: false wins
	_, _ = ipa.FindEntries(context.Background(), c, "user_find", "", ipa.Options{"all": false}, 0)
	if lastFind(s).Options["all"] != false {
		t.Error("all overridden")
	}
}

func TestFindEntries_GroupHostLimit(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	ctx := context.Background()
	for _, n := range []string{"a1", "a2"} {
		if _, err := c.GroupAdd(&ipa.Group{Name: n}); err != nil {
			t.Fatal(err)
		}
		s.AddHost(n+".test.local", ipatest.Host{})
	}
	for _, m := range []string{"group_find", "host_find"} {
		es, err := ipa.FindEntries(ctx, c, m, "a", nil, 1)
		if err != ipa.ErrTruncated || len(es) != 1 {
			t.Errorf("%s: %d, %v", m, len(es), err)
		}
	}
}
