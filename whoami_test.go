// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestWhoAmI(t *testing.T) {
	s := ipatest.NewServer(t)
	got, err := s.ClientAs("u1").WhoAmI()
	if err != nil {
		t.Fatal(err)
	}
	if got.Object != "user" || got.Command != "user_show/1" || !reflect.DeepEqual(got.Arguments, []string{"u1"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestWhoAmI_NoResultKey(t *testing.T) {
	s := ipatest.NewServer(t)
	raw, err := s.ClientAs("u1").RPC("whoami", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(raw.Result.Raw, "result").Exists() || gjson.GetBytes(raw.Result.Raw, "object").String() != "user" {
		t.Fatalf("raw = %s", raw.Result.Raw)
	}
}
