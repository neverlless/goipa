// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func names(cmds []ipa.Command) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.Name
	}
	return out
}

func TestCommands_All(t *testing.T) {
	all := ipa.Commands("")
	n := names(all)
	if !slices.IsSorted(n) {
		t.Error("not sorted by name")
	}
	if len(all) < 506 {
		t.Errorf("%d commands, want >= 506", len(all))
	}
	for _, want := range []string{"user_show", "sysaccount_add"} {
		if !slices.Contains(n, want) {
			t.Errorf("%s missing", want)
		}
	}
	if !reflect.DeepEqual(ipa.Commands("garbage"), all) {
		t.Error(`Commands("garbage") != Commands("")`)
	}
}

func TestCommands_Versions(t *testing.T) {
	for _, tc := range []struct {
		cmd, before, at string
	}{
		{"subid_find", "4.9.6", "4.9.7"},
		{"host_add_delegation", "4.10.1", "4.10.2"},
		{"sysaccount_add", "4.12.5", "4.13.0"},
		{"sysaccount_add", "4.12.5", "4.13.5.dev1"},
	} {
		if slices.Contains(names(ipa.Commands(tc.before)), tc.cmd) {
			t.Errorf("%s present at %s", tc.cmd, tc.before)
		}
		if !slices.Contains(names(ipa.Commands(tc.at)), tc.cmd) {
			t.Errorf("%s absent at %s", tc.cmd, tc.at)
		}
	}
	if !reflect.DeepEqual(ipa.Commands("4.8.10"), ipa.Commands("4.9.0")) {
		t.Error(`Commands("4.8.10") != Commands("4.9.0")`)
	}
}

func option(c ipa.Command, name string) (ipa.Param, bool) {
	for _, p := range c.Options {
		if p.Name == name {
			return p, true
		}
	}
	return ipa.Param{}, false
}

func TestLookupCommand(t *testing.T) {
	c, ok := ipa.LookupCommand("user_add", "4.13.4")
	if !ok {
		t.Fatal("user_add missing")
	}
	if want := (ipa.Param{Name: "uid", Type: "Str", Required: true, Since: "4.9.0"}); len(c.Args) == 0 || c.Args[0] != want {
		t.Errorf("args = %+v", c.Args)
	}
	for _, tc := range []struct {
		name            string
		typ             string
		required, multi bool
	}{
		{"givenname", "Str", true, false},
		{"all", "Flag", false, false},
		{"cn", "Str", false, false},
		{"mail", "Str", false, true},
	} {
		p, ok := option(c, tc.name)
		if !ok || p.Type != tc.typ || p.Required != tc.required || p.Multi != tc.multi {
			t.Errorf("option %s = %+v, %v", tc.name, p, ok)
		}
	}

	if _, ok := ipa.LookupCommand("subid_find", "4.9.6"); ok {
		t.Error("subid_find at 4.9.6")
	}
	if c, ok := ipa.LookupCommand("user_add_passkey", ""); !ok || c.Since != "4.11.0" {
		t.Errorf("user_add_passkey = %+v, %v", c, ok)
	}
	if _, ok := ipa.LookupCommand("nope", ""); ok {
		t.Error("nope found")
	}

	// ipaidpconfiglink (--idp) arrived in 4.9.10.
	if c, _ := ipa.LookupCommand("user_add", "4.9.9"); hasOption(c, "ipaidpconfiglink") {
		t.Error("ipaidpconfiglink at 4.9.9")
	}
	c, _ = ipa.LookupCommand("user_add", "4.9.10")
	if p, ok := option(c, "ipaidpconfiglink"); !ok || p.Since != "4.9.10" {
		t.Errorf("ipaidpconfiglink at 4.9.10 = %+v, %v", p, ok)
	}
}

func hasOption(c ipa.Command, name string) bool {
	_, ok := option(c, name)
	return ok
}

func TestCommands_ReturnsCopies(t *testing.T) {
	c, _ := ipa.LookupCommand("user_add", "")
	c.Args[0].Name = "x"
	for _, cmd := range ipa.Commands("") {
		if cmd.Name == "user_add" {
			cmd.Args[0].Type = "x"
		}
	}
	again, _ := ipa.LookupCommand("user_add", "")
	if want := (ipa.Param{Name: "uid", Type: "Str", Required: true, Since: "4.9.0"}); again.Args[0] != want {
		t.Errorf("catalogue changed: %+v", again.Args[0])
	}
}
