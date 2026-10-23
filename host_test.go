// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestHostShow(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h1.test.local", ipatest.Host{
		Description: "d", Locality: "Kyiv", Location: "rack 1", Platform: "x86", OSVersion: "9",
		MACAddresses: []string{"aa:bb"}, UserClass: []string{"web"}, HostGroups: []string{"hg"},
		ManagedBy: []string{"h1.test.local"}, HasKeytab: true,
	})
	h, err := c.HostShow("h1.test.local")
	if err != nil {
		t.Fatal(err)
	}
	want := &ipa.Host{
		FQDN: "h1.test.local", Description: "d", Locality: "Kyiv", Location: "rack 1", Platform: "x86", OSVersion: "9",
		Principal:    "host/h1.test.local@TEST.LOCAL",
		MACAddresses: []string{"aa:bb"}, UserClass: []string{"web"}, HostGroups: []string{"hg"},
		ManagedBy: []string{"h1.test.local"}, HasKeytab: true,
	}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("got %+v, want %+v", h, want)
	}
	calls := s.Calls()
	if o := calls[len(calls)-1].Options; o["all"] != true || o["no_members"] != false {
		t.Errorf("options = %v", o)
	}
}

func TestHostShow_NotFound(t *testing.T) {
	_, c := newFake(t)
	_, err := c.HostShow("nope.test.local")
	if !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("err is %T, want bare *IpaError", err)
	}
}

func TestHostShow_EmptyFQDN(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.HostShow(""); err == nil {
		t.Fatal("nil error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestHostFind(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("a.test.local", ipatest.Host{HostGroups: []string{"hg"}})
	s.AddHost("b.test.local", ipatest.Host{})
	hs, err := c.HostFind(ipa.Options{"fqdn": "a.test.local"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 1 || hs[0].FQDN != "a.test.local" || !reflect.DeepEqual(hs[0].HostGroups, []string{"hg"}) {
		t.Errorf("got %+v", hs)
	}
	calls := s.Calls()
	last := calls[len(calls)-1]
	if last.Options["all"] != true || last.Options["no_members"] != false || !reflect.DeepEqual(last.Args, []string{""}) {
		t.Errorf("call = %+v", last)
	}
	all, err := c.HostFind(nil) // the server's own host is seeded (R11)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("%d hosts, want 3", len(all))
	}
}

func TestHostFind_DoesNotModifyOptions(t *testing.T) {
	_, c := newFake(t)
	opts := ipa.Options{"fqdn": "a.test.local"}
	if _, err := c.HostFind(opts); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, ipa.Options{"fqdn": "a.test.local"}) {
		t.Errorf("options modified: %v", opts)
	}
}

func TestHostShow_ServerHostHasKeytab(t *testing.T) {
	_, c := newFake(t)
	h, err := c.HostShow("ipa.test.local")
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasKeytab {
		t.Error("HasKeytab false")
	}
}
