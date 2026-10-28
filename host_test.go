// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
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

// lastCall is the last call without the client's version option.
func lastCall(s *ipatest.Server) ipatest.Call {
	calls := s.Calls()
	c := calls[len(calls)-1]
	c.Options = maps.Clone(c.Options)
	delete(c.Options, "version")
	return c
}

func TestHostAdd_SendsAttributes(t *testing.T) {
	s, c := newFake(t)
	h, err := c.HostAdd(&ipa.Host{
		FQDN: "H1.test.local", Description: "d", Locality: "Kyiv", Location: "rack 1", Platform: "x86", OSVersion: "9",
		MACAddresses: []string{"aa:bb:cc:dd:ee:ff"}, UserClass: []string{"web"},
	}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.FQDN != "h1.test.local" || h.Locality != "Kyiv" || !slices.Equal(h.MACAddresses, []string{"AA:BB:CC:DD:EE:FF"}) || h.RandomPassword != "" || h.HasPassword {
		t.Errorf("got %+v", h)
	}
	call := lastCall(s)
	if call.Method != "host_add" || len(call.Args) != 1 || call.Args[0] != "H1.test.local" {
		t.Fatalf("call %+v", call)
	}
	want := map[string]any{"all": true, "no_members": false, "force": true, "description": "d", "l": "Kyiv",
		"nshostlocation": "rack 1", "nshardwareplatform": "x86", "nsosversion": "9",
		"macaddress": []any{"aa:bb:cc:dd:ee:ff"}, "userclass": []any{"web"}}
	if !reflect.DeepEqual(call.Options, want) {
		t.Errorf("options %v, want %v", call.Options, want)
	}

	if _, err := c.HostAdd(&ipa.Host{FQDN: "h2.test.local"}, false, false); err != nil {
		t.Fatal(err)
	}
	o := lastCall(s).Options
	for _, k := range []string{"force", "random", "description", "macaddress", "userpassword"} {
		if _, ok := o[k]; ok {
			t.Errorf("option %s sent: %v", k, o)
		}
	}
}

func TestHostAdd_Random(t *testing.T) {
	s, c := newFake(t)
	h, err := c.HostAdd(&ipa.Host{FQDN: "h1.test.local"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if h.RandomPassword == "" || !h.HasPassword || h.HasKeytab {
		t.Errorf("got %+v", h)
	}
	if lastCall(s).Options["random"] != true {
		t.Errorf("options %v", lastCall(s).Options)
	}
	shown, err := c.HostShow("h1.test.local")
	if err != nil {
		t.Fatal(err)
	}
	if shown.RandomPassword != "" || !shown.HasPassword {
		t.Errorf("shown %+v", shown)
	}
}

func TestHostAddWithPassword(t *testing.T) {
	s, c := newFake(t)
	h, err := c.HostAddWithPassword(&ipa.Host{FQDN: "h1.test.local"}, true, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasPassword || h.RandomPassword != "" {
		t.Errorf("got %+v", h)
	}
	// Calls shows the password raw until it is redacted; only the key is pinned.
	if _, ok := lastCall(s).Options["userpassword"]; !ok {
		t.Errorf("options %v", lastCall(s).Options)
	}
}

func TestHostAddWithPassword_EmptyPassword(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.HostAddWithPassword(&ipa.Host{FQDN: "h1.test.local"}, true, ""); err == nil {
		t.Fatal("nil error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestHostAdd_RequiresFQDN(t *testing.T) {
	_, c := newFake(t)
	for _, h := range []*ipa.Host{nil, {}} {
		if _, err := c.HostAdd(h, true, false); err == nil {
			t.Errorf("HostAdd(%v): nil error", h)
		}
	}
}

func TestHostAdd_Duplicate(t *testing.T) {
	_, c := newFake(t)
	_, err := c.HostAdd(&ipa.Host{FQDN: "ipa.test.local"}, true, false)
	if !errors.Is(err, ipa.ErrDuplicateEntry) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("err is %T, want bare *IpaError", err)
	}
}

func TestHostMod(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h1.test.local", ipatest.Host{Description: "d", Locality: "Kyiv", MACAddresses: []string{"aa"}})
	h, err := c.HostMod(&ipa.Host{FQDN: "h1.test.local", Description: "new", UserClass: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	// Absent attributes are cleared, as GroupMod clears description.
	if h.Description != "new" || h.Locality != "" || h.MACAddresses != nil || !reflect.DeepEqual(h.UserClass, []string{"web"}) {
		t.Errorf("got %+v", h)
	}
	if o := lastCall(s).Options; o["l"] != "" || o["description"] != "new" || len(o) != 9 || !reflect.DeepEqual(o["macaddress"], []any{}) {
		t.Errorf("options %v", o)
	}
}

func TestHostMod_EmptyModlistReturnsHost(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h1.test.local", ipatest.Host{Description: "d"})
	in := &ipa.Host{FQDN: "h1.test.local", Description: "d"}
	out, err := c.HostMod(in)
	if err != nil || out != in {
		t.Fatalf("out %p, in %p, err %v", out, in, err)
	}
}

func TestHostMod_Errors(t *testing.T) {
	_, c := newFake(t)
	if _, err := c.HostMod(&ipa.Host{}); err == nil {
		t.Error("empty fqdn: nil error")
	}
	if _, err := c.HostMod(&ipa.Host{FQDN: "nope.test.local"}); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestHostDelete(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h1.test.local", ipatest.Host{})
	if err := c.HostDelete(true, "h1.test.local"); err != nil {
		t.Fatal(err)
	}
	if o := lastCall(s).Options; o["continue"] != false || o["updatedns"] != true {
		t.Errorf("options %v", o)
	}
	if _, err := c.HostShow("h1.test.local"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	s.AddHost("h2.test.local", ipatest.Host{})
	if err := c.HostDelete(false, "h2.test.local"); err != nil {
		t.Fatal(err)
	}
	if _, ok := lastCall(s).Options["updatedns"]; ok {
		t.Errorf("options %v", lastCall(s).Options)
	}
}

func TestHostDelete_RequiresName(t *testing.T) {
	s, c := newFake(t)
	for _, names := range [][]string{nil, {""}, {"a.test.local", ""}} {
		if err := c.HostDelete(false, names...); err == nil {
			t.Errorf("HostDelete(%q): nil error", names)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestHostDelete_UpdateDNS(t *testing.T) {
	s, c := newFake(t)
	for _, fqdn := range []string{"keep.test.local", "gone.test.local"} {
		s.AddHost(fqdn, ipatest.Host{})
		if _, err := c.DNSRecordAdd("test.local.", strings.TrimSuffix(fqdn, ".test.local"), "A", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.HostDelete(false, "keep.test.local"); err != nil {
		t.Fatal(err)
	}
	if err := c.HostDelete(true, "gone.test.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DNSRecordShow("test.local.", "keep"); err != nil {
		t.Errorf("keep: %v", err)
	}
	if _, err := c.DNSRecordShow("test.local.", "gone"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("gone: %v", err)
	}
}

func TestHostDisable_DropsKeytab(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h1.test.local", ipatest.Host{HasKeytab: true, Password: "pw"})
	if err := c.HostDisable("h1.test.local"); err != nil {
		t.Fatal(err)
	}
	if o := lastCall(s).Options; len(o) != 0 {
		t.Errorf("options %v", o)
	}
	h, err := c.HostShow("h1.test.local")
	if err != nil {
		t.Fatal(err)
	}
	if h.HasKeytab || !h.HasPassword { // the source leaves userPassword
		t.Errorf("shown %+v", h)
	}
	var ie *ipa.IpaError
	if err := c.HostDisable("h1.test.local"); !errors.As(err, &ie) || ie.Code != ipa.CodeAlreadyInactive {
		t.Errorf("second disable: %v", err)
	}
	if err := c.HostDisable(""); err == nil {
		t.Error("empty fqdn: nil error")
	}
}

func TestHostDisable_ServiceKeys(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h2.test.local", ipatest.Host{})
	s.AddService("HTTP/h2.test.local", ipatest.Service{HasKeytab: true})
	res, err := c.RPC("host_disable", []string{"h2.test.local"}, nil)
	if err != nil {
		t.Fatalf("host without keytab but with a service key: %v", err)
	}
	if res.Result.Summary != `Disabled host "h2.test.local"` {
		t.Errorf("summary %q", res.Result.Summary)
	}
	svc, err := c.ServiceShow("HTTP/h2.test.local")
	if err != nil || svc.HasKeytab {
		t.Errorf("service %+v, %v", svc, err)
	}
}
