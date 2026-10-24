// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestDNS_NoRequestWithoutKeys(t *testing.T) {
	s, c := newFake(t)
	for name, err := range map[string]error{
		"zone delete":   c.DNSZoneDelete(),
		"zone del gap":  c.DNSZoneDelete("z.test.", ""),
		"zone show":     func() error { _, err := c.DNSZoneShow(""); return err }(),
		"zone add":      func() error { _, err := c.DNSZoneAdd("", false); return err }(),
		"zone enable":   c.DNSZoneEnable(""),
		"zone disable":  c.DNSZoneDisable(""),
		"record zone":   func() error { _, err := c.DNSRecordAdd("", "www", "A", "192.0.2.1"); return err }(),
		"record name":   func() error { _, err := c.DNSRecordShow("z.test.", ""); return err }(),
		"record find":   func() error { _, err := c.DNSRecordFind("", nil); return err }(),
		"record values": func() error { _, err := c.DNSRecordAdd("z.test.", "www", "A"); return err }(),
		"remove values": c.DNSRecordRemove("z.test.", "www", "A"),
		"delete name":   c.DNSRecordDelete("z.test.", ""),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	for _, rtype := range []string{"", "nosuch", "addattr"} {
		_, err := c.DNSRecordAdd("z.test.", "www", rtype, "x")
		if !errors.Is(err, ipa.ErrInvalidCall) {
			t.Errorf("rtype %q: got %v, want ErrInvalidCall", rtype, err)
		}
		if err := c.DNSRecordRemove("z.test.", "www", rtype, "x"); !errors.Is(err, ipa.ErrInvalidCall) {
			t.Errorf("remove rtype %q: got %v, want ErrInvalidCall", rtype, err)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}

func TestDNSRecord_Calls(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.DNSZoneAdd("z.test", true); err != nil {
		t.Fatal(err)
	}
	if o := s.Calls()[0].Options; o["force"] != true {
		t.Errorf("dnszone_add options %v", o)
	}
	r, err := c.DNSRecordAdd("z.test", "www.z.test.", "Mx", "10 mail.z.test.")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "www" || len(r.Records["MX"]) != 1 {
		t.Fatalf("record %+v", r)
	}
	if err := c.DNSRecordDelete("z.test", "www"); err != nil {
		t.Fatal(err)
	}
	calls := s.Calls()
	if o := calls[len(calls)-1].Options; o["del_all"] != true {
		t.Errorf("dnsrecord_del options %v", o)
	}
	if _, err := c.DNSRecordShow("z.test", "www"); !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestDNSFind_Truncated(t *testing.T) {
	_, c := newFake(t)
	for _, z := range []string{"a.test.", "b.test."} {
		if _, err := c.DNSZoneAdd(z, false); err != nil {
			t.Fatal(err)
		}
	}
	zones, err := c.DNSZoneFind(ipa.Options{"sizelimit": 1})
	if !errors.Is(err, ipa.ErrTruncated) || len(zones) != 1 {
		t.Fatalf("zones %d, err %v", len(zones), err)
	}
	if _, err := c.DNSRecordAdd("a.test.", "www", "A", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	recs, err := c.DNSRecordFind("a.test.", ipa.Options{"sizelimit": 1})
	if !errors.Is(err, ipa.ErrTruncated) || len(recs) != 1 {
		t.Fatalf("records %d, err %v", len(recs), err)
	}
}
