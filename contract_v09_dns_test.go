// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/neverlless/goipa"
)

func zoneName(t *testing.T) string { return "goipa" + randHex(t, 4) + ".test." }

// newZone adds a random zone and deletes it when the test ends.
func newZone(t *testing.T, b backend) string {
	t.Helper()
	zone := zoneName(t)
	if _, err := b.admin.DNSZoneAdd(zone, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.DNSZoneDelete(zone) })
	return zone
}

func zoneActive(t *testing.T, b backend, zone string, want bool) {
	t.Helper()
	z, err := b.admin.DNSZoneShow(zone)
	if err != nil {
		t.Fatal(err)
	}
	if z.Active != want {
		t.Fatalf("Active %v, want %v", z.Active, want)
	}
}

// TestContractDNSZoneLifecycle pins Q100 and Q101.
func TestContractDNSZoneLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		zone := zoneName(t)
		t.Cleanup(func() { _ = b.admin.DNSZoneDelete(zone) })
		z, err := b.admin.DNSZoneAdd(zone, false)
		if err != nil {
			t.Fatal(err)
		}
		if z.Name != zone || !z.Active || z.DynamicUpdate {
			t.Fatalf("added %+v", z)
		}
		if z.NameServer == "" || z.AdminEmail != "hostmaster" {
			t.Errorf("NameServer %q, AdminEmail %q", z.NameServer, z.AdminEmail)
		}
		if z.Serial <= 0 || z.Refresh <= 0 || z.Retry <= 0 || z.Expire <= 0 || z.Minimum <= 0 {
			t.Errorf("SOA fields %+v", z)
		}
		shown, err := b.admin.DNSZoneShow(zone)
		if err != nil {
			t.Fatal(err)
		}
		if shown.Name != zone || shown.NameServer != z.NameServer || shown.Refresh != z.Refresh {
			t.Errorf("shown %+v, added %+v", shown, z)
		}
		zones, err := b.admin.DNSZoneFind(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(zones, func(z *ipa.DNSZone) bool { return z.Name == zone }) {
			t.Errorf("DNSZoneFind lacks %s", zone)
		}
		_, err = b.admin.DNSZoneAdd(zone, false)
		wantIs(t, err, ipa.ErrDuplicateEntry)

		if err := b.admin.DNSZoneDisable(zone); err != nil {
			t.Fatal(err)
		}
		zoneActive(t, b, zone, false)
		if err := b.admin.DNSZoneDisable(zone); err != nil {
			t.Fatalf("second disable: %v", err)
		}
		if err := b.admin.DNSZoneEnable(zone); err != nil {
			t.Fatal(err)
		}
		zoneActive(t, b, zone, true)

		if err := b.admin.DNSZoneDelete(zone); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.DNSZoneShow(zone)
		wantIs(t, err, ipa.ErrNotFound)
		wantIs(t, b.admin.DNSZoneEnable(zone), ipa.ErrNotFound)
	})
}

func wantRecords(t *testing.T, r *ipa.DNSRecord, rtype string, want ...string) {
	t.Helper()
	if !slices.Equal(r.Records[rtype], want) {
		t.Fatalf("%s %s records %q, want %q (all: %v)", r.Name, rtype, r.Records[rtype], want, r.Records)
	}
}

// TestContractDNSRecords pins Q102 and Q103.
func TestContractDNSRecords(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		zone := newZone(t, b)
		r, err := b.admin.DNSRecordAdd(zone, "www", "A", "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		if r.Name != "www" {
			t.Fatalf("Name %q", r.Name)
		}
		wantRecords(t, r, "A", "192.0.2.1")
		if r, err = b.admin.DNSRecordAdd(zone, "www", "aaaa", "2001:db8::1"); err != nil {
			t.Fatal(err)
		}
		wantRecords(t, r, "AAAA", "2001:db8::1")
		wantRecords(t, r, "A", "192.0.2.1")
		if _, err = b.admin.DNSRecordAdd(zone, "www", "TXT", "goipa-test"); err != nil {
			t.Fatal(err)
		}
		if r, err = b.admin.DNSRecordAdd(zone, "alias", "CNAME", "www."+zone); err != nil {
			t.Fatal(err)
		}
		wantRecords(t, r, "CNAME", "www."+zone)

		if r, err = b.admin.DNSRecordShow(zone, "www"); err != nil {
			t.Fatal(err)
		}
		wantRecords(t, r, "A", "192.0.2.1")
		wantRecords(t, r, "AAAA", "2001:db8::1")
		wantRecords(t, r, "TXT", "goipa-test")

		recs, err := b.admin.DNSRecordFind(zone, nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range recs {
			names = append(names, r.Name)
		}
		for _, n := range []string{"@", "_kerberos", "www", "alias"} {
			if !slices.Contains(names, n) {
				t.Errorf("DNSRecordFind names %q lack %q", names, n)
			}
		}

		if err := b.admin.DNSRecordRemove(zone, "www", "A", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		if r, err = b.admin.DNSRecordShow(zone, "www"); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.Records["A"]; ok {
			t.Fatalf("A records left: %v", r.Records)
		}
		wantIs(t, b.admin.DNSRecordRemove(zone, "www", "A", "192.0.2.1"), &ipa.IpaError{Code: ipa.CodeAttrValueNotFound})

		if err := b.admin.DNSRecordDelete(zone, "www"); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.DNSRecordShow(zone, "www")
		wantIs(t, err, ipa.ErrNotFound)

		_, err = b.admin.DNSRecordAdd(zone, "www", "NOSUCH", "x")
		wantIs(t, err, ipa.ErrInvalidCall)
	})
}

// TestContractDNSRecordMissingZone pins Q104.
func TestContractDNSRecordMissingZone(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		_, err := b.admin.DNSRecordAdd(zoneName(t), "www", "A", "192.0.2.1")
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != ipa.CodeNotFound {
			t.Fatalf("got %v, want 4001", err)
		}
	})
}
