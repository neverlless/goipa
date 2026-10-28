// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// newHostFQDN is a fresh name under the fixture domain; the host is deleted
// when the test ends.
func newHostFQDN(t *testing.T, b backend) string {
	t.Helper()
	_, domain, _ := strings.Cut(serverHost(t, b), ".")
	fqdn := "goipa" + randHex(t, 4) + "." + domain
	t.Cleanup(func() { _ = b.admin.HostDelete(false, fqdn) })
	return fqdn
}

func TestContractHostAddShowDelete(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newHostFQDN(t, b)
		h, err := b.admin.HostAdd(&ipa.Host{
			FQDN: fqdn, Description: "d", Locality: "Kyiv", Location: "rack 1", Platform: "x86", OSVersion: "9",
			MACAddresses: []string{"aa:bb:cc:dd:ee:ff"}, UserClass: []string{"web"},
		}, true, false)
		if err != nil {
			t.Fatal(err)
		}
		if h.FQDN != fqdn || h.Description != "d" || h.Locality != "Kyiv" || h.Location != "rack 1" ||
			h.Platform != "x86" || h.OSVersion != "9" || h.Principal != "host/"+fqdn+"@"+b.realm ||
			!slices.Equal(h.MACAddresses, []string{"AA:BB:CC:DD:EE:FF"}) || !slices.Equal(h.UserClass, []string{"web"}) {
			t.Errorf("added %+v", h)
		}
		if h.HasKeytab || h.HasPassword || h.RandomPassword != "" {
			t.Errorf("fresh host has keytab %v, password %v, random %q", h.HasKeytab, h.HasPassword, h.RandomPassword)
		}
		shown, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if shown.Description != "d" || shown.Locality != "Kyiv" || shown.RandomPassword != "" {
			t.Errorf("shown %+v", shown)
		}

		_, err = b.admin.HostAdd(&ipa.Host{FQDN: fqdn}, true, false)
		wantIs(t, err, ipa.ErrDuplicateEntry)
		if _, ok := err.(*ipa.IpaError); !ok {
			t.Errorf("duplicate err is %T, want bare *IpaError", err)
		}

		if err := b.admin.HostDelete(false, fqdn); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.HostShow(fqdn)
		wantIs(t, err, ipa.ErrNotFound)
		wantIs(t, b.admin.HostDelete(false, fqdn), ipa.ErrNotFound)
	})
}

func TestContractHostAddRandom(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newHostFQDN(t, b)
		h, err := b.admin.HostAdd(&ipa.Host{FQDN: fqdn}, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if h.RandomPassword == "" || !h.HasPassword || h.HasKeytab {
			t.Errorf("added %+v", h)
		}
		shown, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if shown.RandomPassword != "" || !shown.HasPassword {
			t.Errorf("shown %+v", shown)
		}
	})
}

func TestContractHostAddWithPassword(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newHostFQDN(t, b)
		h, err := b.admin.HostAddWithPassword(&ipa.Host{FQDN: fqdn}, true, "Host-Enroll-1")
		if err != nil {
			t.Fatal(err)
		}
		if !h.HasPassword || h.RandomPassword != "" || h.HasKeytab {
			t.Errorf("added %+v", h)
		}
		shown, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if !shown.HasPassword {
			t.Errorf("shown %+v", shown)
		}
	})
}

// TestContractHostModRoundTrip: a shown host goes back through HostMod
// unchanged and clears nothing; "" and an empty list clear.
func TestContractHostModRoundTrip(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newHostFQDN(t, b)
		if _, err := b.admin.HostAdd(&ipa.Host{
			FQDN: fqdn, Description: "d", Locality: "Kyiv", Location: "rack 1", Platform: "x86", OSVersion: "9",
			MACAddresses: []string{"aa:bb:cc:dd:ee:ff"}, UserClass: []string{"web"},
		}, true, false); err != nil {
			t.Fatal(err)
		}
		shown, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		same, err := b.admin.HostMod(shown)
		if err != nil {
			t.Fatal(err)
		}
		if same != shown {
			t.Errorf("unchanged HostMod returned %p, want the input %p", same, shown)
		}
		after, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if after.Description != "d" || after.Locality != "Kyiv" || len(after.MACAddresses) != 1 || len(after.UserClass) != 1 {
			t.Errorf("after round trip %+v", after)
		}

		shown.Description, shown.Locality, shown.MACAddresses = "", "", nil
		shown.Location = "rack 2"
		mod, err := b.admin.HostMod(shown)
		if err != nil {
			t.Fatal(err)
		}
		if mod.Description != "" || mod.Locality != "" || mod.MACAddresses != nil || mod.Location != "rack 2" ||
			mod.Platform != "x86" || mod.OSVersion != "9" || !slices.Equal(mod.UserClass, []string{"web"}) {
			t.Errorf("modified %+v", mod)
		}

		_, err = b.admin.HostMod(&ipa.Host{FQDN: newHostFQDN(t, b), Description: "x"})
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractHostDisable pins Q157: only a host with a keytab can be
// disabled, and a one-time password alone does not count.
func TestContractHostDisable(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newHostFQDN(t, b)
		if _, err := b.admin.HostAdd(&ipa.Host{FQDN: fqdn}, true, true); err != nil {
			t.Fatal(err)
		}
		var ie *ipa.IpaError
		if err := b.admin.HostDisable(fqdn); !errors.As(err, &ie) || ie.Code != ipa.CodeAlreadyInactive {
			t.Errorf("disable without keytab: %v", err)
		}
		h, err := b.admin.HostShow(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if h.HasKeytab || !h.HasPassword {
			t.Errorf("host has keytab %v, password %v", h.HasKeytab, h.HasPassword)
		}
		wantIs(t, b.admin.HostDisable(newHostFQDN(t, b)), ipa.ErrNotFound)
	})
}

func TestContractHostDeleteUpdateDNS(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		zone := newZone(t, b)
		for _, updateDNS := range []bool{false, true} {
			name := "h" + randHex(t, 4)
			fqdn := name + "." + strings.TrimSuffix(zone, ".")
			if _, err := b.admin.DNSRecordAdd(zone, name, "A", "192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.admin.HostAdd(&ipa.Host{FQDN: fqdn}, true, false); err != nil {
				t.Fatal(err)
			}
			if err := b.admin.HostDelete(updateDNS, fqdn); err != nil {
				t.Fatal(err)
			}
			_, err := b.admin.DNSRecordShow(zone, name)
			if updateDNS {
				wantIs(t, err, ipa.ErrNotFound)
			} else if err != nil {
				t.Errorf("updateDNS=false removed the record: %v", err)
			}
		}
	})
}
