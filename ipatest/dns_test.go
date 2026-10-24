// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestDNS_Errors(t *testing.T) {
	c := ipatest.NewServer(t).ClientAs("admin")
	rpc(t, c, "dnsrecord_add", []string{"test.local", "www"}, ipa.Options{"arecord": "192.0.2.1"})
	for _, tc := range []struct {
		method string
		args   []string
		opts   ipa.Options
		code   int
	}{
		{"dnszone_show", nil, nil, ipa.CodeRequirement},
		{"dnszone_add", []string{"test.local"}, nil, ipa.CodeDuplicateEntry},
		{"dnszone_del", []string{"test.local.", "nosuch.test."}, nil, ipa.CodeNotFound},
		{"dnszone_disable", []string{"nosuch.test"}, nil, ipa.CodeNotFound},
		{"dnsrecord_show", []string{"test.local."}, nil, ipa.CodeRequirement},
		{"dnsrecord_show", []string{"test.local.", "nosuch"}, nil, ipa.CodeNotFound},
		{"dnsrecord_find", []string{"nosuch.test."}, nil, ipa.CodeNotFound},
		{"dnsrecord_add", []string{"test.local.", "www"}, nil, ipa.CodeOption},
		{"dnsrecord_add", []string{"test.local.", "www"}, ipa.Options{"arecord": "192.0.2.1"}, ipa.CodeEmptyModlist},
		{"dnsrecord_del", []string{"test.local.", "nosuch"}, ipa.Options{"del_all": true}, ipa.CodeNotFound},
		{"dnsrecord_del", []string{"test.local.", "www"}, nil, ipa.CodeOption},
		{"dnsrecord_del", []string{"test.local.", "www"}, ipa.Options{"arecord": "192.0.2.9"}, ipa.CodeAttrValueNotFound},
	} {
		_, err := c.RPC(tc.method, tc.args, tc.opts)
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != tc.code {
			t.Errorf("%s %v %v: got %v, want %d", tc.method, tc.args, tc.opts, err, tc.code)
		}
	}
	// test.local. survived the failed multi-delete.
	rpc(t, c, "dnszone_show", []string{"test.local."}, nil)
}

func TestDNS_FindAndApex(t *testing.T) {
	c := ipatest.NewServer(t).ClientAs("admin")
	zones, err := c.DNSZoneFind(ipa.Options{"idnsname": "test.local"})
	if err != nil || len(zones) != 1 || !zones[0].Active || zones[0].NameServer != "ipa.test.local." {
		t.Fatalf("zones %+v, err %v", zones, err)
	}
	if _, err := c.DNSRecordAdd("test.local.", "test.local.", "A", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	recs, err := c.DNSRecordFind("test.local.", ipa.Options{"idnsname": "@"})
	if err != nil || len(recs) != 1 || len(recs[0].Records["NS"]) != 1 || len(recs[0].Records["A"]) != 1 {
		t.Fatalf("records %+v, err %v", recs, err)
	}
	if err := c.DNSRecordRemove("test.local.", "ipa", "A", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DNSRecordShow("test.local.", "ipa"); !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound after the last value went", err)
	}
}
