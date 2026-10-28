// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestHostFind_HidesMembersByDefault(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHost("h.test.local", ipatest.Host{HostGroups: []string{"hg"}})
	c := s.ClientAs("admin")
	for _, tc := range []struct {
		opts ipa.Options
		want bool
	}{{nil, false}, {ipa.Options{"no_members": false}, true}, {ipa.Options{"all": true}, true}} {
		opts := ipa.Options{"fqdn": "h.test.local"}
		for k, v := range tc.opts {
			opts[k] = v
		}
		var recs []map[string]any
		if err := json.Unmarshal(rpc(t, c, "host_find", nil, opts).Result.Data, &recs); err != nil {
			t.Fatal(err)
		}
		if _, has := recs[0]["memberof_hostgroup"]; has != tc.want {
			t.Errorf("opts %v: memberof_hostgroup present = %v", tc.opts, has)
		}
	}
}

func TestHostShow_Shape(t *testing.T) {
	s := ipatest.NewServer(t)
	var rec map[string]any
	if err := json.Unmarshal(rpc(t, s.ClientAs("admin"), "host_show", []string{"ipa.test.local"}, nil).Result.Data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec["has_keytab"] != true || rec["has_password"] != false {
		t.Errorf("has_keytab/has_password = %v/%v", rec["has_keytab"], rec["has_password"])
	}
	if p, _ := rec["krbprincipalname"].([]any); len(p) != 1 || p[0] != "host/ipa.test.local@TEST.LOCAL" {
		t.Errorf("krbprincipalname = %v", rec["krbprincipalname"])
	}
}

func TestHostShow_NotFound(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("host_show", []string{"nope.test.local"}, nil)
	if !errors.Is(err, ipa.ErrNotFound) || !strings.Contains(err.Error(), "nope.test.local: host not found") {
		t.Errorf("err = %v", err)
	}
}

func TestHostMod_UnmodelledOption(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("host_mod", []string{"ipa.test.local"}, ipa.Options{"ipasshpubkey": "k"})
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeCommand || !strings.Contains(ie.Message, "ipasshpubkey") {
		t.Errorf("err = %v", err)
	}
}

func TestHostAdd_RandomPasswordShape(t *testing.T) {
	s := ipatest.NewServer(t)
	var rec map[string]any
	res := rpc(t, s.ClientAs("admin"), "host_add", []string{"n.test.local"}, ipa.Options{"random": true, "force": true})
	if err := json.Unmarshal(res.Result.Data, &rec); err != nil {
		t.Fatal(err)
	}
	if p, _ := rec["randompassword"].(string); p == "" || rec["has_password"] != true {
		t.Errorf("randompassword/has_password = %v/%v", rec["randompassword"], rec["has_password"])
	}
}

func TestHostDel_UpdateDNSOnlyWhenAsked(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.AddHost("w.test.local", ipatest.Host{})
	rpc(t, c, "dnsrecord_add", []string{"test.local.", "w"}, ipa.Options{"arecord": "192.0.2.1"})
	rpc(t, c, "host_del", []string{"w.test.local"}, nil)
	rpc(t, c, "dnsrecord_show", []string{"test.local.", "w"}, nil)
	s.AddHost("w.test.local", ipatest.Host{})
	rpc(t, c, "host_del", []string{"w.test.local"}, ipa.Options{"updatedns": true})
	if _, err := c.RPC("dnsrecord_show", []string{"test.local.", "w"}, nil); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}
