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
