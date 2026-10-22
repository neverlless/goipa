// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/http"
	"sync"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestRPCUsesClientTLSPool(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{"summary":"IPA server version 4.13.4"}`))
	// system roots must not trust httptest's CA, or the test proves nothing
	if _, err := http.Post("https://"+c.Host()+"/ipa/json", "application/json", nil); err == nil {
		t.Fatal("system roots unexpectedly trust the test CA")
	}
	res, err := c.RPC("ping", nil, nil)
	if err != nil {
		t.Fatalf("RPC: %v", err)
	}
	if res.Result == nil || res.Result.Summary != "IPA server version 4.13.4" {
		t.Errorf("Result = %+v", res.Result)
	}
}

func TestRPCRequestShape(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.RPC("user_show", []string{"bob"}, ipa.Options{"all": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RPC("ping", nil, nil); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("got %d calls", len(calls))
	}
	if g := calls[0]; g.Path != "/ipa/json" || g.Method != "user_show" || string(g.Args) != `["bob"]` ||
		g.Options["all"] != true || g.Options["version"] != ipa.IpaClientVersion {
		t.Errorf("call 0 = %+v", g)
	}
	if g := string(calls[1].Args); g != `[]` {
		t.Errorf("nil args sent as %s, want []", g)
	}
}

func TestRPCVersionOverride(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.RPC("ping", nil, ipa.Options{"version": "2.251"}); err != nil {
		t.Fatal(err)
	}
	if v := f.Calls()[0].Options["version"]; v != "2.251" {
		t.Errorf("version = %v", v)
	}
}

func TestRPCDoesNotModifyOptions(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{}`))
	opts := ipa.Options{"all": true}
	if _, err := c.RPC("user_show", []string{"bob"}, opts); err != nil {
		t.Fatal(err)
	}
	if _, ok := opts["version"]; ok || len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
}

func TestUserFindDoesNotModifyOptions(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"result":[],"count":0,"truncated":false,"summary":"0 users matched"}`))
	opts := ipa.Options{"sizelimit": 5}
	if _, err := c.UserFind(opts); err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
	o := f.Calls()[0].Options
	if o["all"] != true || o["no_members"] != false || o["sizelimit"] != float64(5) {
		t.Errorf("sent options = %v", o)
	}
}

// Run with -race.
func TestRPCSharedOptionsConcurrent(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{"result":[]}`))
	shared := ipa.Options{"sizelimit": 5}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := c.RPC("ping", nil, shared); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := c.UserFind(shared); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(shared) != 1 {
		t.Errorf("shared options modified: %v", shared)
	}
}
