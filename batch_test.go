// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestBatch(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1")
	if _, err := c.GroupAdd(&ipa.Group{Name: "g1"}); err != nil {
		t.Fatal(err)
	}
	before := len(s.Calls())
	rs, err := c.Batch(context.Background(),
		ipa.BatchCall{Method: "user_show", Args: []string{"u1"}},
		ipa.BatchCall{Method: "group_show", Args: []string{"g1"}, Options: ipa.Options{"all": true}})
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v, %v", rs, err)
	}
	for i, r := range rs {
		if r.Result == nil || r.Err != nil {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	e := ipa.Entry{}
	if err := json.Unmarshal(rs[0].Result.Data, &e); err != nil || e.Str("uid") != "u1" {
		t.Errorf("user_show data %s, %v", rs[0].Result.Data, err)
	}
	var got []string
	for _, call := range s.Calls()[before:] {
		got = append(got, call.Method)
	}
	if want := []string{"batch", "user_show", "group_show"}; !reflect.DeepEqual(got, want) {
		t.Errorf("calls %v, want %v", got, want)
	}
}

func TestBatch_Wire(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"count":2,"results":[{"result":{},"error":null},{"result":{},"error":null}]}`))
	if _, err := c.Batch(context.Background(),
		ipa.BatchCall{Method: "user_show", Args: []string{"u1"}},
		ipa.BatchCall{Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Method != "batch" {
		t.Fatalf("calls %+v", calls)
	}
	var methods []map[string]any
	if err := json.Unmarshal(calls[0].Args, &methods); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"method": "user_show", "params": []any{[]any{"u1"}, map[string]any{}}},
		{"method": "ping", "params": []any{[]any{}, map[string]any{}}},
	}
	if !reflect.DeepEqual(methods, want) {
		t.Errorf("methods %v, want %v", methods, want)
	}
	if calls[0].Options["version"] != ipa.IpaClientVersion {
		t.Errorf("outer options %v", calls[0].Options)
	}
}

func TestBatch_MiddleFails(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	addUsers(t, c, "u1", "u2")
	rs, err := c.Batch(context.Background(),
		ipa.BatchCall{Method: "user_show", Args: []string{"u1"}},
		ipa.BatchCall{Method: "user_show", Args: []string{"ghost"}},
		ipa.BatchCall{Method: "user_show", Args: []string{"u2"}})
	if err != nil || len(rs) != 3 {
		t.Fatalf("%v, %v", rs, err)
	}
	if rs[0].Result == nil || rs[2].Result == nil || rs[0].Err != nil || rs[2].Err != nil {
		t.Errorf("ok results: %+v %+v", rs[0], rs[2])
	}
	if e := rs[1].Err; rs[1].Result != nil || e == nil || e.Code != ipa.CodeNotFound || e.Name != "NotFound" || e.Message == "" || !json.Valid([]byte(e.Data)) {
		t.Errorf("failed result: %+v %+v", rs[1], rs[1].Err)
	}
}

func TestBatch_ErrorKw(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{"count":1,"results":[{"error":"'method' is required","error_code":3007,"error_name":"RequirementError","error_kw":{"name":"method"}}]}`))
	rs, err := c.Batch(context.Background(), ipa.BatchCall{Method: "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := ipa.IpaError{Message: "'method' is required", Code: 3007, Name: "RequirementError", Data: `{"name":"method"}`}
	if rs[0].Err == nil || *rs[0].Err != want {
		t.Errorf("err %+v", rs[0].Err)
	}
}

func TestBatch_Empty(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.Batch(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d requests", n)
	}
}

func TestBatch_CountMismatch(t *testing.T) {
	s := ipatest.NewServer(t)
	s.Handle("batch", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"count": 1, "results": []any{map[string]any{"result": map[string]any{}, "error": nil}}}, nil
	})
	rs, err := s.ClientAs("admin").Batch(context.Background(),
		ipa.BatchCall{Method: "ping"}, ipa.BatchCall{Method: "ping"})
	if err == nil || rs != nil {
		t.Fatalf("%v, %v", rs, err)
	}
}

func TestBatch_WholeFailure(t *testing.T) {
	c, _ := newFakeIPA(t, 200, errorBody(ipa.CodeACI, "ACIError", "denied"))
	rs, err := c.Batch(context.Background(), ipa.BatchCall{Method: "ping"})
	if ie, ok := err.(*ipa.IpaError); !ok || ie.Code != ipa.CodeACI || rs != nil {
		t.Fatalf("%v, %#v", rs, err)
	}
}

func TestBatch_DoesNotModifyOptions(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{"count":1,"results":[{"result":{},"error":null}]}`))
	opts := ipa.Options{"all": true}
	if _, err := c.Batch(context.Background(), ipa.BatchCall{Method: "user_show", Args: []string{"u1"}, Options: opts}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, ipa.Options{"all": true}) {
		t.Errorf("options changed: %v", opts)
	}
}
