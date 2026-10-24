// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

func TestEntry_Forms(t *testing.T) {
	var e ipa.Entry
	in := `{"a":["x","y"],"s":"one","n":null,"b":["TRUE"],"b2":true,"i":["42"],"i2":7,"t":[{"__datetime__":"20261024120000Z"}],"t2":"2026-10-24T12:00:00Z","bin":[{"__base64__":"aGk="}],"a.b":["dot"]}`
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	if got := e.Strs("a"); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Errorf("Strs(a) = %v", got)
	}
	if e.Str("a") != "x" || e.DN("a") != "x" || e.Str("missing") != "" {
		t.Error("Str")
	}
	if got := e.Strs("s"); !reflect.DeepEqual(got, []string{"one"}) {
		t.Errorf("Strs(s) = %v", got)
	}
	if e.Strs("n") != nil || e.Strs("missing") != nil {
		t.Error("Strs of null/missing must be nil")
	}
	if !e.Bool("b") || !e.Bool("b2") || e.Bool("missing") {
		t.Error("Bool")
	}
	for attr, want := range map[string]int64{"i": 42, "i2": 7} {
		if n, ok := e.Int(attr); !ok || n != want {
			t.Errorf("Int(%s) = %d, %v", attr, n, ok)
		}
	}
	if n, ok := e.Int("missing"); ok || n != 0 {
		t.Error("Int(missing)")
	}
	if _, ok := e.Int("s"); ok {
		t.Error("Int(s) must fail")
	}
	want := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if !e.Time("t").Equal(want) || !e.Time("t2").Equal(want) || !e.Time("s").IsZero() {
		t.Errorf("Time: %v %v", e.Time("t"), e.Time("t2"))
	}
	if string(e.Bytes("bin")) != "hi" || e.Bytes("s") != nil {
		t.Error("Bytes")
	}
	if !e.Has("n") || e.Has("missing") || !e.Has("a.b") || e.Str("a.b") != "dot" {
		t.Error("Has / dotted attr")
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal([]byte(in), &a)
	_ = json.Unmarshal(out, &b)
	if !reflect.DeepEqual(a, b) || string(e.Raw()) != in {
		t.Errorf("round trip: %s", out)
	}
}

func TestEntry_DNSName(t *testing.T) {
	var e ipa.Entry
	in := `{"idnsname":[{"__dns_name__":"example.test."}],"one":{"__dns_name__":"a.test."},"many":[{"__dns_name__":"x."},"y."]}`
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	if e.Str("idnsname") != "example.test." || e.DN("one") != "a.test." {
		t.Error("Str")
	}
	if got := e.Strs("idnsname"); !reflect.DeepEqual(got, []string{"example.test."}) {
		t.Errorf("Strs = %v", got)
	}
	if got := e.Strs("one"); !reflect.DeepEqual(got, []string{"a.test."}) {
		t.Errorf("Strs(one) = %v", got)
	}
	if got := e.Strs("many"); !reflect.DeepEqual(got, []string{"x.", "y."}) {
		t.Errorf("Strs(many) = %v", got)
	}
}

func TestEntry_StrsObject(t *testing.T) {
	var e ipa.Entry
	in := `{"hint":{"__dns_name__":"a.test.","x":"b"},"obj":{"k":"v","n":1}}`
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	if got := e.Strs("hint"); !reflect.DeepEqual(got, []string{"a.test."}) {
		t.Errorf("Strs(hint) = %v", got)
	}
	if got := e.Strs("obj"); !reflect.DeepEqual(got, []string{`{"k":"v","n":1}`}) {
		t.Errorf("Strs(obj) = %v", got)
	}
}
