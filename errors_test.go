// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestIpaErrorFields(t *testing.T) {
	c, _ := newFakeIPA(t, http.StatusOK, errorBody(4001, "NotFound", "bob: user not found"))
	_, err := c.RPC("user_show", []string{"bob"}, nil)
	var ierr *ipa.IpaError
	if !errors.As(err, &ierr) {
		t.Fatalf("err = %v, want *IpaError", err)
	}
	if ierr.Code != 4001 || ierr.Name != "NotFound" || ierr.Message != "bob: user not found" {
		t.Errorf("got %+v", ierr)
	}
	if got := ierr.Data; got != `{"reason":"bob: user not found"}` {
		t.Errorf("Data = %s", got)
	}
}

func TestIpaErrorIs(t *testing.T) {
	sentinels := []*ipa.IpaError{ipa.ErrNotFound, ipa.ErrDuplicateEntry, ipa.ErrACI, ipa.ErrEmptyModlist}
	for i, code := range []int{4001, 4002, 2100, 4202} {
		c, _ := newFakeIPA(t, http.StatusOK, errorBody(code, "X", "m"))
		_, err := c.RPC("user_show", nil, nil)
		for j, s := range sentinels {
			if got := errors.Is(err, s); got != (i == j) {
				t.Errorf("code %d Is sentinel %d = %v", code, j, got)
			}
		}
		if errors.Is(err, ipa.ErrUnauthorized) {
			t.Errorf("code %d matches ErrUnauthorized", code)
		}
		var nilErr *ipa.IpaError
		if errors.Is(err, nilErr) || errors.Is(nilErr, ipa.ErrNotFound) {
			t.Errorf("code %d matches a nil *IpaError", code)
		}
	}
}

func TestIpaErrorReturnedBare(t *testing.T) {
	c, _ := newFakeIPA(t, http.StatusOK, errorBody(4001, "NotFound", "m"))
	_, err := c.RPC("user_show", []string{"bob"}, nil)
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("RPC err is %T", err)
	}
	_, err = c.UserShow("bob")
	if _, ok := err.(*ipa.IpaError); !ok {
		t.Errorf("UserShow err is %T", err)
	}
}

func TestUserAddDuplicateStillErrUserExists(t *testing.T) {
	c, _ := newFakeIPA(t, http.StatusOK, errorBody(4002, "DuplicateEntry", `user with name "bob" already exists`))
	_, err := c.UserAdd(&ipa.User{Username: "bob"}, false)
	if err != ipa.ErrUserExists {
		t.Errorf("err = %v, want ErrUserExists", err)
	}
}

func TestUserModEmptyModlist(t *testing.T) {
	c, _ := newFakeIPA(t, http.StatusOK, errorBody(4202, "EmptyModlist", "no modifications to be performed"))
	u := &ipa.User{Username: "bob"}
	got, err := c.UserMod(u)
	if err != nil || got != u {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestRPCHTTPError(t *testing.T) {
	c, _ := newFakeIPA(t, http.StatusServiceUnavailable, "busy")
	_, err := c.RPC("ping", nil, nil)
	var herr *ipa.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("err = %v, want *HTTPError", err)
	}
	if herr.StatusCode != 503 || herr.Status != "503 Service Unavailable" {
		t.Errorf("got %+v", herr)
	}
	if errors.Is(err, ipa.ErrUnauthorized) {
		t.Error("503 must not match ErrUnauthorized")
	}
	if want := "IPA RPC called failed with HTTP status code: 503"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestRPCExpiredSession401(t *testing.T) {
	c, f := newFakeIPA(t, http.StatusUnauthorized, "")
	c.SetSessionID("MagBearerToken=x")
	_, err := c.RPC("ping", nil, nil)
	if got := f.Calls()[0].Path; got != "/ipa/session/json" {
		t.Errorf("path = %q, want /ipa/session/json", got)
	}
	if !errors.Is(err, ipa.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
	var herr *ipa.HTTPError
	if !errors.As(err, &herr) || herr.StatusCode != 401 {
		t.Errorf("err = %v, want *HTTPError 401", err)
	}
}

func TestIpaErrorMarshalJSON(t *testing.T) {
	for _, in := range []ipa.IpaError{
		{Code: 4001, Name: "NotFound", Message: "bob: user not found", Data: `{"reason":"bob: user not found"}`},
		{Code: 905, Name: "CommandError", Message: "unknown command 'x'"},
	} {
		b, err := json.Marshal(&in)
		if err != nil {
			t.Fatal(err)
		}
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(b, &shape); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"code", "message", "name", "data"} {
			if _, ok := shape[k]; !ok {
				t.Errorf("%s: key %q missing", b, k)
			}
		}
		var out ipa.IpaError
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		want := in
		if want.Data == "" {
			want.Data = "{}"
		}
		if out != want {
			t.Errorf("round trip: got %+v, want %+v", out, want)
		}
	}
}

func TestIpaErrorMarshalJSONInvalidData(t *testing.T) {
	b, err := json.Marshal(&ipa.IpaError{Code: 4001, Message: "m", Data: "not json"})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Data json.RawMessage }
	if err := json.Unmarshal(b, &out); err != nil || string(out.Data) != "{}" {
		t.Errorf("got %s, %v", b, err)
	}
}
