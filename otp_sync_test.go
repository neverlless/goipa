// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

type syncCapture struct {
	rt   http.RoundTripper
	form url.Values
}

func (c *syncCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/sync_token") {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		c.form, _ = url.ParseQuery(string(b))
	}
	return c.rt.RoundTrip(r)
}

func TestSyncOTPToken(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jdoe", ipatest.User{Password: "pw-123456"})
	tok := s.AddOTPToken(ipatest.OTPToken{Owner: "jdoe"})
	ct := &syncCapture{rt: s.HTTPClient().Transport}
	c := ipa.NewClientCustomHttp(s.Host(), s.Realm(), &http.Client{Transport: ct})

	if err := c.SyncOTPToken("jdoe", "pw-123456", "123456", "654321", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := ct.form["token"]; ok {
		t.Errorf("empty token ID was sent: %v", ct.form)
	}
	if ct.form.Get("first_code") != "123456" || ct.form.Get("second_code") != "654321" || ct.form.Get("user") != "jdoe" {
		t.Errorf("form = %v", ct.form)
	}
	if err := c.SyncOTPToken("jdoe", "pw-123456", "123456", "654321", tok.UUID); err != nil {
		t.Fatal(err)
	}
	if ct.form.Get("token") != tok.UUID {
		t.Errorf("token = %q", ct.form.Get("token"))
	}
}

func TestSyncOTPToken_InvalidCredentials(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jdoe", ipatest.User{Password: "pw-123456"})
	s.AddOTPToken(ipatest.OTPToken{Owner: "jdoe"})
	c := ipa.NewClientCustomHttp(s.Host(), s.Realm(), s.HTTPClient())
	if err := c.SyncOTPToken("jdoe", "wrong", "123456", "654321", ""); !errors.Is(err, ipa.ErrInvalidCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if err := c.SyncOTPToken("jdoe", "pw-123456", "12", "654321", ""); !errors.Is(err, ipa.ErrInvalidCredentials) {
		t.Errorf("short code: %v", err)
	}
}

func TestSyncOTPToken_Errors(t *testing.T) {
	want := map[string]string{
		"400":       "ipa: token sync failed with HTTP status code: 400",
		"error":     "ipa: token sync failed: error",
		"no header": "ipa: token sync failed: ",
	}
	for name, h := range map[string]http.HandlerFunc{
		"400":       func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad", 400) },
		"error":     func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-IPA-TokenSync-Result", "error") },
		"no header": func(w http.ResponseWriter, r *http.Request) {},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(h)
			defer srv.Close()
			hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test server
			c := ipa.NewClientCustomHttp(strings.TrimPrefix(srv.URL, "https://"), "TEST.LOCAL", hc)
			err := c.SyncOTPToken("u", "p", "123456", "654321", "")
			if err == nil || errors.Is(err, ipa.ErrInvalidCredentials) {
				t.Fatalf("err = %v", err)
			}
			if err.Error() != want[name] {
				t.Errorf("err = %q, want %q", err, want[name])
			}
		})
	}
}

func TestSyncOTPToken_Required(t *testing.T) {
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer srv.Close()
	c := ipa.NewClientCustomHttp(strings.TrimPrefix(srv.URL, "https://"), "TEST.LOCAL", srv.Client())
	for _, a := range [][4]string{{"", "p", "1", "2"}, {"u", "", "1", "2"}, {"u", "p", "", "2"}, {"u", "p", "1", ""}} {
		err := c.SyncOTPToken(a[0], a[1], a[2], a[3], "")
		if err == nil || err.Error() != "ipa: username, password and both codes are required" {
			t.Errorf("%v: err = %v", a, err)
		}
	}
	if requests != 0 {
		t.Errorf("%d requests", requests)
	}
}
