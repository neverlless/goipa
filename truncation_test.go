// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// truncFinds seeds two entries of every kind and returns the eight Finds
// asking for one. FetchOTPTokens takes no options, so the fake answers it
// with a truncated result.
func truncFinds(s *ipatest.Server, limit int) map[string]func(c *ipa.Client) (int, error) {
	for _, u := range []string{"ua", "ub"} {
		s.AddUser(u, ipatest.User{})
		s.AddStageUser(u+"s", ipatest.User{})
		s.AddSubID(ipatest.SubID{Owner: u})
		s.AddGroup("g"+u, ipatest.Group{})
		s.AddHost(u+".test.local", ipatest.Host{})
		s.AddHBACRule("h"+u, ipatest.HBACRule{})
		s.AddSudoRule("s"+u, ipatest.SudoRule{})
	}
	s.AddOTPToken(ipatest.OTPToken{Owner: "ua"})
	s.AddOTPToken(ipatest.OTPToken{Owner: "ua"})
	s.Handle("otptoken_find", func(c ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": []map[string]any{}, "count": 0, "truncated": true, "summary": ""}, nil
	})
	o := ipa.Options{"sizelimit": limit}
	return map[string]func(*ipa.Client) (int, error){
		"UserFind": func(c *ipa.Client) (int, error) { r, err := c.UserFind(o); return len(r), err },
		"GroupFind": func(c *ipa.Client) (int, error) {
			r, err := c.GroupFind(o)
			return len(r), err
		},
		"HostFind":      func(c *ipa.Client) (int, error) { r, err := c.HostFind(o); return len(r), err },
		"StageUserFind": func(c *ipa.Client) (int, error) { r, err := c.StageUserFind(o); return len(r), err },
		"SubIDFind":     func(c *ipa.Client) (int, error) { r, err := c.SubIDFind(o); return len(r), err },
		"HBACRuleFind":  func(c *ipa.Client) (int, error) { r, err := c.HBACRuleFind(o); return len(r), err },
		"SudoRuleFind":  func(c *ipa.Client) (int, error) { r, err := c.SudoRuleFind(o); return len(r), err },
		"FetchOTPTokens": func(c *ipa.Client) (int, error) {
			r, err := c.FetchOTPTokens("ua")
			return len(r), err
		},
	}
}

func truncClient(t *testing.T, s *ipatest.Server, opts ...ipa.Option) *ipa.Client {
	t.Helper()
	opts = append([]ipa.Option{ipa.WithHost(s.Host()), ipa.WithRealm(s.Realm()), ipa.WithHTTPClient(s.HTTPClient())}, opts...)
	c, err := ipa.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	c.SetSessionID(s.Session("admin"))
	return c
}

func TestTruncation_DefaultSilent(t *testing.T) {
	s := ipatest.NewServer(t)
	finds := truncFinds(s, 1)
	c := truncClient(t, s)
	for name, f := range finds {
		n, err := f(c)
		if err != nil {
			t.Errorf("%s: err = %v", name, err)
		}
		if want := 1; name != "FetchOTPTokens" && n != want {
			t.Errorf("%s: %d entries", name, n)
		}
	}
}

func TestTruncation_OptIn(t *testing.T) {
	s := ipatest.NewServer(t)
	finds := truncFinds(s, 1)
	c := truncClient(t, s, ipa.WithTruncationErrors())
	for name, f := range finds {
		n, err := f(c)
		if !errors.Is(err, ipa.ErrTruncated) {
			t.Errorf("%s: err = %v", name, err)
		}
		if want := 1; name != "FetchOTPTokens" && n != want {
			t.Errorf("%s: %d entries", name, n)
		}
	}
}

func TestTruncation_NotTruncated(t *testing.T) {
	s := ipatest.NewServer(t)
	finds := truncFinds(s, 10)
	s.Handle("otptoken_find", nil)
	c := truncClient(t, s, ipa.WithTruncationErrors())
	for name, f := range finds {
		if _, err := f(c); err != nil {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
