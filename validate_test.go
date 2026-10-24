// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func validatingClient(t *testing.T, s *ipatest.Server) *ipa.Client {
	t.Helper()
	c, err := ipa.New(ipa.WithHost(s.Host()), ipa.WithRealm(s.Realm()), ipa.WithHTTPClient(s.HTTPClient()), ipa.WithValidation())
	if err != nil {
		t.Fatal(err)
	}
	c.SetSessionID(s.Session("admin"))
	return c
}

func sent(s *ipatest.Server, method string) *ipatest.Call {
	for _, c := range s.Calls() {
		if c.Method == method {
			return &c
		}
	}
	return nil
}

func ping(t *testing.T, c *ipa.Client) {
	t.Helper()
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestValidation_UnknownCommand(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.RPC("user_shwo", []string{"admin"}, nil)
	wantIs(t, err, ipa.ErrInvalidCall)
	if len(s.Calls()) != 0 {
		t.Errorf("sent %v", s.Calls())
	}
}

func TestValidation_UnknownOption(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.RPC("user_show", []string{"admin"}, ipa.Options{"no_members": true, "bogus": 1})
	wantIs(t, err, ipa.ErrInvalidCall)
	if !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("message %q", err)
	}
	if len(s.Calls()) != 0 {
		t.Errorf("sent %v", s.Calls())
	}
}

// FreeIPA takes an argument by name in the options; ChangePassword sends
// passwd's current_password that way.
func TestValidation_ArgAsOption(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.RPC("passwd", []string{"u", "new"}, ipa.Options{"current_password": "old"})
	if errors.Is(err, ipa.ErrInvalidCall) || sent(s, "passwd") == nil {
		t.Fatal(err)
	}
}

func TestValidation_TooManyArgs(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.RPC("user_show", []string{"a", "b"}, nil)
	wantIs(t, err, ipa.ErrInvalidCall)

	del, ok := ipa.LookupCommand("user_del", "")
	if !ok || len(del.Args) != 1 {
		t.Fatalf("user_del %+v", del)
	}
	_, err = c.RPC("user_del", []string{"a", "b"}, nil)
	if got := errors.Is(err, ipa.ErrInvalidCall); got == del.Args[0].Multi {
		t.Errorf("user_del Multi=%v, got error %v", del.Args[0].Multi, err)
	}
}

// olderOption finds a command present in 4.9.0 with an option added later.
func olderOption(t *testing.T) (method, option, since string) {
	t.Helper()
	for _, cmd := range ipa.Commands("") {
		if cmd.Since != "4.9.0" {
			continue
		}
		for _, o := range cmd.Options {
			if o.Since != "4.9.0" {
				return cmd.Name, o.Name, o.Since
			}
		}
	}
	t.Fatal("no option added after 4.9.0")
	return
}

func TestValidation_NotSupported(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	s.SetVersion("4.9.6")
	ping(t, c)
	_, err := c.RPC("subid_find", nil, nil)
	wantIs(t, err, ipa.ErrNotSupported)
	if sent(s, "subid_find") != nil {
		t.Error("subid_find was sent")
	}

	method, option, _ := olderOption(t)
	s.SetVersion("4.9.0")
	ping(t, c)
	_, err = c.RPC(method, nil, ipa.Options{option: true})
	wantIs(t, err, ipa.ErrNotSupported)
	if sent(s, method) != nil {
		t.Errorf("%s was sent", method)
	}
}

func TestValidation_UnknownVersion(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.RPC("user_shwo", nil, nil)
	wantIs(t, err, ipa.ErrInvalidCall)

	// Before the version is known nothing is too new; the server decides.
	_, err = c.RPC("passkeyconfig_show", nil, nil)
	if errors.Is(err, ipa.ErrNotSupported) || errors.Is(err, ipa.ErrInvalidCall) {
		t.Fatal(err)
	}
	if sent(s, "passkeyconfig_show") == nil {
		t.Error("passkeyconfig_show was not sent")
	}
}

func TestValidation_NewerServerSkips(t *testing.T) {
	for _, v := range []string{"4.13.5", "4.14.0", "4.13.5.dev1"} {
		t.Run(v, func(t *testing.T) {
			s := ipatest.NewServer(t)
			c := validatingClient(t, s)
			s.SetVersion(v)
			ping(t, c)
			_, err := c.RPC("newthing_show", nil, nil)
			if errors.Is(err, ipa.ErrInvalidCall) || sent(s, "newthing_show") == nil {
				t.Errorf("newthing_show: %v", err)
			}
			_, err = c.RPC("user_show", []string{"admin"}, ipa.Options{"newopt": true})
			if errors.Is(err, ipa.ErrInvalidCall) || sent(s, "user_show") == nil {
				t.Errorf("user_show: %v", err)
			}
		})
	}
}

func TestValidation_OffByDefault(t *testing.T) {
	s := ipatest.NewServer(t)
	c, err := ipa.New(ipa.WithHost(s.Host()), ipa.WithRealm(s.Realm()), ipa.WithHTTPClient(s.HTTPClient()))
	if err != nil {
		t.Fatal(err)
	}
	c.SetSessionID(s.Session("admin"))
	for _, c := range []*ipa.Client{c, s.ClientAs("admin")} {
		_, err := c.RPC("user_show", []string{"admin"}, ipa.Options{"bogus": 1})
		if errors.Is(err, ipa.ErrInvalidCall) {
			t.Fatal(err)
		}
	}
	n := 0
	for _, call := range s.Calls() {
		if call.Method == "user_show" && call.Options["bogus"] != nil {
			n++
		}
	}
	if n != 2 {
		t.Errorf("sent %d user_show calls with bogus, want 2", n)
	}
}

func TestValidation_BatchInner(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	_, err := c.Batch(context.Background(),
		ipa.BatchCall{Method: "user_show", Args: []string{"admin"}},
		ipa.BatchCall{Method: "user_show", Args: []string{"admin"}, Options: ipa.Options{"bogus": 1}},
	)
	wantIs(t, err, ipa.ErrInvalidCall)
	if !strings.Contains(err.Error(), "batch call 1") {
		t.Errorf("message %q", err)
	}
	if len(s.Calls()) != 0 {
		t.Errorf("sent %v", s.Calls())
	}

	if _, err := c.Batch(context.Background(), ipa.BatchCall{Method: "user_show", Args: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
}

func TestValidation_TypedCalls(t *testing.T) {
	s := ipatest.NewServer(t)
	c := validatingClient(t, s)
	ctx := context.Background()
	_, _, err := ipa.Call[ipa.Entry](ctx, c, "user_show", []string{"admin"}, ipa.Options{"bogus": 1})
	wantIs(t, err, ipa.ErrInvalidCall)
	_, err = ipa.FindEntries(ctx, c, "user_find", nil, ipa.Options{"bogus": 1}, 0)
	wantIs(t, err, ipa.ErrInvalidCall)
	if len(s.Calls()) != 0 {
		t.Errorf("sent %v", s.Calls())
	}
	// ipatest has no admin user: not found means the call was sent.
	_, _, err = ipa.Call[ipa.Entry](ctx, c, "user_show", []string{"admin"}, ipa.Options{"all": true})
	wantIs(t, err, ipa.ErrNotFound)
}
