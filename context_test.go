// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
)

type twinCall struct {
	name string
	call func(context.Context, *ipa.Client) error
}

func twinCalls() []twinCall {
	return []twinCall{
		{"RPCContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.RPCContext(ctx, "ping", nil, nil)
			return err
		}},
		{"PingContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PingContext(ctx)
			return err
		}},
		{"RemoteLoginContext", func(ctx context.Context, c *ipa.Client) error {
			return c.RemoteLoginContext(ctx, "bob", "pw")
		}},
		{"UserShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserShowContext(ctx, "bob")
			return err
		}},
		{"UserFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserFindContext(ctx, nil)
			return err
		}},
		{"ResetPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ResetPasswordContext(ctx, "bob")
			return err
		}},
		{"ChangePasswordContext", func(ctx context.Context, c *ipa.Client) error {
			return c.ChangePasswordContext(ctx, "bob", "old", "new", "")
		}},
		{"SetPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SetPasswordContext(ctx, "bob", "old", "new", "")
		}},
		{"SetAuthTypesContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SetAuthTypesContext(ctx, "bob", []string{"otp"})
		}},
		{"UserDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserDisableContext(ctx, "bob")
		}},
		{"UserEnableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserEnableContext(ctx, "bob")
		}},
		{"UserAddWithPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserAddWithPasswordContext(ctx, &ipa.User{Username: "bob"}, "pw")
			return err
		}},
		{"UserAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserAddContext(ctx, &ipa.User{Username: "bob"}, false)
			return err
		}},
		{"UserDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserDeleteContext(ctx, false, true, "bob")
		}},
		{"UserModContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserModContext(ctx, &ipa.User{Username: "bob"})
			return err
		}},
		{"RemoveOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.RemoveOTPTokenContext(ctx, "u")
		}},
		{"FetchOTPTokensContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.FetchOTPTokensContext(ctx, "bob")
			return err
		}},
		{"AddOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AddOTPTokenContext(ctx, nil)
			return err
		}},
		{"EnableOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.EnableOTPTokenContext(ctx, "u")
		}},
		{"DisableOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DisableOTPTokenContext(ctx, "u")
		}},
		{"GroupShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupShowContext(ctx, "g")
			return err
		}},
		{"GroupFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupFindContext(ctx, nil)
			return err
		}},
	}
}

func TestContextCancelReachesTransport(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"summary":"ok"}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range twinCalls() {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(ctx, c); !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}

// Methods that do no network I/O, or cannot honour ctx (gokrb5).
var noTwin = map[string]bool{"Host": true, "Realm": true, "SessionID": true, "SetSessionID": true,
	"ClearSession": true, "StickySession": true, "Login": true, "LoginWithKeytab": true, "LoginFromCCache": true}

func TestEveryMethodHasContextTwin(t *testing.T) {
	typ := reflect.TypeFor[*ipa.Client]()
	rows := map[string]bool{}
	for _, tc := range twinCalls() {
		rows[tc.name] = true
	}
	for m := range typ.Methods() {
		if strings.HasSuffix(m.Name, "Context") {
			if !rows[m.Name] {
				t.Errorf("%s has no row in twinCalls", m.Name)
			}
		} else if _, ok := typ.MethodByName(m.Name + "Context"); !ok && !noTwin[m.Name] {
			t.Errorf("%s has no Context twin", m.Name)
		}
	}
}
