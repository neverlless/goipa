// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
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
