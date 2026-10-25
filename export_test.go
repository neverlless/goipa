// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import "context"

func ptr(e Entry) *Entry { return &e }

// Exported shims over the unexported typed helpers, for ipa_test (the fake
// server imports this package, so an internal test cannot use it).

func ShowEntry(ctx context.Context, c *Client, method string, args []string) (*Entry, error) {
	return showEntry(ctx, c, method, args, ptr)
}

func FindTyped(ctx context.Context, c *Client, method string, args []string, o Options) ([]*Entry, error) {
	return findTyped(ctx, c, method, args, o, ptr)
}

func Members(ctx context.Context, c *Client, method string, args []string, lists map[string][]string) (*Entry, error) {
	return members(ctx, c, method, args, lists, ptr)
}
