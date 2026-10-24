// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
)

// Call runs a FreeIPA command and decodes its "result" into T, or the whole
// result object when the command sends none (whoami, hbactest). T may be
// Entry, []Entry, a struct of your own or json.RawMessage. A FreeIPA failure
// is returned as a bare *IpaError.
func Call[T any](ctx context.Context, c *Client, method string, args []string, opts Options) (T, *Result, error) {
	var out T
	res, err := c.rpc(ctx, method, args, opts)
	if err != nil {
		return out, nil, err
	}
	data := res.Result.Data
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		data = res.Result.Raw
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, res.Result, fmt.Errorf("ipa: decode %s result: %w", method, err)
	}
	return out, res.Result, nil
}

// ErrTruncated is returned by FindEntries with the entries found when the
// server cut the search short.
var ErrTruncated = errors.New("ipa: search truncated; raise sizelimit or narrow the search")

// FindEntries runs a *_find command with args as Call sends them (nil sends
// none; the search criteria is optional in FreeIPA), all: true (unless opts
// sets all) and sizelimit when it is above 0 (0 keeps the server default).
// When the server reports the result truncated it returns the entries and
// ErrTruncated. opts is not modified.
func FindEntries(ctx context.Context, c *Client, method string, args []string, opts Options, sizelimit int) ([]Entry, error) {
	o := maps.Clone(opts)
	if o == nil {
		o = Options{}
	}
	if _, ok := o["all"]; !ok {
		o["all"] = true
	}
	if sizelimit > 0 {
		o["sizelimit"] = sizelimit
	}
	entries, res, err := Call[[]Entry](ctx, c, method, args, o)
	if err != nil {
		return nil, err
	}
	if res.Truncated {
		return entries, ErrTruncated
	}
	return entries, nil
}
