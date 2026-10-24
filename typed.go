// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"
	"slices"
)

// takesOption reports whether the command catalogue lists opt for method.
func takesOption(method, opt string) bool {
	cmd, _ := LookupCommand(method, "")
	return slices.ContainsFunc(cmd.Options, func(p Param) bool { return p.Name == opt })
}

// showEntry runs a *_show command with all: true and, where the command has
// it, no_members: false so the result carries every attribute and the member
// lists. Validating servers reject no_members on commands that lack it.
func showEntry[T any](ctx context.Context, c *Client, method string, args []string, conv func(Entry) *T) (*T, error) {
	o := Options{"all": true}
	if takesOption(method, "no_members") {
		o["no_members"] = false
	}
	e, _, err := Call[Entry](ctx, c, method, args, o)
	if err != nil {
		return nil, err
	}
	return conv(e), nil
}

// findTyped runs a *_find command; options is copied, and all and no_members
// (where the command has it) default to true and false unless the caller set
// them. The server's
// truncation comes back as ErrTruncated next to the converted entries.
func findTyped[T any](ctx context.Context, c *Client, method string, args []string, options Options, conv func(Entry) *T) ([]*T, error) {
	o := maps.Clone(options)
	if o == nil {
		o = Options{}
	}
	if _, ok := o["no_members"]; !ok && takesOption(method, "no_members") {
		o["no_members"] = false
	}
	entries, err := FindEntries(ctx, c, method, args, o, 0)
	if err != nil && !errors.Is(err, ErrTruncated) {
		return nil, err
	}
	out := make([]*T, len(entries))
	for i, e := range entries {
		out[i] = conv(e)
	}
	return out, err
}

// memberEntry runs an <x>_add_member / _remove_member style command. FreeIPA
// reports members it could not change in the result, not as an error, so those
// come back as *MemberError together with the updated entry.
func (c *Client) memberEntry(ctx context.Context, method string, args []string, lists map[string][]string) (Entry, error) {
	o := Options{"all": true, "no_members": false}
	n := 0
	for k, v := range lists {
		if len(v) > 0 {
			o[k] = v
			n++
		}
	}
	if n == 0 {
		return Entry{}, errors.New("ipa: " + method + ": nothing to add or remove")
	}
	e, res, err := Call[Entry](ctx, c, method, args, o)
	if err != nil {
		return Entry{}, err
	}
	if f := parseMemberFailures(res.Failed); len(f) > 0 {
		return e, &MemberError{Failures: f}
	}
	return e, nil
}
