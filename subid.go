// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"maps"

	"github.com/tidwall/gjson"
)

// SubID is a subordinate UID/GID range of a user.
type SubID struct {
	// ipauniqueid, ipaowner, description
	ID, Owner, Description string
	// ipasubuidnumber, ipasubuidcount
	UIDStart, UIDCount int64
	// ipasubgidnumber, ipasubgidcount
	GIDStart, GIDCount int64
}

func subIDFrom(res gjson.Result) *SubID {
	return &SubID{
		ID:          res.Get("ipauniqueid.0").String(),
		Owner:       res.Get("ipaowner.0").String(),
		Description: res.Get("description.0").String(),
		UIDStart:    res.Get("ipasubuidnumber.0").Int(),
		UIDCount:    res.Get("ipasubuidcount.0").Int(),
		GIDStart:    res.Get("ipasubgidnumber.0").Int(),
		GIDCount:    res.Get("ipasubgidcount.0").Int(),
	}
}

// SubIDFind finds sub-ID ranges with `subid_find`; options are passed through
// (e.g. `ipaowner`). Any authenticated user may read sub-IDs. FreeIPA 4.9.7+;
// ErrNotSupported when the server version is known to be older.
//
// A truncated search is not reported unless the Client was built
// WithTruncationErrors; FindEntries reports it too.
func (c *Client) SubIDFind(options Options) ([]*SubID, error) {
	return c.SubIDFindContext(context.Background(), options)
}

// SubIDFindContext is like SubIDFind but bounds the request with ctx.
func (c *Client) SubIDFindContext(ctx context.Context, options Options) ([]*SubID, error) {
	if err := c.requireVersion("subid_find", "4.9.7"); err != nil {
		return nil, err
	}
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}
	options["all"] = true

	res, err := c.rpc(ctx, "subid_find", []string{""}, options)
	if err != nil {
		return nil, err
	}
	subs := make([]*SubID, 0)
	for _, t := range gjson.ParseBytes(res.Result.Data).Array() {
		subs = append(subs, subIDFrom(t))
	}
	return subs, c.truncated(res)
}

// SubIDGenerate allocates a range with `subid_generate`; owner "" means the
// caller. For yourself it needs the Subordinate ID Selfservice User role, for
// others Subordinate ID Administrators. One range per user: a second call
// returns ErrDuplicateEntry. Servers older than 4.9.7 give ErrNotSupported
// when their version is known. A server with sub-IDs disabled returns a 3009
// ValidationError.
func (c *Client) SubIDGenerate(owner string) (*SubID, error) {
	return c.SubIDGenerateContext(context.Background(), owner)
}

// SubIDGenerateContext is like SubIDGenerate but bounds the request with ctx.
func (c *Client) SubIDGenerateContext(ctx context.Context, owner string) (*SubID, error) {
	if err := c.requireVersion("subid_generate", "4.9.7"); err != nil {
		return nil, err
	}
	options := Options{"all": true}
	if owner != "" {
		options["ipaowner"] = owner
	}
	res, err := c.rpc(ctx, "subid_generate", nil, options)
	if err != nil {
		return nil, err
	}
	return subIDFrom(gjson.ParseBytes(res.Result.Data)), nil
}
