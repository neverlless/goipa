// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"

	"github.com/tidwall/gjson"
)

// Identity is the account the server sees for the current credentials.
type Identity struct {
	// object: "user", "host", "service" or "idoverrideuser"
	Object string
	// command, as sent: "user_show/1"
	Command string
	// arguments: the primary key(s), e.g. ["admin"]
	Arguments []string
}

// WhoAmI runs `whoami`: which account the server maps the credentials to. Any
// authenticated principal may call it; FreeIPA 4.5+.
func (c *Client) WhoAmI() (*Identity, error) {
	return c.WhoAmIContext(context.Background())
}

// WhoAmIContext is like WhoAmI but bounds the request with ctx.
func (c *Client) WhoAmIContext(ctx context.Context) (*Identity, error) {
	res, err := c.rpc(ctx, "whoami", []string{}, Options{})
	if err != nil {
		return nil, err
	}
	// whoami has no "result" key: the fields sit in the result object.
	r := gjson.ParseBytes(res.Result.Raw)
	return &Identity{
		Object:    r.Get("object").String(),
		Command:   r.Get("command").String(),
		Arguments: strList(r, "arguments"),
	}, nil
}
