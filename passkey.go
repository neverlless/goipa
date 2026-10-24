// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
)

// UserAddPasskey adds a passkey mapping with `user_add_passkey`. The mapping
// is passkey:<credential id b64>,<public key b64 SPKI>[,<user id>]. Users may
// manage their own mappings; for others the Passkey Administrators privilege
// is needed. FreeIPA 4.11+: when the server version is known to be older it
// returns ErrNotSupported without sending (see ServerVersion). A
// duplicate returns 4038, an invalid mapping 3009. Read mappings with
// UserShow (User.Passkeys).
func (c *Client) UserAddPasskey(username, mapping string) error {
	return c.UserAddPasskeyContext(context.Background(), username, mapping)
}

// UserAddPasskeyContext is like UserAddPasskey but bounds the request with ctx.
func (c *Client) UserAddPasskeyContext(ctx context.Context, username, mapping string) error {
	return c.passkey(ctx, "user_add_passkey", username, mapping)
}

// UserRemovePasskey removes a passkey mapping with `user_remove_passkey`; see
// UserAddPasskey. A mapping that is not present returns 4026.
func (c *Client) UserRemovePasskey(username, mapping string) error {
	return c.UserRemovePasskeyContext(context.Background(), username, mapping)
}

// UserRemovePasskeyContext is like UserRemovePasskey but bounds the request with ctx.
func (c *Client) UserRemovePasskeyContext(ctx context.Context, username, mapping string) error {
	return c.passkey(ctx, "user_remove_passkey", username, mapping)
}

func (c *Client) passkey(ctx context.Context, method, username, mapping string) error {
	if username == "" || mapping == "" {
		return errors.New("ipa: username and passkey mapping are required")
	}
	if err := c.requireVersion(method, "4.11"); err != nil {
		return err
	}
	_, err := c.rpc(ctx, method, []string{username, mapping}, Options{})
	return err
}
