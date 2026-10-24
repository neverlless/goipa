// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"

	"github.com/tidwall/gjson"
)

// Stage users are users waiting for activation: FreeIPA keeps them in a
// separate container, always locked, and they have no uidnumber or group
// membership until StageUserActivate moves them to the active users.

func (c *Client) stageUser(ctx context.Context, method string, args []string, options Options) (*User, error) {
	res, err := c.rpc(ctx, method, args, options)
	if err != nil {
		return nil, err
	}
	u := new(User)
	if err := u.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return u, nil
}

// StageUserAdd adds a stage user with `stageuser_add`. Username, First and Last
// are required; empty fields are not sent. It requires the Stage User
// Administrators privilege (add also: Stage User Provisioning). A duplicate
// returns the bare *IpaError (ErrDuplicateEntry), not ErrUserExists.
func (c *Client) StageUserAdd(user *User) (*User, error) {
	return c.StageUserAddContext(context.Background(), user)
}

// StageUserAddContext is like StageUserAdd but bounds the request with ctx.
func (c *Client) StageUserAddContext(ctx context.Context, user *User) (*User, error) {
	if user.Username == "" {
		return nil, errors.New("ipa: username is required")
	}
	return c.stageUser(ctx, "stageuser_add", []string{user.Username}, nonEmpty(user.ToOptions()))
}

// StageUserShow fetches a stage user with `stageuser_show`. It requires the
// Stage User Administrators privilege.
func (c *Client) StageUserShow(username string) (*User, error) {
	return c.StageUserShowContext(context.Background(), username)
}

// StageUserShowContext is like StageUserShow but bounds the request with ctx.
func (c *Client) StageUserShowContext(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, errors.New("ipa: username is required")
	}
	return c.stageUser(ctx, "stageuser_show", []string{username}, Options{"no_members": false, "all": true})
}

// StageUserFind finds stage users with `stageuser_find`; options are passed
// through (e.g. `uid`, `sizelimit`). It requires the Stage User Administrators
// privilege.
func (c *Client) StageUserFind(options Options) ([]*User, error) {
	return c.StageUserFindContext(context.Background(), options)
}

// StageUserFindContext is like StageUserFind but bounds the request with ctx.
func (c *Client) StageUserFindContext(ctx context.Context, options Options) ([]*User, error) {
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}
	options["no_members"] = false
	options["all"] = true

	res, err := c.rpc(ctx, "stageuser_find", []string{""}, options)
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0)
	for _, t := range gjson.ParseBytes(res.Result.Data).Array() {
		u := new(User)
		if err := u.fromJSON([]byte(t.Raw)); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// StageUserMod modifies a stage user with `stageuser_mod`, sending the same
// attributes as UserMod. It returns user itself when nothing changed. It
// requires the Stage User Administrators privilege.
func (c *Client) StageUserMod(user *User) (*User, error) {
	return c.StageUserModContext(context.Background(), user)
}

// StageUserModContext is like StageUserMod but bounds the request with ctx.
func (c *Client) StageUserModContext(ctx context.Context, user *User) (*User, error) {
	if user.Username == "" {
		return nil, errors.New("ipa: username is required")
	}
	u, err := c.stageUser(ctx, "stageuser_mod", []string{user.Username}, user.ToOptions())
	if errors.Is(err, ErrEmptyModlist) {
		return user, nil
	}
	return u, err
}

// StageUserActivate activates a stage user with `stageuser_activate` and
// returns the new active user. It requires the Stage User Administrators and
// User Administrators privileges. If an active user with that name exists,
// FreeIPA answers ErrDuplicateEntry and keeps the stage entry.
func (c *Client) StageUserActivate(username string) (*User, error) {
	return c.StageUserActivateContext(context.Background(), username)
}

// StageUserActivateContext is like StageUserActivate but bounds the request with ctx.
func (c *Client) StageUserActivateContext(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, errors.New("ipa: username is required")
	}
	return c.stageUser(ctx, "stageuser_activate", []string{username}, nil)
}

// StageUserDelete deletes stage users with `stageuser_del`, stopping at the
// first error. It requires the Stage User Administrators privilege.
func (c *Client) StageUserDelete(usernames ...string) error {
	return c.StageUserDeleteContext(context.Background(), usernames...)
}

// StageUserDeleteContext is like StageUserDelete but bounds the request with ctx.
func (c *Client) StageUserDeleteContext(ctx context.Context, usernames ...string) error {
	if len(usernames) == 0 {
		return errors.New("ipa: at least one username is required")
	}
	_, err := c.rpc(ctx, "stageuser_del", usernames, Options{"continue": false})
	return err
}
