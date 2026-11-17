// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
)

// SelfService is a self-service rule: the attributes a user may change on
// their own entry.
type SelfService struct {
	Name               string   // aciname
	Permissions, Attrs []string // permissions (e.g. "write"), attrs
}

func selfServiceFrom(e Entry) *SelfService {
	return &SelfService{Name: e.Str("aciname"), Permissions: e.Strs("permissions"), Attrs: e.Strs("attrs")}
}

// SelfServiceFind lists self-service rules with `selfservice_find`; options
// are passed through (`aciname`, `attrs`, `permissions`, `sizelimit`).
// FreeIPA always ships default rules, so an unfiltered find that returns
// nothing means the caller lacks System: Read ACIs (privilege "RBAC
// Readers"): the server hides the rules without an error.
func (c *Client) SelfServiceFind(options Options) ([]*SelfService, error) {
	return c.SelfServiceFindContext(context.Background(), options)
}

// SelfServiceFindContext is like SelfServiceFind but bounds the request with ctx.
func (c *Client) SelfServiceFindContext(ctx context.Context, options Options) ([]*SelfService, error) {
	return findTyped(ctx, c, "selfservice_find", []string{""}, options, selfServiceFrom)
}

// SelfServiceShow fetches the rule called name with `selfservice_show`. A
// caller without System: Read ACIs gets the not-found error.
func (c *Client) SelfServiceShow(name string) (*SelfService, error) {
	return c.SelfServiceShowContext(context.Background(), name)
}

// SelfServiceShowContext is like SelfServiceShow but bounds the request with ctx.
func (c *Client) SelfServiceShowContext(ctx context.Context, name string) (*SelfService, error) {
	if name == "" {
		return nil, errors.New("ipa: self-service rule name is required")
	}
	return showEntry(ctx, c, "selfservice_show", []string{name}, selfServiceFrom)
}
