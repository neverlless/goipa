// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"strings"
)

// Modification builds one *_mod call that changes single values with
// FreeIPA's setattr, addattr and delattr options. It is a builder: not safe
// for concurrent use.
type Modification struct {
	client        *Client
	command, pkey string
	set, add, del []string
	err           error
}

// Modify starts a modification of the entry pkey with a *_mod command such
// as "user_mod". Nothing is sent until Run.
func (c *Client) Modify(command, pkey string) *Modification {
	m := &Modification{client: c, command: command, pkey: pkey}
	switch {
	case command == "":
		m.err = errors.New("ipa: modify: empty command")
	case pkey == "":
		m.err = errors.New("ipa: modify: empty primary key")
	}
	return m
}

// Set replaces the attribute's values with value; Set(attr, "") clears it.
// Several Set calls for one attribute give it several values.
func (m *Modification) Set(attr, value string) *Modification { return m.push(&m.set, attr, value) }

// Add appends value to the attribute's values.
func (m *Modification) Add(attr, value string) *Modification { return m.push(&m.add, attr, value) }

// Del removes value from the attribute's values.
func (m *Modification) Del(attr, value string) *Modification { return m.push(&m.del, attr, value) }

func (m *Modification) push(list *[]string, attr, value string) *Modification {
	switch {
	case attr == "":
		m.fail("empty attribute name")
	case strings.Contains(attr, "="):
		m.fail("attribute name contains '='")
	}
	*list = append(*list, attr+"="+value)
	return m
}

func (m *Modification) fail(what string) {
	if m.err == nil {
		m.err = errors.New("ipa: modify: " + what)
	}
}

// Run sends the call: setattr, addattr and delattr in call order within
// each kind, with all: true. A call that changes nothing returns
// ErrEmptyModlist as the server sent it.
func (m *Modification) Run(ctx context.Context) (*Response, error) {
	if m.err == nil && len(m.set)+len(m.add)+len(m.del) == 0 {
		m.fail("nothing to do")
	}
	if m.err != nil {
		return nil, m.err
	}
	opts := Options{"all": true}
	for k, v := range map[string][]string{"setattr": m.set, "addattr": m.add, "delattr": m.del} {
		if len(v) > 0 {
			opts[k] = v
		}
	}
	return m.client.rpc(ctx, m.command, []string{m.pkey}, opts)
}
