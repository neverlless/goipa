// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNotSupported is returned, before anything is sent, by commands that need
// a newer FreeIPA than the one the client last talked to. The gate uses the
// version of the server that answered last, so behind a load balancer during
// a rolling upgrade it follows whichever replica that was. Test with
// errors.Is.
var ErrNotSupported = errors.New("ipa: not supported by this FreeIPA server")

// ServerVersion returns the FreeIPA release from the last successful response
// that carried one (e.g. 4.13.4), or "" before the first call; call Ping to
// learn it.
func (c *Client) ServerVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverVersion
}

// parseVersion reads the leading integers of up to three dot-separated parts,
// so "4.13.5.dev202610" is 4.13.5 and "4.9" is 4.9.0. Major and minor must
// start with digits; a patch without them counts as 0.
func parseVersion(s string) (v [3]int, ok bool) {
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 2 {
		return v, false
	}
	for i := range v {
		if i == len(parts) {
			break
		}
		d := parts[i]
		for j, r := range d {
			if r < '0' || r > '9' {
				d = d[:j]
				break
			}
		}
		n, err := strconv.Atoi(d)
		if err != nil {
			return v, i == 2
		}
		v[i] = n
	}
	return v, true
}

// requireVersion fails with ErrNotSupported when the server version is known
// and older than need; an unknown or unparsable version lets the call go.
func (c *Client) requireVersion(method, need string) error {
	have := c.ServerVersion()
	h, ok := parseVersion(have)
	if !ok {
		return nil
	}
	n, _ := parseVersion(need)
	if h[0] < n[0] || h[0] == n[0] && (h[1] < n[1] || h[1] == n[1] && h[2] < n[2]) {
		return fmt.Errorf("%w: %s needs FreeIPA %s, server is %s", ErrNotSupported, method, need, have)
	}
	return nil
}
