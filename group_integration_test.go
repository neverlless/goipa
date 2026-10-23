//go:build integration

// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/neverlless/goipa"
	"github.com/stretchr/testify/require"
)

func TestIntegrationGroupShowFind(t *testing.T) {
	c, err := newTestClientCCache()
	require.NoError(t, err)

	g, err := c.GroupShow("admins")
	require.NoError(t, err)
	require.Contains(t, g.Users, "admin")
	require.False(t, g.NonPOSIX)

	gs, err := c.GroupFind(ipa.Options{"cn": "admins"})
	require.NoError(t, err)
	require.Len(t, gs, 1)
}

func TestIntegrationGroupCRUD(t *testing.T) {
	c, err := newTestClientCCache()
	require.NoError(t, err)

	n := time.Now().UnixNano()
	posix, nonposix, ext := fmt.Sprintf("goipa-it-%d-a", n), fmt.Sprintf("goipa-it-%d-b", n), fmt.Sprintf("goipa-it-%d-c", n)
	t.Cleanup(func() {
		for _, g := range []string{posix, nonposix, ext} {
			_ = c.GroupDelete(g)
		}
	})

	g, err := c.GroupAdd(&ipa.Group{Name: posix, Description: "goipa test"})
	require.NoError(t, err)
	require.False(t, g.NonPOSIX)
	require.NotEmpty(t, g.GID)

	g, err = c.GroupAdd(&ipa.Group{Name: nonposix, NonPOSIX: true})
	require.NoError(t, err)
	require.True(t, g.NonPOSIX)
	require.Empty(t, g.GID)

	g, err = c.GroupAdd(&ipa.Group{Name: ext, External: true})
	require.NoError(t, err)
	require.True(t, g.External)
	require.True(t, g.NonPOSIX)

	g, err = c.GroupMod(&ipa.Group{Name: posix, Description: "changed"})
	require.NoError(t, err)
	require.Equal(t, "changed", g.Description)

	require.NoError(t, c.GroupDelete(posix, nonposix, ext))
	_, err = c.GroupShow(posix)
	require.ErrorIs(t, err, ipa.ErrNotFound)
}
