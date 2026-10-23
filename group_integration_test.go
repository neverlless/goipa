//go:build integration

// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"testing"

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
