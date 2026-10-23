//go:build integration

// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/stretchr/testify/require"
)

func TestIntegrationHost(t *testing.T) {
	c, err := newTestClientCCache()
	require.NoError(t, err)

	fqdn := c.Host()
	if h, _, err := net.SplitHostPort(fqdn); err == nil {
		fqdn = h
	}

	h, err := c.HostShow(fqdn)
	require.NoError(t, err)
	require.Equal(t, fqdn, h.FQDN)
	require.True(t, h.HasKeytab)

	hs, err := c.HostFind(ipa.Options{"fqdn": fqdn})
	require.NoError(t, err)
	require.Len(t, hs, 1)
}
