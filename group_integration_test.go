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

func TestIntegrationGroupMembers(t *testing.T) {
	c, err := newTestClientCCache()
	require.NoError(t, err)

	n := time.Now().UnixNano()
	group := fmt.Sprintf("goipa-it-%d-g", n)
	u1, mgr, third, stranger := fmt.Sprintf("goipait%da", n), fmt.Sprintf("goipait%db", n), fmt.Sprintf("goipait%dc", n), fmt.Sprintf("goipait%dd", n)
	_, err = c.GroupAdd(&ipa.Group{Name: group})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = c.GroupDelete(group)
		_ = c.UserDelete(false, false, u1, mgr, third, stranger)
	})
	for _, u := range []string{u1, third} {
		_, err := c.UserAdd(&ipa.User{Username: u, First: "Go", Last: "IPA"}, false)
		require.NoError(t, err)
	}
	const pass = "Secret-pw-1-goipa"
	for _, u := range []string{mgr, stranger} {
		_, err := c.UserAddWithPassword(&ipa.User{Username: u, First: "Go", Last: "IPA"}, pass)
		require.NoError(t, err)
	}

	g, err := c.GroupAddMember(group, []string{u1}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{u1}, g.Users)

	var me *ipa.MemberError
	_, err = c.GroupAddMember(group, []string{u1}, nil)
	require.ErrorAs(t, err, &me)
	require.Contains(t, me.Failures[0].Message, "already a member")

	_, err = c.GroupAddMember(group, []string{fmt.Sprintf("nonexistent-%d", n)}, nil)
	require.ErrorAs(t, err, &me)

	_, err = c.GroupAddMemberManager(group, []string{mgr}, nil)
	require.NoError(t, err)

	asMgr := ipa.NewDefaultClient()
	require.NoError(t, asMgr.RemoteLogin(mgr, pass))
	_, err = asMgr.GroupAddMember(group, []string{third}, nil)
	require.NoError(t, err)

	asStranger := ipa.NewDefaultClient()
	require.NoError(t, asStranger.RemoteLogin(stranger, pass))
	_, err = asStranger.GroupAddMember(group, []string{stranger}, nil)
	require.ErrorAs(t, err, &me)

	_, err = c.GroupRemoveMember(group, []string{u1, third}, nil)
	require.NoError(t, err)
	_, err = c.GroupRemoveMemberManager(group, []string{mgr}, nil)
	require.NoError(t, err)
}
