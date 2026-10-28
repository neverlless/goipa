// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
)

// TestContractTruncationOptIn pins Q164-Q167: the finds honour sizelimit and
// report truncated. FetchOTPTokens takes no options, so otptoken_find is
// checked through FindEntries.
func TestContractTruncationOptIn(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		enableSubIDs(t, b)
		tag := "gtr" + randHex(t, 4)
		for i := 0; i < 2; i++ {
			uid := newUID(t, b)
			if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: tag}, false); err != nil {
				t.Fatal(err)
			}
			if _, err := b.admin.SubIDGenerate(uid); err != nil {
				t.Fatal(err)
			}
			suid := newStageUID(t, b)
			if _, err := b.admin.StageUserAdd(&ipa.User{Username: suid, First: "Go", Last: tag}); err != nil {
				t.Fatal(err)
			}
			cn := "gtg" + randHex(t, 4)
			if _, err := b.admin.GroupAdd(&ipa.Group{Name: cn, Description: tag}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.admin.GroupDelete(cn) })
			fqdn := cn + ".example.test"
			mustRPC(t, b.admin, "host_add", []string{fqdn}, ipa.Options{"force": true, "description": tag})
			t.Cleanup(func() { _, _ = b.admin.RPC("host_del", []string{fqdn}, nil) })
			if _, err := b.admin.HBACRuleAdd(&ipa.HBACRule{Name: cn, Description: tag}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.admin.HBACRuleDelete(cn) })
			if _, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: cn, Description: tag}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.admin.SudoRuleDelete(cn) })
		}
		for i := 0; i < 2; i++ {
			tok, err := b.admin.AddOTPToken(nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.admin.RemoveOTPToken(tok.UUID) })
		}
		on, err := ipa.New(ipa.WithHost(b.host), ipa.WithRealm(b.realm), ipa.WithHTTPClient(b.http), ipa.WithTruncationErrors(), ipa.WithValidation())
		if err != nil {
			t.Fatal(err)
		}
		on.SetSessionID(b.admin.SessionID())
		desc := ipa.Options{"sizelimit": 1, "description": tag}
		finds := map[string]func(c *ipa.Client) (int, error){
			"UserFind": func(c *ipa.Client) (int, error) {
				r, err := c.UserFind(ipa.Options{"sizelimit": 1, "sn": tag})
				return len(r), err
			},
			"StageUserFind": func(c *ipa.Client) (int, error) {
				r, err := c.StageUserFind(ipa.Options{"sizelimit": 1, "sn": tag})
				return len(r), err
			},
			"SubIDFind": func(c *ipa.Client) (int, error) {
				r, err := c.SubIDFind(ipa.Options{"sizelimit": 1})
				return len(r), err
			},
			"GroupFind":    func(c *ipa.Client) (int, error) { r, err := c.GroupFind(desc); return len(r), err },
			"HostFind":     func(c *ipa.Client) (int, error) { r, err := c.HostFind(desc); return len(r), err },
			"HBACRuleFind": func(c *ipa.Client) (int, error) { r, err := c.HBACRuleFind(desc); return len(r), err },
			"SudoRuleFind": func(c *ipa.Client) (int, error) { r, err := c.SudoRuleFind(desc); return len(r), err },
		}
		if es, err := ipa.FindEntries(context.Background(), b.admin, "otptoken_find", nil, nil, 1); err != ipa.ErrTruncated || len(es) != 1 {
			t.Errorf("otptoken_find: %d entries, %v", len(es), err)
		}
		for name, f := range finds {
			if n, err := f(b.admin); err != nil || n != 1 {
				t.Errorf("%s default: %d entries, %v", name, n, err)
			}
			if n, err := f(on); !errors.Is(err, ipa.ErrTruncated) || n != 1 {
				t.Errorf("%s opt-in: %d entries, %v", name, n, err)
			}
		}
	})
}
