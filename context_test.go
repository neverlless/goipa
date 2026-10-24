// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
)

type twinCall struct {
	name string
	call func(context.Context, *ipa.Client) error
}

func twinCalls() []twinCall {
	return []twinCall{
		{"CertRequestContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.CertRequestContext(ctx, "host/h", "csr")
			return err
		}},
		{"CertShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.CertShowContext(ctx, "1")
			return err
		}},
		{"CertRevokeContext", func(ctx context.Context, c *ipa.Client) error {
			return c.CertRevokeContext(ctx, "1", 0)
		}},
		{"RPCContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.RPCContext(ctx, "ping", nil, nil)
			return err
		}},
		{"PwPolicyShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PwPolicyShowContext(ctx, "")
			return err
		}},
		{"UserPwPolicyContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserPwPolicyContext(ctx, "bob")
			return err
		}},
		{"PingContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PingContext(ctx)
			return err
		}},
		{"RemoteLoginContext", func(ctx context.Context, c *ipa.Client) error {
			return c.RemoteLoginContext(ctx, "bob", "pw")
		}},
		{"UserShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserShowContext(ctx, "bob")
			return err
		}},
		{"UserFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserFindContext(ctx, nil)
			return err
		}},
		{"UserStatusContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserStatusContext(ctx, "bob")
			return err
		}},
		{"UserUnlockContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserUnlockContext(ctx, "bob")
		}},
		{"ResetPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ResetPasswordContext(ctx, "bob")
			return err
		}},
		{"ChangePasswordContext", func(ctx context.Context, c *ipa.Client) error {
			return c.ChangePasswordContext(ctx, "bob", "old", "new", "")
		}},
		{"SetPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SetPasswordContext(ctx, "bob", "old", "new", "")
		}},
		{"SyncOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SyncOTPTokenContext(ctx, "bob", "pw", "123456", "654321", "")
		}},
		{"SetAuthTypesContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SetAuthTypesContext(ctx, "bob", []string{"otp"})
		}},
		{"UserDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserDisableContext(ctx, "bob")
		}},
		{"UserEnableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserEnableContext(ctx, "bob")
		}},
		{"UserAddWithPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserAddWithPasswordContext(ctx, &ipa.User{Username: "bob"}, "pw")
			return err
		}},
		{"UserAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserAddContext(ctx, &ipa.User{Username: "bob"}, false)
			return err
		}},
		{"UserDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserDeleteContext(ctx, false, true, "bob")
		}},
		{"UserModContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.UserModContext(ctx, &ipa.User{Username: "bob"})
			return err
		}},
		{"RemoveOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.RemoveOTPTokenContext(ctx, "u")
		}},
		{"FetchOTPTokensContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.FetchOTPTokensContext(ctx, "bob")
			return err
		}},
		{"AddOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AddOTPTokenContext(ctx, nil)
			return err
		}},
		{"EnableOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.EnableOTPTokenContext(ctx, "u")
		}},
		{"DisableOTPTokenContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DisableOTPTokenContext(ctx, "u")
		}},
		{"GroupShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupShowContext(ctx, "g")
			return err
		}},
		{"GroupFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupFindContext(ctx, nil)
			return err
		}},
		{"GroupAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupAddContext(ctx, &ipa.Group{Name: "g"})
			return err
		}},
		{"GroupModContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupModContext(ctx, &ipa.Group{Name: "g"})
			return err
		}},
		{"GroupDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.GroupDeleteContext(ctx, "g")
		}},
		{"GroupAddMemberContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupAddMemberContext(ctx, "g", []string{"u"}, nil)
			return err
		}},
		{"GroupRemoveMemberContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupRemoveMemberContext(ctx, "g", []string{"u"}, nil)
			return err
		}},
		{"GroupAddMemberManagerContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupAddMemberManagerContext(ctx, "g", []string{"u"}, nil)
			return err
		}},
		{"GroupRemoveMemberManagerContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.GroupRemoveMemberManagerContext(ctx, "g", []string{"u"}, nil)
			return err
		}},
		{"HostShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostShowContext(ctx, "h.test.local")
			return err
		}},
		{"HostFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostFindContext(ctx, nil)
			return err
		}},
		{"HBACRuleFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleFindContext(ctx, nil)
			return err
		}},
		{"WhoAmIContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.WhoAmIContext(ctx)
			return err
		}},
		{"HBACTestContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACTestContext(ctx, "bob", "h.test.local", "sshd")
			return err
		}},
		{"SudoRuleFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleFindContext(ctx, nil)
			return err
		}},
		{"StageUserAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserAddContext(ctx, &ipa.User{Username: "bob"})
			return err
		}},
		{"StageUserShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserShowContext(ctx, "bob")
			return err
		}},
		{"StageUserFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserFindContext(ctx, nil)
			return err
		}},
		{"StageUserModContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserModContext(ctx, &ipa.User{Username: "bob"})
			return err
		}},
		{"SubIDFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SubIDFindContext(ctx, nil)
			return err
		}},
		{"SubIDGenerateContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SubIDGenerateContext(ctx, "bob")
			return err
		}},
		{"StageUserActivateContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserActivateContext(ctx, "bob")
			return err
		}},
		{"StageUserDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.StageUserDeleteContext(ctx, "bob")
		}},
		{"UserAddPasskeyContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserAddPasskeyContext(ctx, "bob", testPasskey)
		}},
		{"UserRemovePasskeyContext", func(ctx context.Context, c *ipa.Client) error {
			return c.UserRemovePasskeyContext(ctx, "bob", testPasskey)
		}},
		{"HostGroupShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupShowContext(ctx, "hg")
			return err
		}},
		{"HostGroupFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupFindContext(ctx, nil)
			return err
		}},
		{"HostGroupAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupAddContext(ctx, &ipa.HostGroup{Name: "hg"})
			return err
		}},
		{"HostGroupDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.HostGroupDeleteContext(ctx, "hg")
		}},
		{"HostGroupAddMemberContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupAddMemberContext(ctx, "hg", []string{"h"}, nil)
			return err
		}},
		{"HostGroupRemoveMemberContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupRemoveMemberContext(ctx, "hg", []string{"h"}, nil)
			return err
		}},
		{"HostGroupAddMemberManagerContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupAddMemberManagerContext(ctx, "hg", []string{"bob"}, nil)
			return err
		}},
		{"HostGroupRemoveMemberManagerContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HostGroupRemoveMemberManagerContext(ctx, "hg", []string{"bob"}, nil)
			return err
		}},
		{"HBACRuleShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleShowContext(ctx, "r")
			return err
		}},
		{"HBACRuleAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleAddContext(ctx, &ipa.HBACRule{Name: "r"})
			return err
		}},
		{"HBACRuleDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.HBACRuleDeleteContext(ctx, "r")
		}},
		{"HBACRuleEnableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.HBACRuleEnableContext(ctx, "r")
		}},
		{"HBACRuleDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.HBACRuleDisableContext(ctx, "r")
		}},
		{"HBACRuleAddUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleAddUserContext(ctx, "r", []string{"u"}, nil)
			return err
		}},
		{"HBACRuleRemoveUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleRemoveUserContext(ctx, "r", []string{"u"}, nil)
			return err
		}},
		{"HBACRuleAddHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleAddHostContext(ctx, "r", []string{"h"}, nil)
			return err
		}},
		{"HBACRuleRemoveHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleRemoveHostContext(ctx, "r", []string{"h"}, nil)
			return err
		}},
		{"HBACRuleAddServiceContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleAddServiceContext(ctx, "r", []string{"sshd"}, nil)
			return err
		}},
		{"HBACRuleRemoveServiceContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.HBACRuleRemoveServiceContext(ctx, "r", []string{"sshd"}, nil)
			return err
		}},
		{"DNSZoneShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSZoneShowContext(ctx, "z.test.")
			return err
		}},
		{"DNSZoneFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSZoneFindContext(ctx, nil)
			return err
		}},
		{"DNSZoneAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSZoneAddContext(ctx, "z.test.", false)
			return err
		}},
		{"DNSZoneDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DNSZoneDeleteContext(ctx, "z.test.")
		}},
		{"DNSZoneEnableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DNSZoneEnableContext(ctx, "z.test.")
		}},
		{"DNSZoneDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DNSZoneDisableContext(ctx, "z.test.")
		}},
		{"DNSRecordShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSRecordShowContext(ctx, "z.test.", "www")
			return err
		}},
		{"DNSRecordFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSRecordFindContext(ctx, "z.test.", nil)
			return err
		}},
		{"DNSRecordAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.DNSRecordAddContext(ctx, "z.test.", "www", "A", "192.0.2.1")
			return err
		}},
		{"DNSRecordRemoveContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DNSRecordRemoveContext(ctx, "z.test.", "www", "A", "192.0.2.1")
		}},
		{"DNSRecordDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.DNSRecordDeleteContext(ctx, "z.test.", "www")
		}},
	}
}

func TestContextCancelReachesTransport(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"summary":"ok"}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range twinCalls() {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(ctx, c); !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}

// Methods that do no network I/O, take ctx themselves, or cannot honour ctx (gokrb5).
var noTwin = map[string]bool{"Modify": true, "Host": true, "Realm": true, "SessionID": true, "SetSessionID": true,
	"ClearSession": true, "StickySession": true, "Login": true, "LoginWithKeytab": true, "LoginFromCCache": true,
	"LoginWithKeytabData": true, "LoginFromCCacheData": true,
	"ServerVersion": true, "Batch": true}

func TestEveryMethodHasContextTwin(t *testing.T) {
	typ := reflect.TypeFor[*ipa.Client]()
	rows := map[string]bool{}
	for _, tc := range twinCalls() {
		rows[tc.name] = true
	}
	for m := range typ.Methods() {
		if strings.HasSuffix(m.Name, "Context") {
			if !rows[m.Name] {
				t.Errorf("%s has no row in twinCalls", m.Name)
			}
		} else if _, ok := typ.MethodByName(m.Name + "Context"); !ok && !noTwin[m.Name] {
			t.Errorf("%s has no Context twin", m.Name)
		}
	}
}
