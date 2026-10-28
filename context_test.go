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
		{"StageUserAddWithPasswordContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.StageUserAddWithPasswordContext(ctx, &ipa.User{Username: "bob"}, "Secret123")
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
		{"RoleShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.RoleShowContext(ctx, "r")
			return err
		}},
		{"RoleFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.RoleFindContext(ctx, nil)
			return err
		}},
		{"PrivilegeShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PrivilegeShowContext(ctx, "p")
			return err
		}},
		{"PrivilegeFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PrivilegeFindContext(ctx, nil)
			return err
		}},
		{"PermissionShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PermissionShowContext(ctx, "p")
			return err
		}},
		{"PermissionFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.PermissionFindContext(ctx, nil)
			return err
		}},
		{"ServiceShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceShowContext(ctx, "HTTP/h")
			return err
		}},
		{"ServiceFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceFindContext(ctx, nil)
			return err
		}},
		{"ServiceAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceAddContext(ctx, "HTTP/h", false)
			return err
		}},
		{"ServiceDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.ServiceDeleteContext(ctx, "HTTP/h")
		}},
		{"ServiceAddHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceAddHostContext(ctx, "HTTP/h", []string{"h"})
			return err
		}},
		{"ServiceRemoveHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceRemoveHostContext(ctx, "HTTP/h", []string{"h"})
			return err
		}},
		{"ServiceAllowRetrieveKeytabContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceAllowRetrieveKeytabContext(ctx, "HTTP/h", ipa.KeytabAccess{Users: []string{"bob"}})
			return err
		}},
		{"ServiceDisallowRetrieveKeytabContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceDisallowRetrieveKeytabContext(ctx, "HTTP/h", ipa.KeytabAccess{Users: []string{"bob"}})
			return err
		}},
		{"ServiceAllowCreateKeytabContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceAllowCreateKeytabContext(ctx, "HTTP/h", ipa.KeytabAccess{Users: []string{"bob"}})
			return err
		}},
		{"ServiceDisallowCreateKeytabContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.ServiceDisallowCreateKeytabContext(ctx, "HTTP/h", ipa.KeytabAccess{Users: []string{"bob"}})
			return err
		}},
		{"ServiceDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.ServiceDisableContext(ctx, "HTTP/h")
		}},
		{"AutomemberShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberShowContext(ctx, ipa.AutomemberGroup, "g")
			return err
		}},
		{"AutomemberFindContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberFindContext(ctx, ipa.AutomemberGroup, nil)
			return err
		}},
		{"AutomemberAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberAddContext(ctx, ipa.AutomemberGroup, "g", "")
			return err
		}},
		{"AutomemberDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.AutomemberDeleteContext(ctx, ipa.AutomemberGroup, "g")
		}},
		{"AutomemberAddConditionContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberAddConditionContext(ctx, ipa.AutomemberGroup, "g", "uid", []string{"^a"}, nil)
			return err
		}},
		{"AutomemberRemoveConditionContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberRemoveConditionContext(ctx, ipa.AutomemberGroup, "g", "uid", []string{"^a"}, nil)
			return err
		}},
		{"AutomemberDefaultGroupContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.AutomemberDefaultGroupContext(ctx, ipa.AutomemberGroup)
			return err
		}},
		{"AutomemberSetDefaultGroupContext", func(ctx context.Context, c *ipa.Client) error {
			return c.AutomemberSetDefaultGroupContext(ctx, ipa.AutomemberGroup, "g")
		}},
		{"AutomemberRemoveDefaultGroupContext", func(ctx context.Context, c *ipa.Client) error {
			return c.AutomemberRemoveDefaultGroupContext(ctx, ipa.AutomemberGroup)
		}},
		{"AutomemberRebuildContext", func(ctx context.Context, c *ipa.Client) error {
			return c.AutomemberRebuildContext(ctx, ipa.AutomemberGroup)
		}},
		{"SudoRuleShowContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleShowContext(ctx, "r")
			return err
		}},
		{"SudoRuleAddContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddContext(ctx, &ipa.SudoRule{Name: "r"})
			return err
		}},
		{"SudoRuleDeleteContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SudoRuleDeleteContext(ctx, "r")
		}},
		{"SudoRuleEnableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SudoRuleEnableContext(ctx, "r")
		}},
		{"SudoRuleDisableContext", func(ctx context.Context, c *ipa.Client) error {
			return c.SudoRuleDisableContext(ctx, "r")
		}},
		{"SudoRuleAddUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddUserContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleRemoveUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveUserContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleAddHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddHostContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleRemoveHostContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveHostContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleAddAllowCommandContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddAllowCommandContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleRemoveAllowCommandContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveAllowCommandContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleAddDenyCommandContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddDenyCommandContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleRemoveDenyCommandContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveDenyCommandContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleAddRunAsUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddRunAsUserContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleRemoveRunAsUserContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveRunAsUserContext(ctx, "r", []string{"x"}, nil)
			return err
		}},
		{"SudoRuleAddRunAsGroupContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddRunAsGroupContext(ctx, "r", []string{"x"})
			return err
		}},
		{"SudoRuleRemoveRunAsGroupContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveRunAsGroupContext(ctx, "r", []string{"x"})
			return err
		}},
		{"SudoRuleAddOptionContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleAddOptionContext(ctx, "r", "!authenticate")
			return err
		}},
		{"SudoRuleRemoveOptionContext", func(ctx context.Context, c *ipa.Client) error {
			_, err := c.SudoRuleRemoveOptionContext(ctx, "r", "!authenticate")
			return err
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
