// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"time"

	"github.com/tidwall/gjson"
)

// PwPolicy is a FreeIPA password policy. Attributes the server does not
// return (older releases, unset values) are zero.
type PwPolicy struct {
	// cn: "global_policy" or the group the policy belongs to
	Name string
	// cospriority; group policies only. 0 from UserPwPolicy: FreeIPA does not
	// return it for the effective policy, use PwPolicyShow(Name).
	Priority int
	// krbmaxpwdlife (days on the wire), krbminpwdlife (hours on the wire)
	MaxLife, MinLife time.Duration
	// krbpwdhistorylength, krbpwdmindiffchars, krbpwdminlength, krbpwdmaxfailure
	HistoryLength, MinClasses, MinLength, MaxFailures int
	// krbpwdfailurecountinterval (seconds), krbpwdlockoutduration (seconds;
	// 0 = locked until an admin unlocks)
	FailureInterval, LockoutDuration time.Duration
	// ipapwdmaxrepeat, ipapwdmaxsequence
	MaxRepeat, MaxSequence int
	// ipapwddictcheck, ipapwdusercheck
	DictCheck, UserCheck bool
	// passwordgracelimit, FreeIPA 4.9.10+; -1 = no grace logins enforced
	GraceLimit int
	// ipapwddcredit, ipapwducredit, ipapwdlcredit, ipapwdocredit; FreeIPA 4.13+
	DigitCredit, UpperCredit, LowerCredit, OtherCredit int
}

func pwPolicyFrom(res gjson.Result) *PwPolicy {
	n := func(k string) int { return int(res.Get(k + ".0").Int()) }
	d := func(k string, unit time.Duration) time.Duration { return time.Duration(res.Get(k+".0").Int()) * unit }
	return &PwPolicy{
		Name:            res.Get("cn.0").String(),
		Priority:        n("cospriority"),
		MaxLife:         d("krbmaxpwdlife", 24*time.Hour),
		MinLife:         d("krbminpwdlife", time.Hour),
		HistoryLength:   n("krbpwdhistorylength"),
		MinClasses:      n("krbpwdmindiffchars"),
		MinLength:       n("krbpwdminlength"),
		MaxFailures:     n("krbpwdmaxfailure"),
		FailureInterval: d("krbpwdfailurecountinterval", time.Second),
		LockoutDuration: d("krbpwdlockoutduration", time.Second),
		MaxRepeat:       n("ipapwdmaxrepeat"),
		MaxSequence:     n("ipapwdmaxsequence"),
		DictCheck:       boolAttr(res, "ipapwddictcheck"),
		UserCheck:       boolAttr(res, "ipapwdusercheck"),
		GraceLimit:      n("passwordgracelimit"),
		DigitCredit:     n("ipapwddcredit"),
		UpperCredit:     n("ipapwducredit"),
		LowerCredit:     n("ipapwdlcredit"),
		OtherCredit:     n("ipapwdocredit"),
	}
}

func (c *Client) pwPolicyShow(ctx context.Context, args []string, options Options) (*PwPolicy, error) {
	options["all"] = true
	res, err := c.rpc(ctx, "pwpolicy_show", args, options)
	if err != nil {
		return nil, err
	}
	return pwPolicyFrom(gjson.ParseBytes(res.Result.Data)), nil
}

// PwPolicyShow fetches the password policy of group with `pwpolicy_show`;
// "" is the global_policy. It needs the Password Policy Readers or Password
// Policy Administrator privilege (System: Read Group Password Policy);
// without it FreeIPA hides the entry and answers ErrNotFound, not ErrACI.
func (c *Client) PwPolicyShow(group string) (*PwPolicy, error) {
	return c.PwPolicyShowContext(context.Background(), group)
}

// PwPolicyShowContext is like PwPolicyShow but bounds the request with ctx.
func (c *Client) PwPolicyShowContext(ctx context.Context, group string) (*PwPolicy, error) {
	args := []string{}
	if group != "" {
		args = append(args, group)
	}
	return c.pwPolicyShow(ctx, args, Options{})
}

// UserPwPolicy fetches the policy that applies to username with
// `pwpolicy_show` and its `user` option: the group policy with the lowest
// priority among the user's groups, else the global policy. FreeIPA resolves
// it as the caller, so the caller must be able to read the user, and, as for
// PwPolicyShow, a caller without the privilege gets ErrNotFound. Priority is
// 0 because FreeIPA does not return it here.
func (c *Client) UserPwPolicy(username string) (*PwPolicy, error) {
	return c.UserPwPolicyContext(context.Background(), username)
}

// UserPwPolicyContext is like UserPwPolicy but bounds the request with ctx.
func (c *Client) UserPwPolicyContext(ctx context.Context, username string) (*PwPolicy, error) {
	if username == "" {
		return nil, errors.New("ipa: username is required")
	}
	return c.pwPolicyShow(ctx, []string{}, Options{"user": username})
}
