// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import "context"

// Config is the server-wide FreeIPA configuration (`config_show`), the
// attributes a user portal reads. Unset attributes are zero or nil.
type Config struct {
	// ipauserauthtype: the default authentication types of users that have
	// none of their own; nil when unset (password and the other types apply
	// as the server's own defaults).
	UserAuthTypes []string
	// ipauserobjectclasses, ipaconfigstring
	UserObjectClasses, ConfigString []string
	// ipadefaultprimarygroup, ipahomesrootdir, ipadefaultloginshell,
	// ipadefaultemaildomain
	DefaultPrimaryGroup, HomesRootDir, DefaultLoginShell, DefaultEmailDomain string
	// ipamaxusernamelength, ipapwdexpadvnotify (days)
	MaxUsernameLength, PwdExpAdvNotify int
}

func configFromEntry(e Entry) *Config {
	n := func(k string) int { v, _ := e.Int(k); return int(v) }
	return &Config{
		UserAuthTypes:       e.Strs("ipauserauthtype"),
		UserObjectClasses:   e.Strs("ipauserobjectclasses"),
		ConfigString:        e.Strs("ipaconfigstring"),
		DefaultPrimaryGroup: e.Str("ipadefaultprimarygroup"),
		HomesRootDir:        e.Str("ipahomesrootdir"),
		DefaultLoginShell:   e.Str("ipadefaultloginshell"),
		DefaultEmailDomain:  e.Str("ipadefaultemaildomain"),
		MaxUsernameLength:   n("ipamaxusernamelength"),
		PwdExpAdvNotify:     n("ipapwdexpadvnotify"),
	}
}

// ConfigShow reads the server configuration with `config_show`. FreeIPA
// lets any authenticated user read it (System: Read Global Configuration).
func (c *Client) ConfigShow() (*Config, error) {
	return c.ConfigShowContext(context.Background())
}

// ConfigShowContext is like ConfigShow but bounds the request with ctx.
func (c *Client) ConfigShowContext(ctx context.Context) (*Config, error) {
	return showEntry(ctx, c, "config_show", []string{}, configFromEntry)
}
