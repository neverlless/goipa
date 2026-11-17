// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"strconv"

	ipa "github.com/neverlless/goipa"
)

// Config is the server-wide configuration config_show returns. Zero fields
// are left out of the response, as FreeIPA leaves out unset attributes.
type Config struct {
	UserAuthTypes, UserObjectClasses, ConfigString                           []string
	DefaultPrimaryGroup, HomesRootDir, DefaultLoginShell, DefaultEmailDomain string
	MaxUsernameLength, PwdExpAdvNotify                                       int
}

// seedConfig holds the values of a fresh FreeIPA 4.13.4 install (Q199).
func seedConfig() Config {
	return Config{
		UserObjectClasses: []string{"top", "person", "organizationalperson", "inetorgperson", "inetuser",
			"posixaccount", "krbprincipalaux", "krbticketpolicyaux", "ipaobject", "ipasshuser"},
		ConfigString:        []string{"AllowNThash", "KDC:Disable Last Success"},
		DefaultPrimaryGroup: "ipausers", HomesRootDir: "/home", DefaultLoginShell: "/bin/sh",
		DefaultEmailDomain: "test.local", MaxUsernameLength: 32, PwdExpAdvNotify: 4,
	}
}

// SetConfig replaces the configuration config_show returns; the default is
// the one of a fresh install. A user's own ipauserauthtype is not combined
// with UserAuthTypes at login.
func (s *Server) SetConfig(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
}

func (cfg Config) render() map[string]any {
	out := map[string]any{"cn": []string{"ipaConfig"}, "dn": "cn=ipaConfig,cn=etc,dc=test,dc=local"}
	list := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = v
		}
	}
	one := func(k, v string) {
		if v != "" {
			out[k] = []string{v}
		}
	}
	list("ipauserauthtype", cfg.UserAuthTypes)
	list("ipauserobjectclasses", cfg.UserObjectClasses)
	list("ipaconfigstring", cfg.ConfigString)
	one("ipadefaultprimarygroup", cfg.DefaultPrimaryGroup)
	one("ipahomesrootdir", cfg.HomesRootDir)
	one("ipadefaultloginshell", cfg.DefaultLoginShell)
	one("ipadefaultemaildomain", cfg.DefaultEmailDomain)
	if cfg.MaxUsernameLength != 0 {
		one("ipamaxusernamelength", strconv.Itoa(cfg.MaxUsernameLength))
	}
	if cfg.PwdExpAdvNotify != 0 {
		one("ipapwdexpadvnotify", strconv.Itoa(cfg.PwdExpAdvNotify))
	}
	return out
}

func init() {
	// Q199: config_show renders the SetConfig values; like FreeIPA it has no
	// value or summary.
	builtins["config_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return map[string]any{"result": s.config.render(), "value": nil, "summary": nil}, nil
	}
}
