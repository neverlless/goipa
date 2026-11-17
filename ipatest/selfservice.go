// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"slices"
	"strings"

	ipa "github.com/neverlless/goipa"
)

type selfRule struct {
	name  string
	attrs []string
}

// selfRules are FreeIPA's default self-service rules, in the recorded order.
var selfRules = []selfRule{
	{"Self can write own password", []string{"userpassword", "krbprincipalkey", "sambalmpassword", "sambantpassword"}},
	{"User Self service", []string{"givenname", "sn", "cn", "displayname", "title", "initials", "loginshell", "gecos",
		"homephone", "mobile", "pager", "facsimiletelephonenumber", "telephonenumber", "street", "roomnumber", "l", "st",
		"postalcode", "manager", "secretary", "description", "carlicense", "labeleduri", "inetuserhttpurl", "seealso",
		"employeetype", "businesscategory", "ou"}},
	{"Users can manage their own SSH public keys", []string{"ipasshpubkey"}},
	{"Users can manage their own X.509 certificates", []string{"usercertificate"}},
	{"Users can manage their own X.509 certificate identity mappings", []string{"ipacertmapdata"}},
	{"Users can manage their own passkey mappings", []string{"ipapasskey"}},
}

// selfServices are the rules of the release (Q200): the passkey rule came
// with 4.11.0.
func (s *Server) selfServices() []selfRule {
	if v, ok := parseRelease(s.version); ok && slices.Compare(v[:], []int{4, 11, 0}) < 0 {
		return selfRules[:len(selfRules)-1]
	}
	return selfRules
}

// selfVisible is Q201: from 4.13 the rules are readable only with System:
// Read ACIs, bound to RBAC Readers; an older release is taken to show them
// to everyone.
func (s *Server) selfVisible(uid string) bool {
	v, ok := parseRelease(s.version)
	return s.holds(uid, "RBAC Readers") || ok && slices.Compare(v[:], []int{4, 13, 0}) < 0
}

func (r selfRule) render() map[string]any {
	return map[string]any{"aciname": r.name, "attrs": r.attrs, "permissions": []string{"write"}, "selfaci": true}
}

func init() {
	builtins["selfservice_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		needle := ""
		if len(c.Args) > 0 {
			needle = strings.ToLower(c.Args[0])
		}
		out := []map[string]any{}
		for _, r := range s.selfServices() {
			if !s.selfVisible(c.User) || !strings.Contains(strings.ToLower(r.name), needle) || !matches(c, "aciname", r.name) ||
				!containsAll(r.attrs, c.Options["attrs"]) || !containsAll([]string{"write"}, c.Options["permissions"]) {
				continue
			}
			out = append(out, r.render())
		}
		return listLimited(c, out), nil
	}
	builtins["selfservice_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		if len(c.Args) == 0 || c.Args[0] == "" {
			return nil, required("aciname")
		}
		for _, r := range s.selfServices() {
			if r.name == c.Args[0] && s.selfVisible(c.User) {
				return entry(r.name, r.render(), ""), nil
			}
		}
		// Q202: a missing and a hidden rule are the same error.
		return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Name: "NotFound", Message: `ACI with name "` + c.Args[0] + `" not found`}
	}
}

func containsAll(have []string, want any) bool {
	for _, w := range strs(want) {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}
