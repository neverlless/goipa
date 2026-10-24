// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"

	ipa "github.com/neverlless/goipa"
)

var passkeyRE = regexp.MustCompile(`^passkey:([^,]*),([^,]*),?(.*)$`)

// validPasskey is validate_passkey, Q36.
func validPasskey(m string) *ipa.IpaError {
	bad := func(why string) *ipa.IpaError {
		return &ipa.IpaError{Code: ipa.CodeValidation, Name: "ValidationError", Message: "invalid 'passkey': " + why}
	}
	g := passkeyRE.FindStringSubmatch(m)
	if g == nil {
		return bad("Invalid passkey mapping format")
	}
	if _, err := base64.StdEncoding.DecodeString(g[1]); err != nil {
		return bad("Invalid credential id")
	}
	der, err := base64.StdEncoding.DecodeString(g[2])
	if err != nil {
		return bad("Invalid public key")
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return bad("Invalid public key")
	}
	return nil
}

func passkeyCmd(add bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		uid, r, err := s.userArg(c)
		if err != nil {
			return nil, err
		}
		if len(c.Args) < 2 || c.Args[1] == "" {
			return nil, required("ipapasskey")
		}
		m := c.Args[1]
		has := slices.Contains(r.Passkeys, m)
		summary := fmt.Sprintf("Removed passkey mappings from user %q", uid)
		switch {
		case add:
			if err := validPasskey(m); err != nil {
				return nil, err
			}
			if has {
				return nil, &ipa.IpaError{Code: ipa.CodeAlreadyContainsValue, Name: "AlreadyContainsValueError", Message: fmt.Sprintf("'ipapasskey' already contains '%s'", m)}
			}
			r.Passkeys = append(r.Passkeys, m)
			summary = fmt.Sprintf("Added passkey mappings to user %q", uid)
		case !has:
			return nil, &ipa.IpaError{Code: ipa.CodeAttrValueNotFound, Name: "AttrValueNotFound", Message: fmt.Sprintf("'ipapasskey' does not contain '%s'", m)}
		default:
			r.Passkeys = slices.DeleteFunc(r.Passkeys, func(p string) bool { return p == m })
		}
		return entry(uid, map[string]any{"uid": []string{uid}, "ipapasskey": slices.Clone(r.Passkeys)}, summary), nil
	}
}

func init() {
	builtins["user_add_passkey"] = passkeyCmd(true)
	builtins["user_remove_passkey"] = passkeyCmd(false)
}
