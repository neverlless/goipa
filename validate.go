// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// ErrInvalidCall is returned, before anything is sent, by a client built with
// WithValidation for a call the command catalogue says cannot succeed. Test
// with errors.Is.
var ErrInvalidCall = errors.New("ipa: call does not match the FreeIPA command catalogue")

// WithValidation checks every call against the command catalogue before
// sending it: an unknown command or option, or more arguments than the
// command takes, fails with ErrInvalidCall; a command or option newer than
// the server version from the last response fails with ErrNotSupported.
// Before the version is known nothing fails with ErrNotSupported, and a
// server newer than the newest catalogued release is not checked at all.
// Argument values and types are not checked. An option key that names a
// positional argument is accepted. The version gate follows the replica that
// answered last (see ErrNotSupported), so in a mixed 4.9/4.13 fleet behind a
// load balancer a call valid on 4.13 can get ErrNotSupported. Since values are
// upstream releases; distro backports are not known. Opt-in through New only:
// the old constructors never validate.
func WithValidation() Option {
	return func(s *settings) error {
		s.validate = true
		return nil
	}
}

func validateCall(method, version string, nargs int, opts Options) error {
	limit, all := catalogueLimit(version)
	if newest, _ := parseVersion(catalogueReleases[len(catalogueReleases)-1]); !all && versionLess(newest, limit) {
		return nil
	}
	i, ok := catalogueIndex()[method]
	if !ok {
		return fmt.Errorf("%w: unknown command %q", ErrInvalidCall, method)
	}
	cmd := &catalogue[i]
	if !sinceOK(cmd.Since, limit, all) {
		return fmt.Errorf("%w: %s needs FreeIPA %s, server is %s", ErrNotSupported, method, cmd.Since, version)
	}
	args := filterParams(cmd.Args, limit, all)
	if nargs > len(args) && (len(args) == 0 || !args[len(args)-1].Multi) {
		return fmt.Errorf("%w: %s takes at most %d arguments, got %d", ErrInvalidCall, method, len(args), nargs)
	}
	for _, key := range slices.Sorted(maps.Keys(opts)) {
		byName := func(p Param) bool { return p.Name == key }
		var since string
		if j := slices.IndexFunc(cmd.Options, byName); j >= 0 {
			since = cmd.Options[j].Since
		} else if j := slices.IndexFunc(cmd.Args, byName); j >= 0 {
			since = cmd.Args[j].Since // FreeIPA takes an argument by name among the options too (passwd current_password)
		} else {
			return fmt.Errorf("%w: %s has no option %q", ErrInvalidCall, method, key)
		}
		if !sinceOK(since, limit, all) {
			return fmt.Errorf("%w: %s option %q needs FreeIPA %s, server is %s", ErrNotSupported, method, key, since, version)
		}
	}
	return nil
}
