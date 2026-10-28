// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"maps"
	"slices"

	ipa "github.com/neverlless/goipa"
)

// GrantPrivilege gives user uid the FreeIPA privilege named privilege, as a
// role holding it would. ipatest consults grants only where it checks rights
// (see # Auth model); a name it does not check, a misspelt one included, is
// kept and changes nothing, as AddUser takes any input. Grants are not shown
// by role, privilege or user reads.
func (s *Server) GrantPrivilege(uid, privilege string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants[uid] == nil {
		s.grants[uid] = map[string]bool{}
	}
	s.grants[uid][privilege] = true
}

// holds reports whether uid is an admin or was granted one of privs.
func (s *Server) holds(uid string, privs ...string) bool {
	return s.isAdmin(uid) || slices.ContainsFunc(privs, func(p string) bool { return s.grants[uid][p] })
}

// writePrivileges are the default privileges of the managed permissions
// FreeIPA 4.13.4 binds to each gated write (Q168).
var writePrivileges = map[string][]string{
	"user_add":        {"User Administrators"},
	"user_mod":        {"User Administrators"},
	"user_del":        {"User Administrators"},
	"stageuser_add":   {"Stage User Administrators", "Stage User Provisioning"},
	"group_add":       {"Group Administrators"},
	"group_mod":       {"Group Administrators"},
	"group_del":       {"Group Administrators"},
	"host_add":        {"Host Administrators"},
	"host_mod":        {"Host Administrators"},
	"host_del":        {"Host Administrators"},
	"hostgroup_add":   {"Host Group Administrators"},
	"hostgroup_del":   {"Host Group Administrators"},
	"service_add":     {"Service Administrators"},
	"service_del":     {"Service Administrators"},
	"hbacrule_add":    {"HBAC Administrator"},
	"hbacrule_del":    {"HBAC Administrator"},
	"hbacrule_enable": {"HBAC Administrator"},
	"sudorule_add":    {"Sudo Administrator"},
	"sudorule_del":    {"Sudo Administrator"},
	"dnszone_add":     {"DNS Administrators"},
	"automember_add":  nil, // no privilege grants adding automember rules
}

// refuse is the 2100 a gated write gets from a caller without its privilege,
// nil otherwise or for a command that is not gated. ldap is the LDAP ACI text
// releases without the API gate answer (4.12.2, Q169); gate false keeps it on
// every release, for the commands the gate does not cover (Q170).
func (s *Server) refuse(c Call, gate bool, ldap string) *ipa.IpaError {
	privs, ok := writePrivileges[c.Method]
	if !ok || s.holds(c.User, privs...) {
		return nil
	}
	if gate && !ldapACIRelease(s.version) {
		ldap = "not allowed to perform this operation"
	}
	return &ipa.IpaError{Code: ipa.CodeACI, Message: "Insufficient access: " + ldap}
}

// ldapACIRelease is true from 4.10 up to 4.13.3: the 4.9.13 integration image
// carries the API gate backported (Q169).
func ldapACIRelease(version string) bool {
	v, ok := parseRelease(version)
	return ok && slices.Compare(v[:], []int{4, 10, 0}) >= 0 && slices.Compare(v[:], []int{4, 13, 4}) < 0
}

func noAdd(dn string) string {
	return fmt.Sprintf("Insufficient 'add' privilege to add the entry '%s'.", dn)
}

func noDelete(dn string) string {
	return fmt.Sprintf("Insufficient 'delete' privilege to delete the entry '%s'.", dn)
}

func noWrite(attr, dn string) string {
	return fmt.Sprintf("Insufficient 'write' privilege to the '%s' attribute of entry '%s'.", attr, dn)
}

// firstAttr is the first attribute option of c in name order.
// shortcut: the directory names the first attribute of its modlist, which may differ; model the order if a test needs it.
func firstAttr(c Call) string {
	for _, k := range slices.Sorted(maps.Keys(c.Options)) {
		if !slices.Contains([]string{"all", "raw", "rights", "no_members", "version", "random", "setattr", "addattr", "delattr"}, k) {
			return k
		}
	}
	return "objectClass"
}
