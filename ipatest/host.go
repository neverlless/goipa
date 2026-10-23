// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"sort"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const (
	hostBaseDN = "cn=computers,cn=accounts,dc=test,dc=local"
	// serverFQDN is the fake IPA's own host, enrolled as on every real IPA.
	serverFQDN = "ipa.test.local"
)

// Host is a host of the fake server.
type Host struct {
	Description, Locality, Location, Platform, OSVersion string
	MACAddresses, UserClass                              []string
	HostGroups                                           []string // memberof_hostgroup
	ManagedBy                                            []string // managedby_host
	HasKeytab                                            bool
}

func (h Host) clone() Host {
	h.MACAddresses = cloneStrs(h.MACAddresses)
	h.UserClass = cloneStrs(h.UserClass)
	h.HostGroups = cloneStrs(h.HostGroups)
	h.ManagedBy = cloneStrs(h.ManagedBy)
	return h
}

// AddHost creates or replaces host fqdn. New servers already hold their own
// host, ipa.test.local, with a keytab.
func (s *Server) AddHost(fqdn string, h Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts[fqdn] = h.clone()
}

func (s *Server) renderHost(fqdn string, h Host, members, all bool) map[string]any {
	out := map[string]any{
		"fqdn":             []string{fqdn},
		"krbprincipalname": []string{"host/" + fqdn + "@" + realm},
		"has_keytab":       h.HasKeytab,
		"has_password":     false,
	}
	set := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = v
		}
	}
	for k, v := range map[string]string{"description": h.Description, "l": h.Locality, "nshostlocation": h.Location,
		"nshardwareplatform": h.Platform, "nsosversion": h.OSVersion} {
		if v != "" {
			out[k] = []string{v}
		}
	}
	set("macaddress", h.MACAddresses)
	set("userclass", h.UserClass)
	if members {
		set("memberof_hostgroup", h.HostGroups)
		set("managedby_host", h.ManagedBy)
	}
	if all {
		out["objectclass"] = []string{"top", "ipaobject", "nshost", "ipahost", "pkiuser", "ipaservice", "krbprincipalaux", "krbprincipal", "ieee802device", "ipasshhost", "ipaallowedoperations"}
		out["dn"] = "fqdn=" + fqdn + "," + hostBaseDN
	}
	return out
}

func hostShow(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("fqdn")
	}
	fqdn := c.Args[0]
	h, ok := s.hosts[fqdn]
	if !ok {
		return nil, notFound(fqdn, "host")
	}
	all := flag(c, "all")
	return entry(fqdn, s.renderHost(fqdn, h, all || !flag(c, "no_members"), all), ""), nil
}

func hostFind(s *Server, c Call) (any, *ipa.IpaError) {
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	all := flag(c, "all")
	members := all
	if v, ok := c.Options["no_members"].(bool); ok && !v { // U1
		members = true
	}
	var fqdns []string
	for fqdn, h := range s.hosts {
		if needle != "" && !strings.Contains(strings.ToLower(fqdn), needle) && !strings.Contains(strings.ToLower(h.Description), needle) {
			continue
		}
		if !matches(c, "fqdn", fqdn) || !matches(c, "description", h.Description) {
			continue
		}
		fqdns = append(fqdns, fqdn)
	}
	sort.Strings(fqdns)
	recs := make([]map[string]any, 0, len(fqdns))
	for _, fqdn := range fqdns {
		recs = append(recs, s.renderHost(fqdn, s.hosts[fqdn], members, all))
	}
	return list(recs), nil
}

func init() {
	builtins["host_show"] = hostShow
	builtins["host_find"] = hostFind
}
