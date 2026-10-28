// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"
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
	HostGroups                                           []string // memberof_hostgroup, with the host groups listing the host (Q50)
	ManagedBy                                            []string // managedby_host
	HasKeytab                                            bool
	Password                                             string // one-time enrollment password; has_password
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
	h = h.clone()
	lowerHostGroups(h.HostGroups)
	s.hosts[fqdn] = h
}

func (s *Server) renderHost(fqdn string, h Host, members, all bool) map[string]any {
	out := map[string]any{
		"fqdn":             []string{fqdn},
		"krbprincipalname": []string{"host/" + fqdn + "@" + realm},
		"has_keytab":       h.HasKeytab,
		"has_password":     h.Password != "",
	}
	set := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
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
		mine := s.hostGroupsOf(fqdn)
		set("memberof_hostgroup", mine)
		set("memberofindirect_hostgroup", s.hostGroupAncestors(mine))
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
	return listLimited(c, recs), nil
}

func init() {
	builtins["host_show"] = hostShow
	builtins["host_find"] = hostFind
}

func (h Host) sameAttrs(o Host) bool {
	return h.Description == o.Description && h.Locality == o.Locality && h.Location == o.Location &&
		h.Platform == o.Platform && h.OSVersion == o.OSVersion &&
		slices.Equal(h.MACAddresses, o.MACAddresses) && slices.Equal(h.UserClass, o.UserClass)
}

// applyAttrs applies the seven modelled attributes present in c.
func (h *Host) applyAttrs(c Call) {
	for k, p := range map[string]*string{"description": &h.Description, "l": &h.Locality, "nshostlocation": &h.Location,
		"nshardwareplatform": &h.Platform, "nsosversion": &h.OSVersion} {
		if v, ok := c.Options[k]; ok {
			*p = str(v)
		}
	}
	if v, ok := c.Options["macaddress"]; ok {
		h.MACAddresses = strs(v)
	}
	if v, ok := c.Options["userclass"]; ok {
		h.UserClass = strs(v)
	}
}

// hostAdd is host_add without DNS: every fqdn is accepted, as with force.
func hostAdd(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("fqdn")
	}
	fqdn := strings.ToLower(c.Args[0])
	if _, ok := s.hosts[fqdn]; ok {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: `host with name "` + fqdn + `" already exists`}
	}
	h := Host{}
	h.applyAttrs(c)
	random := flag(c, "random")
	if random {
		h.Password = randomPassword()
	} else {
		h.Password = str(c.Options["userpassword"])
	}
	s.hosts[fqdn] = h
	all := flag(c, "all")
	rec := s.renderHost(fqdn, h, all || !flag(c, "no_members"), all)
	if random {
		rec["randompassword"] = h.Password
	}
	return entry(fqdn, rec, `Added host "`+fqdn+`"`), nil
}

// hostMod models the seven attributes hostAdd keeps.
func hostMod(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("fqdn")
	}
	fqdn := strings.ToLower(c.Args[0])
	h, ok := s.hosts[fqdn]
	if !ok {
		return nil, notFound(c.Args[0], "host")
	}
	for k := range c.Options {
		if !slices.Contains([]string{"all", "raw", "rights", "no_members", "version", "description", "l", "nshostlocation",
			"nshardwareplatform", "nsosversion", "macaddress", "userclass"}, k) {
			return nil, &ipa.IpaError{Code: ipa.CodeCommand, Message: "ipatest: host_mod models description, l, nshostlocation, nshardwareplatform, nsosversion, macaddress and userclass only, not " + k}
		}
	}
	n := h.clone()
	n.applyAttrs(c)
	if n.sameAttrs(h) {
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	s.hosts[fqdn] = n
	all := flag(c, "all")
	return entry(fqdn, s.renderHost(fqdn, n, all || !flag(c, "no_members"), all), `Modified host "`+fqdn+`"`), nil
}

// hostDisable drops the keytab and the one-time password; a host with neither
// is already disabled.
func hostDisable(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("fqdn")
	}
	fqdn := strings.ToLower(c.Args[0])
	h, ok := s.hosts[fqdn]
	if !ok {
		return nil, notFound(c.Args[0], "host")
	}
	if !h.HasKeytab && h.Password == "" {
		return nil, &ipa.IpaError{Code: ipa.CodeAlreadyInactive, Message: "This entry is already disabled"}
	}
	h.HasKeytab, h.Password = false, ""
	s.hosts[fqdn] = h
	return map[string]any{"result": true, "value": fqdn, "summary": fmt.Sprintf("Removed kerberos key from host %q", fqdn)}, nil
}

func hostDel(s *Server, c Call) (any, *ipa.IpaError) {
	deleted := make([]string, len(c.Args))
	for i, fqdn := range c.Args {
		deleted[i] = strings.ToLower(fqdn)
		if _, ok := s.hosts[deleted[i]]; !ok {
			return nil, notFound(fqdn, "host")
		}
	}
	for _, fqdn := range deleted {
		delete(s.hosts, fqdn)
		if flag(c, "updatedns") {
			s.dropHostRecords(fqdn)
		}
		for _, g := range s.hostgroups {
			g.Hosts = dropName(g.Hosts, fqdn)
		}
		for _, r := range s.hbac {
			r.Hosts = dropName(r.Hosts, fqdn)
		}
		for _, r := range s.sudo {
			r.Hosts = dropName(r.Hosts, fqdn)
		}
		for p, v := range s.services {
			if _, h, _ := strings.Cut(strings.SplitN(p, "@", 2)[0], "/"); strings.EqualFold(h, fqdn) {
				delete(s.services, p) // FreeIPA deletes the host's services with it
				continue
			}
			v.ManagedBy = dropName(v.ManagedBy, fqdn)
			v.KeytabRetrieve.Hosts = dropName(v.KeytabRetrieve.Hosts, fqdn)
			v.KeytabCreate.Hosts = dropName(v.KeytabCreate.Hosts, fqdn)
		}
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   deleted,
		"summary": `Deleted host "` + strings.Join(deleted, ",") + `"`,
	}, nil
}

// dropHostRecords deletes the A and AAAA records named after the host in the
// zone holding its name.
func (s *Server) dropHostRecords(fqdn string) {
	for zone, z := range s.dnsZones {
		name, ok := strings.CutSuffix(absName(fqdn), "."+zone)
		if !ok {
			continue
		}
		r := z.records[name]
		delete(r, "arecord")
		delete(r, "aaaarecord")
		if len(r) == 0 {
			delete(z.records, name)
		}
	}
}

func init() {
	builtins["host_mod"] = hostMod
	builtins["host_disable"] = hostDisable
	builtins["host_add"] = hostAdd
	builtins["host_del"] = hostDel
}
