// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const serviceBaseDN = "cn=services,cn=accounts,dc=test,dc=local"

// Service is a Kerberos service of the fake server.
type Service struct {
	ManagedBy                    []string // managedby_host
	HasKeytab                    bool
	KeytabRetrieve, KeytabCreate ipa.KeytabAccess
	AuthIndicators               []string // krbprincipalauthind
}

type serviceRec struct {
	Service
	certs [][]byte // usercertificate, DER
}

func cloneAccess(a ipa.KeytabAccess) ipa.KeytabAccess {
	return ipa.KeytabAccess{Users: cloneStrs(a.Users), Groups: cloneStrs(a.Groups), Hosts: cloneStrs(a.Hosts), HostGroups: cloneStrs(a.HostGroups)}
}

func (v Service) clone() Service {
	v.ManagedBy = cloneStrs(v.ManagedBy)
	v.KeytabRetrieve = cloneAccess(v.KeytabRetrieve)
	v.KeytabCreate = cloneAccess(v.KeytabCreate)
	v.AuthIndicators = cloneStrs(v.AuthIndicators)
	return v
}

// withRealm is principal as FreeIPA stores it, realm included.
func withRealm(principal string) string {
	if principal != "" && !strings.Contains(principal, "@") {
		return principal + "@" + realm
	}
	return principal
}

// AddService creates or replaces service principal; the realm may be left
// out.
func (s *Server) AddService(principal string, svc Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := &serviceRec{Service: svc.clone()}
	lowerHostGroups(rec.KeytabRetrieve.HostGroups)
	lowerHostGroups(rec.KeytabCreate.HostGroups)
	s.services[withRealm(principal)] = rec
}

// Service returns a copy of service principal; the realm may be left out.
func (s *Server) Service(principal string) (Service, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.services[withRealm(principal)]
	if !ok {
		return Service{}, false
	}
	return r.Service.clone(), true
}

func (r *serviceRec) render(p string, members, all bool) map[string]any {
	out := map[string]any{
		"krbcanonicalname": []string{p},
		"krbprincipalname": []string{p},
		"has_keytab":       r.HasKeytab,
	}
	set := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
		}
	}
	set("krbprincipalauthind", r.AuthIndicators)
	if len(r.certs) > 0 {
		certs := make([]map[string]string, len(r.certs))
		for i, der := range r.certs {
			certs[i] = map[string]string{"__base64__": base64.StdEncoding.EncodeToString(der)}
		}
		out["usercertificate"] = certs
	}
	if members {
		set("managedby_host", r.ManagedBy)
		for op, a := range map[string]ipa.KeytabAccess{"read": r.KeytabRetrieve, "write": r.KeytabCreate} {
			p := "ipaallowedtoperform_" + op + "_keys_"
			set(p+"user", a.Users)
			set(p+"group", a.Groups)
			set(p+"host", a.Hosts)
			set(p+"hostgroup", a.HostGroups)
		}
	}
	if all {
		out["ipakrbokasdelegate"] = false
		out["ipakrboktoauthasdelegate"] = false
		out["ipakrbrequirespreauth"] = true
		out["objectclass"] = []string{"krbprincipal", "krbprincipalaux", "krbticketpolicyaux", "ipaobject", "ipaservice", "pkiuser", "ipakrbprincipal", "top"}
		out["dn"] = "krbprincipalname=" + p + "," + serviceBaseDN
	}
	return out
}

func (s *Server) serviceArg(c Call) (string, *serviceRec, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", nil, required("krbcanonicalname")
	}
	p := withRealm(c.Args[0])
	r := s.services[p]
	if r == nil {
		return "", nil, notFound(p, "service")
	}
	return p, r, nil
}

func serviceShow(s *Server, c Call) (any, *ipa.IpaError) {
	p, r, err := s.serviceArg(c)
	if err != nil {
		return nil, err
	}
	all := flag(c, "all")
	return entry(p, r.render(p, all || !flag(c, "no_members"), all), ""), nil
}

func serviceFind(s *Server, c Call) (any, *ipa.IpaError) {
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	all := flag(c, "all")
	members := all
	if v, ok := c.Options["no_members"].(bool); ok && !v { // U1
		members = true
	}
	want := withRealm(str(c.Options["krbcanonicalname"]))
	var ps []string
	for p := range s.services {
		if !strings.Contains(strings.ToLower(p), needle) || want != "" && p != want {
			continue
		}
		ps = append(ps, p)
	}
	sort.Strings(ps)
	recs := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		recs = append(recs, s.services[p].render(p, members, all))
	}
	return listLimited(c, recs), nil
}

// serviceAdd implements Q60: the host must exist unless skip_host_check,
// and becomes the service's managedby.
func serviceAdd(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("krbcanonicalname")
	}
	p := withRealm(c.Args[0])
	if s.services[p] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("service with name %q already exists", p)}
	}
	_, hostname, _ := strings.Cut(strings.SplitN(p, "@", 2)[0], "/")
	r := &serviceRec{}
	if v, ok := c.Options["krbprincipalauthind"]; ok {
		if err := s.checkAuthInds("auth_ind", strs(v)); err != nil {
			return nil, err
		}
		r.AuthIndicators = strs(v)
	}
	if _, ok := s.hosts[hostname]; ok {
		r.ManagedBy = []string{hostname}
	} else if !flag(c, "skip_host_check") {
		return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Message: fmt.Sprintf("The host '%s' does not exist to add a service to.", hostname)}
	}
	s.services[p] = r
	return entry(p, r.render(p, true, flag(c, "all")), fmt.Sprintf("Added service %q", p)), nil
}

// checkAuthInds is the StrEnum check of krbprincipalauthind (Q142); name is
// the option or attribute as FreeIPA names it in the error.
func (s *Server) checkAuthInds(name string, vals []string) *ipa.IpaError {
	allowed := []string{"radius", "otp", "pkinit", "hardened", "idp"}
	var ma, mi int
	_, _ = fmt.Sscanf(s.version, "%d.%d", &ma, &mi)
	if ma > 4 || ma == 4 && mi >= 11 {
		allowed = append(allowed, "passkey")
	}
	for _, v := range vals {
		if !slices.Contains(allowed, v) {
			return invalid(fmt.Sprintf("invalid '%s': must be one of '%s'", name, strings.Join(allowed, "', '")))
		}
	}
	return nil
}

// serviceMod changes the auth indicators, by option or setattr, addattr and
// delattr (Q142).
func serviceMod(s *Server, c Call) (any, *ipa.IpaError) {
	p, r, err := s.serviceArg(c)
	if err != nil {
		return nil, err
	}
	next := slices.Clone(r.AuthIndicators)
	if v, ok := c.Options["krbprincipalauthind"]; ok {
		if err := s.checkAuthInds("auth_ind", strs(v)); err != nil {
			return nil, err
		}
		next = strs(v)
	}
	vals := func(attr string) ([]string, bool) {
		return next, attr == "krbprincipalauthind"
	}
	merged, err := attrOpts(c.Options, vals, map[string]bool{"krbprincipalauthind": true})
	if err != nil {
		return nil, err
	}
	if v, ok := merged["krbprincipalauthind"]; ok {
		next = strs(v)
		if err := s.checkAuthInds("krbprincipalauthind", next); err != nil {
			return nil, err
		}
	}
	if slices.Equal(next, r.AuthIndicators) {
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	r.AuthIndicators = next
	return entry(p, r.render(p, true, flag(c, "all")), fmt.Sprintf("Modified service %q", p)), nil
}

func serviceDel(s *Server, c Call) (any, *ipa.IpaError) {
	deleted := make([]string, 0, len(c.Args))
	for _, p := range c.Args {
		p = withRealm(p)
		if s.services[p] == nil {
			return nil, notFound(p, "service")
		}
		deleted = append(deleted, p)
	}
	for _, p := range deleted {
		delete(s.services, p)
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   deleted,
		"summary": fmt.Sprintf("Deleted service %q", strings.Join(deleted, ",")),
	}, nil
}

// serviceMembers implements service_{add,remove}_host and the keytab
// allow/disallow commands; per-member problems go to failed[attr] (Q62).
func serviceMembers(attr string, add bool, lists func(*serviceRec) map[string]*[]string) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		p, r, err := s.serviceArg(c)
		if err != nil {
			return nil, err
		}
		exists := map[string]func(string) bool{
			"user":      func(n string) bool { return s.users[n] != nil },
			"group":     func(n string) bool { return s.groups[n] != nil },
			"host":      func(n string) bool { _, ok := s.hosts[n]; return ok },
			"hostgroup": func(n string) bool { return s.hostgroups[n] != nil },
		}
		failed := map[string][][]string{}
		completed := 0
		for kind, list := range lists(r) {
			failed[kind] = [][]string{}
			for _, n := range strs(c.Options[kind]) {
				if kind == "hostgroup" {
					n = hostGroupKey(n)
				}
				msg := ""
				switch {
				case !exists[kind](n):
					msg = "no such entry"
				case add && slices.Contains(*list, n):
					msg = "This entry is already a member"
				case !add && !slices.Contains(*list, n):
					msg = "This entry is not a member"
				}
				if msg != "" {
					failed[kind] = append(failed[kind], []string{n, msg})
					continue
				}
				completed++
				if add {
					*list = append(*list, n)
				} else {
					*list = slices.DeleteFunc(*list, func(m string) bool { return m == n })
				}
			}
		}
		return map[string]any{
			"result":    r.render(p, true, flag(c, "all")),
			"completed": completed,
			"failed":    map[string]any{attr: failed},
		}, nil
	}
}

func managedBy(r *serviceRec) map[string]*[]string { return map[string]*[]string{"host": &r.ManagedBy} }

func keytabLists(a func(*serviceRec) *ipa.KeytabAccess) func(*serviceRec) map[string]*[]string {
	return func(r *serviceRec) map[string]*[]string {
		k := a(r)
		return map[string]*[]string{"user": &k.Users, "group": &k.Groups, "host": &k.Hosts, "hostgroup": &k.HostGroups}
	}
}

// serviceDisable implements Q64.
func serviceDisable(s *Server, c Call) (any, *ipa.IpaError) {
	p, r, err := s.serviceArg(c)
	if err != nil {
		return nil, err
	}
	// Every certificate here came from service_add_cert, so none is the CA's
	// to revoke; before 4.13 FreeIPA leaves such certificates alone.
	var ma, mi int
	_, _ = fmt.Sscanf(s.version, "%d.%d", &ma, &mi)
	dropCerts := len(r.certs) > 0 && (ma > 4 || ma == 4 && mi >= 13)
	if !r.HasKeytab && !dropCerts {
		return nil, &ipa.IpaError{Code: ipa.CodeAlreadyInactive, Message: "This entry is already disabled"}
	}
	r.HasKeytab = false
	if dropCerts {
		r.certs = nil
	}
	return map[string]any{"result": true, "value": p, "summary": fmt.Sprintf("Disabled service %q", p)}, nil
}

func serviceAddCert(s *Server, c Call) (any, *ipa.IpaError) {
	p, r, err := s.serviceArg(c)
	if err != nil {
		return nil, err
	}
	certs := strs(c.Options["usercertificate"])
	if len(certs) == 0 {
		return nil, required("usercertificate")
	}
	for _, b64 := range certs {
		der, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			return nil, invalid("Base64 decoding failed: " + derr.Error())
		}
		r.certs = append(r.certs, der)
	}
	return entry(p, r.render(p, true, flag(c, "all")), fmt.Sprintf("Added certificates to service principal %q", p)), nil
}

func init() {
	retrieve := keytabLists(func(r *serviceRec) *ipa.KeytabAccess { return &r.KeytabRetrieve })
	create := keytabLists(func(r *serviceRec) *ipa.KeytabAccess { return &r.KeytabCreate })
	builtins["service_show"] = serviceShow
	builtins["service_find"] = serviceFind
	builtins["service_add"] = serviceAdd
	builtins["service_del"] = serviceDel
	builtins["service_mod"] = serviceMod
	builtins["service_add_host"] = serviceMembers("managedby", true, managedBy)
	builtins["service_remove_host"] = serviceMembers("managedby", false, managedBy)
	builtins["service_allow_retrieve_keytab"] = serviceMembers("ipaallowedtoperform_read_keys", true, retrieve)
	builtins["service_disallow_retrieve_keytab"] = serviceMembers("ipaallowedtoperform_read_keys", false, retrieve)
	builtins["service_allow_create_keytab"] = serviceMembers("ipaallowedtoperform_write_keys", true, create)
	builtins["service_disallow_create_keytab"] = serviceMembers("ipaallowedtoperform_write_keys", false, create)
	builtins["service_disable"] = serviceDisable
	builtins["service_add_cert"] = serviceAddCert
}
