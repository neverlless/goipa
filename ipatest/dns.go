// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
)

const dnsBaseDN = "cn=dns,dc=test,dc=local"

type dnsZone struct {
	active, dynUpdate                            bool
	mname, rname                                 string
	serial, refresh, retry, expire, minimum, ttl int64
	records                                      map[string]map[string][]string // name -> "arecord" -> values
}

// seedDNS is the zone of the fake's own domain, as ipa-server-install
// --setup-dns creates it.
func seedDNS() map[string]*dnsZone {
	z := newZone()
	z.records["ipa"] = map[string][]string{"arecord": {"127.0.0.1"}}
	return map[string]*dnsZone{"test.local.": z}
}

// newZone has dnszone_add's defaults (Q100).
func newZone() *dnsZone {
	return &dnsZone{
		active: true, mname: serverFQDN + ".", rname: "hostmaster",
		serial: time.Now().Unix(), refresh: 3600, retry: 900, expire: 1209600, minimum: 3600,
		records: map[string]map[string][]string{
			"@":         {"nsrecord": {serverFQDN + "."}},
			"_kerberos": {"txtrecord": {realm}},
		},
	}
}

func dnsName(s string) map[string]string { return map[string]string{"__dns_name__": s} }

func absName(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// relName makes a record name relative to zone, as FreeIPA stores it.
func relName(zone, name string) string {
	switch {
	case name == zone:
		return "@"
	case strings.HasSuffix(name, "."+zone):
		return strings.TrimSuffix(name, "."+zone)
	}
	return name
}

func (z *dnsZone) render(name string, all bool) map[string]any {
	n := func(v int64) []string { return []string{strconv.FormatInt(v, 10)} }
	out := map[string]any{
		"idnsname":           []any{dnsName(name)},
		"idnszoneactive":     []bool{z.active},
		"idnssoamname":       []any{dnsName(z.mname)},
		"idnssoarname":       []any{dnsName(z.rname)},
		"idnssoaserial":      n(z.serial),
		"idnssoarefresh":     n(z.refresh),
		"idnssoaretry":       n(z.retry),
		"idnssoaexpire":      n(z.expire),
		"idnssoaminimum":     n(z.minimum),
		"idnsallowdynupdate": []bool{z.dynUpdate},
		"idnsallowquery":     []string{"any;"},
		"idnsallowtransfer":  []string{"none;"},
	}
	if z.ttl > 0 {
		out["dnsttl"] = n(z.ttl)
	}
	maps.Copy(out, cloneRecords(z.records["@"]))
	if all {
		out["dn"] = "idnsname=" + name + "," + dnsBaseDN
		out["objectclass"] = []string{"top", "idnsrecord", "idnszone"}
	}
	return out
}

func cloneRecords(r map[string][]string) map[string]any {
	out := map[string]any{}
	for k, v := range r {
		out[k] = slices.Clone(v)
	}
	return out
}

// renderRecord is a record entry; the apex is the zone entry itself.
func (z *dnsZone) renderRecord(zone, name string, all bool) map[string]any {
	if name == "@" {
		out := z.render(zone, all)
		out["idnsname"] = []any{dnsName(name)}
		return out
	}
	out := cloneRecords(z.records[name])
	out["idnsname"] = []any{dnsName(name)}
	if all {
		out["dn"] = "idnsname=" + name + ",idnsname=" + zone + "," + dnsBaseDN
		out["objectclass"] = []string{"top", "idnsrecord"}
	}
	return out
}

func (s *Server) zoneArg(c Call) (string, *dnsZone, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", nil, required("idnsname")
	}
	name := absName(c.Args[0])
	z, ok := s.dnsZones[name]
	if !ok {
		return name, nil, notFound(name, "DNS zone")
	}
	return name, z, nil
}

func dnszoneShow(s *Server, c Call) (any, *ipa.IpaError) {
	name, z, err := s.zoneArg(c)
	if err != nil {
		return nil, err
	}
	return entry(name, z.render(name, flag(c, "all")), ""), nil
}

func dnszoneFind(s *Server, c Call) (any, *ipa.IpaError) {
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	var recs []map[string]any
	for _, name := range slices.Sorted(maps.Keys(s.dnsZones)) {
		if o, ok := c.Options["idnsname"]; !strings.Contains(name, needle) || ok && absName(str(o)) != name {
			continue
		}
		recs = append(recs, s.dnsZones[name].render(name, flag(c, "all")))
	}
	return listLimited(c, recs), nil
}

func dnszoneAdd(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("idnsname")
	}
	name := absName(c.Args[0])
	if err := s.refuse(c, true, noAdd("idnsname="+name+","+dnsBaseDN)); err != nil {
		return nil, err
	}
	if s.dnsZones[name] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("DNS zone with name %q already exists", name)}
	}
	z := newZone()
	s.dnsZones[name] = z
	return entry(name, z.render(name, flag(c, "all")), fmt.Sprintf("Added DNS zone %q", name)), nil
}

func dnszoneDel(s *Server, c Call) (any, *ipa.IpaError) {
	var names []string
	for _, a := range c.Args {
		name := absName(a)
		if s.dnsZones[name] == nil {
			return nil, notFound(name, "DNS zone")
		}
		names = append(names, name)
	}
	for _, name := range names {
		delete(s.dnsZones, name)
	}
	if names == nil {
		names = []string{}
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   names,
		"summary": fmt.Sprintf("Deleted DNS zone %q", strings.Join(names, ",")),
	}, nil
}

// dnszoneToggle sets idnszoneactive; repeating it is not an error (Q101).
func dnszoneToggle(active bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		name, z, err := s.zoneArg(c)
		if err != nil {
			return nil, err
		}
		z.active = active
		verb := map[bool]string{true: "Enabled", false: "Disabled"}[active]
		return map[string]any{"result": true, "value": name, "summary": fmt.Sprintf("%s DNS zone %q", verb, name)}, nil
	}
}

// recordArgs resolves the zone and the relative record name.
func (s *Server) recordArgs(c Call) (string, string, *dnsZone, *ipa.IpaError) {
	zone, z, err := s.zoneArg(c)
	if err != nil {
		return "", "", nil, err
	}
	if len(c.Args) < 2 || c.Args[1] == "" {
		return "", "", nil, required("idnsname")
	}
	name := relName(zone, c.Args[1])
	if strings.HasSuffix(name, ".") {
		return "", "", nil, invalid("invalid 'idnsname': out-of-zone data: record name must be a subdomain of the zone or a relative name")
	}
	return zone, name, z, nil
}

// suspiciousName is FreeIPA's warning for a relative name that ends in the
// zone's name, likely a missing trailing dot (Q143).
func suspiciousName(zone, name string) []map[string]any {
	bare := strings.TrimSuffix(zone, ".")
	if name != bare && !strings.HasSuffix(name, "."+bare) {
		return nil
	}
	fqdn := name + "." + zone
	return []map[string]any{{
		"type": "warning", "name": "DNSSuspiciousRelativeName", "code": 13014,
		"message": fmt.Sprintf("Relative record name '%s' contains the zone name '%s' as a suffix, which results in FQDN '%s'. This is usually a mistake caused by a missing dot at the end of the name specification.", name, zone, fqdn),
		"data":    map[string]any{"record": name, "zone": zone, "fqdn": fqdn},
	}}
}

// recordOpts are the *record options of c.
func recordOpts(c Call) map[string][]string {
	out := map[string][]string{}
	for k, v := range c.Options {
		if t, ok := strings.CutSuffix(k, "record"); ok && t != "" {
			if vals := strs(v); len(vals) > 0 {
				out[k] = vals
			}
		}
	}
	return out
}

func dnsrecordShow(s *Server, c Call) (any, *ipa.IpaError) {
	zone, name, z, err := s.recordArgs(c)
	if err != nil {
		return nil, err
	}
	if _, ok := z.records[name]; !ok {
		return nil, notFound(name, "DNS resource record")
	}
	return entry(name, z.renderRecord(zone, name, flag(c, "all")), ""), nil
}

func dnsrecordFind(s *Server, c Call) (any, *ipa.IpaError) {
	zone, z, err := s.zoneArg(c)
	if err != nil {
		return nil, err
	}
	needle := ""
	if len(c.Args) > 1 {
		needle = strings.ToLower(c.Args[1])
	}
	var recs []map[string]any
	for _, name := range slices.Sorted(maps.Keys(z.records)) {
		if !strings.Contains(strings.ToLower(name), needle) || !matches(c, "idnsname", name) {
			continue
		}
		recs = append(recs, z.renderRecord(zone, name, flag(c, "all")))
	}
	return listLimited(c, recs), nil
}

func dnsrecordAdd(s *Server, c Call) (any, *ipa.IpaError) {
	zone, name, z, err := s.recordArgs(c)
	if err != nil {
		return nil, err
	}
	add := recordOpts(c)
	if len(add) == 0 {
		return nil, &ipa.IpaError{Code: ipa.CodeOption, Message: "No options to add a specific record provided.\nCommand help may be consulted for all supported record types."}
	}
	r := z.records[name]
	if r == nil {
		r = map[string][]string{}
	}
	changed := false
	for k, vals := range add {
		for _, v := range vals {
			if !slices.Contains(r[k], v) {
				r[k] = append(r[k], v)
				changed = true
			}
		}
	}
	if !changed {
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	z.records[name] = r
	out := entry(name, z.renderRecord(zone, name, flag(c, "all")), "")
	if m := suspiciousName(zone, name); m != nil {
		out["messages"] = m
	}
	return out, nil
}

func dnsrecordDel(s *Server, c Call) (any, *ipa.IpaError) {
	_, name, z, err := s.recordArgs(c)
	if err != nil {
		return nil, err
	}
	r, ok := z.records[name]
	if !ok {
		return nil, notFound(name, "DNS resource record")
	}
	del := recordOpts(c)
	switch {
	case flag(c, "del_all") && name == "@":
		return nil, invalid("invalid 'del_all': Zone record '@' cannot be deleted")
	case flag(c, "del_all"):
		delete(z.records, name)
	case len(del) == 0:
		return nil, &ipa.IpaError{Code: ipa.CodeOption, Message: "Neither --del-all nor options to delete a specific record provided.\nCommand help may be consulted for all supported record types."}
	default:
		for k, vals := range del {
			for _, v := range vals {
				if !slices.Contains(r[k], v) {
					return nil, &ipa.IpaError{Code: ipa.CodeAttrValueNotFound, Message: fmt.Sprintf("%s record does not contain '%s'", strings.ToUpper(strings.TrimSuffix(k, "record")), v)}
				}
			}
		}
		for k, vals := range del {
			r[k] = slices.DeleteFunc(r[k], func(v string) bool { return slices.Contains(vals, v) })
			if len(r[k]) == 0 {
				delete(r, k)
			}
		}
		if len(r) == 0 && name != "@" { // the apex is the zone entry and stays
			delete(z.records, name)
		}
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   []string{name},
		"summary": fmt.Sprintf("Deleted record %q", name),
	}, nil
}

func init() {
	builtins["dnszone_show"] = dnszoneShow
	builtins["dnszone_find"] = dnszoneFind
	builtins["dnszone_add"] = dnszoneAdd
	builtins["dnszone_del"] = dnszoneDel
	builtins["dnszone_enable"] = dnszoneToggle(true)
	builtins["dnszone_disable"] = dnszoneToggle(false)
	builtins["dnsrecord_show"] = dnsrecordShow
	builtins["dnsrecord_find"] = dnsrecordFind
	builtins["dnsrecord_add"] = dnsrecordAdd
	builtins["dnsrecord_del"] = dnsrecordDel
}
