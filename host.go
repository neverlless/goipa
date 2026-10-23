// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"

	"github.com/tidwall/gjson"
)

// Host is a FreeIPA host.
type Host struct {
	// fqdn, description, l, nshostlocation, nshardwareplatform, nsosversion,
	// krbprincipalname (first value of each)
	FQDN, Description, Locality, Location, Platform, OSVersion, Principal string
	// macaddress, userclass
	MACAddresses, UserClass []string
	// memberof_hostgroup, memberofindirect_hostgroup
	HostGroups, IndirectHostGroups []string
	// managedby_host
	ManagedBy []string
	// has_keytab, has_password
	HasKeytab, HasPassword bool
}

func (h *Host) fromJSON(raw []byte) error {
	if !gjson.ValidBytes(raw) {
		return errors.New("invalid host record json")
	}
	res := gjson.ParseBytes(raw)

	h.FQDN = res.Get("fqdn.0").String()
	h.Description = res.Get("description.0").String()
	h.Locality = res.Get("l.0").String()
	h.Location = res.Get("nshostlocation.0").String()
	h.Platform = res.Get("nshardwareplatform.0").String()
	h.OSVersion = res.Get("nsosversion.0").String()
	h.Principal = res.Get("krbprincipalname.0").String()
	h.MACAddresses = strList(res, "macaddress")
	h.UserClass = strList(res, "userclass")
	h.HostGroups = strList(res, "memberof_hostgroup")
	h.IndirectHostGroups = strList(res, "memberofindirect_hostgroup")
	h.ManagedBy = strList(res, "managedby_host")
	h.HasKeytab = res.Get("has_keytab").Bool()
	h.HasPassword = res.Get("has_password").Bool()
	return nil
}

// HostShow fetches a host with `host_show`. Any authenticated user may read
// hosts (System: Read Hosts). ubccr/goipa#11.
func (c *Client) HostShow(fqdn string) (*Host, error) {
	return c.HostShowContext(context.Background(), fqdn)
}

// HostShowContext is like HostShow but bounds the request with ctx.
func (c *Client) HostShowContext(ctx context.Context, fqdn string) (*Host, error) {
	if fqdn == "" {
		return nil, errors.New("ipa: host fqdn is required")
	}
	res, err := c.rpc(ctx, "host_show", []string{fqdn}, Options{"no_members": false, "all": true})
	if err != nil {
		return nil, err
	}
	h := new(Host)
	if err := h.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return h, nil
}

// HostFind finds hosts with `host_find`; options are passed through (e.g.
// `fqdn`, `in_hostgroup`, `sizelimit`). Any authenticated user may read hosts
// (System: Read Hosts). ubccr/goipa#11.
func (c *Client) HostFind(options Options) ([]*Host, error) {
	return c.HostFindContext(context.Background(), options)
}

// HostFindContext is like HostFind but bounds the request with ctx.
func (c *Client) HostFindContext(ctx context.Context, options Options) ([]*Host, error) {
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}
	options["no_members"] = false
	options["all"] = true

	res, err := c.rpc(ctx, "host_find", []string{""}, options)
	if err != nil {
		return nil, err
	}
	hosts := make([]*Host, 0)
	for _, t := range gjson.ParseBytes(res.Result.Data).Array() {
		h := new(Host)
		if err := h.fromJSON([]byte(t.Raw)); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}
