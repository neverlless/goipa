// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"
	"slices"

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
	// randompassword, set only by an add with random
	RandomPassword string
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
	h.RandomPassword = res.Get("randompassword").String()
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
//
// A truncated search is not reported (kept for compatibility); use FindEntries
// with the same method to detect it.
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

var errHostFQDN = errors.New("ipa: host fqdn is required")

// hostAttrs are the seven attributes HostAdd and HostMod send; an empty
// value is "no value".
func hostAttrs(h *Host) Options {
	return Options{
		"description": h.Description, "l": h.Locality, "nshostlocation": h.Location,
		"nshardwareplatform": h.Platform, "nsosversion": h.OSVersion,
		"macaddress": nonNil(h.MACAddresses), "userclass": nonNil(h.UserClass),
	}
}

// nonNil keeps a nil list from going out as JSON null.
func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func (c *Client) hostAdd(ctx context.Context, h *Host, force bool, extra Options) (*Host, error) {
	if h == nil || h.FQDN == "" {
		return nil, errHostFQDN
	}
	o := nonEmpty(hostAttrs(h))
	o["all"], o["no_members"] = true, false
	if force {
		o["force"] = true
	}
	for k, v := range extra {
		o[k] = v
	}
	res, err := c.rpc(ctx, "host_add", []string{h.FQDN}, o)
	if err != nil {
		return nil, err
	}
	out := new(Host)
	if err := out.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return out, nil
}

// HostAdd adds a host with `host_add`; it requires the Host Administrators
// privilege (System: Add Hosts). force skips FreeIPA's DNS check of the fqdn.
// If random is true the server generates a one-time enrollment password,
// returned in RandomPassword. Adding an existing host returns the bare
// *IpaError (ErrDuplicateEntry).
func (c *Client) HostAdd(h *Host, force, random bool) (*Host, error) {
	return c.HostAddContext(context.Background(), h, force, random)
}

// HostAddContext is like HostAdd but bounds the request with ctx.
func (c *Client) HostAddContext(ctx context.Context, h *Host, force, random bool) (*Host, error) {
	var extra Options
	if random {
		extra = Options{"random": true}
	}
	return c.hostAdd(ctx, h, force, extra)
}

// HostAddWithPassword adds a host with a one-time enrollment password
// (`host_add` with userpassword); it requires the Host Administrators
// privilege (System: Add Hosts). Adding an existing host returns the bare
// *IpaError (ErrDuplicateEntry).
func (c *Client) HostAddWithPassword(h *Host, force bool, password string) (*Host, error) {
	return c.HostAddWithPasswordContext(context.Background(), h, force, password)
}

// HostAddWithPasswordContext is like HostAddWithPassword but bounds the request with ctx.
func (c *Client) HostAddWithPasswordContext(ctx context.Context, h *Host, force bool, password string) (*Host, error) {
	if password == "" {
		return nil, errors.New("ipa: password is required")
	}
	return c.hostAdd(ctx, h, force, Options{"userpassword": password})
}

// HostMod changes a host with `host_mod`; it requires the Host Administrators
// privilege (System: Modify Hosts). It sends description, locality, location,
// platform, OS version, MAC addresses and user classes as they are in h; an
// empty value clears the attribute. If nothing changes it returns h itself.
func (c *Client) HostMod(h *Host) (*Host, error) {
	return c.HostModContext(context.Background(), h)
}

// HostModContext is like HostMod but bounds the request with ctx.
func (c *Client) HostModContext(ctx context.Context, h *Host) (*Host, error) {
	if h == nil || h.FQDN == "" {
		return nil, errHostFQDN
	}
	o := hostAttrs(h)
	o["all"], o["no_members"] = true, false
	res, err := c.rpc(ctx, "host_mod", []string{h.FQDN}, o)
	if err != nil {
		if errors.Is(err, ErrEmptyModlist) {
			return h, nil
		}
		return nil, err
	}
	out := new(Host)
	if err := out.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return out, nil
}

// HostDelete deletes hosts with `host_del`; it requires the Host
// Administrators privilege (System: Remove Hosts). If updateDNS is true the
// host's DNS records are removed too.
func (c *Client) HostDelete(updateDNS bool, fqdns ...string) error {
	return c.HostDeleteContext(context.Background(), updateDNS, fqdns...)
}

// HostDeleteContext is like HostDelete but bounds the request with ctx.
func (c *Client) HostDeleteContext(ctx context.Context, updateDNS bool, fqdns ...string) error {
	if len(fqdns) == 0 || slices.Contains(fqdns, "") {
		return errHostFQDN
	}
	o := Options{"continue": false}
	if updateDNS {
		o["updatedns"] = true
	}
	_, err := c.rpc(ctx, "host_del", fqdns, o)
	return err
}

// HostDisable removes the host's Kerberos keys with `host_disable`; it requires the Host Administrators privilege (System:
// Manage Host Keytab). A host without keys, which includes one that was only
// added and never enrolled, is the server's *IpaError 4010 (AlreadyInactive).
func (c *Client) HostDisable(fqdn string) error {
	return c.HostDisableContext(context.Background(), fqdn)
}

// HostDisableContext is like HostDisable but bounds the request with ctx.
func (c *Client) HostDisableContext(ctx context.Context, fqdn string) error {
	if fqdn == "" {
		return errHostFQDN
	}
	_, err := c.rpc(ctx, "host_disable", []string{fqdn}, nil)
	return err
}
