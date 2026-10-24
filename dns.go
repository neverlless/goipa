// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
)

// DNSZone is a master DNS zone of FreeIPA's integrated DNS. Change other
// attributes with Modify("dnszone_mod", name).
type DNSZone struct {
	Name       string // idnsname, absolute with trailing dot
	Active     bool   // idnszoneactive
	NameServer string // idnssoamname
	AdminEmail string // idnssoarname, in DNS form, relative to the zone unless it ends in "." ("hostmaster")
	// idnssoaserial, idnssoarefresh, idnssoaretry, idnssoaexpire, idnssoaminimum
	Serial, Refresh, Retry, Expire, Minimum int64
	TTL                                     int64 // dnsttl (0 if unset)
	DynamicUpdate                           bool  // idnsallowdynupdate
}

// DNSRecord is the set of resource records at one name of a zone. Change
// TTLs and other attributes with Modify("dnsrecord_mod", zone, name).
type DNSRecord struct {
	Name string // idnsname, relative ("@" is the apex)
	// Values by upper-case type ("A" holds arecord), from every *record
	// attribute.
	Records map[string][]string
}

func dnsZoneFrom(e Entry) *DNSZone {
	z := &DNSZone{
		Name:          e.Str("idnsname"),
		Active:        e.Bool("idnszoneactive"),
		NameServer:    e.Str("idnssoamname"),
		AdminEmail:    e.Str("idnssoarname"),
		DynamicUpdate: e.Bool("idnsallowdynupdate"),
	}
	z.Serial, _ = e.Int("idnssoaserial")
	z.Refresh, _ = e.Int("idnssoarefresh")
	z.Retry, _ = e.Int("idnssoaretry")
	z.Expire, _ = e.Int("idnssoaexpire")
	z.Minimum, _ = e.Int("idnssoaminimum")
	z.TTL, _ = e.Int("dnsttl")
	return z
}

func dnsRecordFrom(e Entry) *DNSRecord {
	r := &DNSRecord{Name: e.Str("idnsname"), Records: map[string][]string{}}
	gjson.ParseBytes(e.Raw()).ForEach(func(k, _ gjson.Result) bool {
		if t, ok := strings.CutSuffix(k.String(), "record"); ok && t != "" {
			if v := e.Strs(k.String()); len(v) > 0 {
				r.Records[strings.ToUpper(t)] = v
			}
		}
		return true
	})
	return r
}

// recordOption maps a record type to its dnsrecord_add option ("A" → arecord).
func recordOption(rtype string) (string, error) {
	opt := strings.ToLower(rtype) + "record"
	cmd, _ := LookupCommand("dnsrecord_add", "")
	if rtype == "" || !slices.ContainsFunc(cmd.Options, func(p Param) bool { return p.Name == opt }) {
		return "", fmt.Errorf("%w: unknown DNS record type %q", ErrInvalidCall, rtype)
	}
	return opt, nil
}

var (
	errZoneRequired   = errors.New("ipa: dns zone name is required")
	errRecordRequired = errors.New("ipa: dns record name is required")
	errValueRequired  = errors.New("ipa: dns record value is required")
)

// DNSZoneShow fetches a zone with `dnszone_show`; it requires the DNS
// Administrators privilege (System: Read DNS Entries).
func (c *Client) DNSZoneShow(name string) (*DNSZone, error) {
	return c.DNSZoneShowContext(context.Background(), name)
}

// DNSZoneShowContext is like DNSZoneShow but bounds the request with ctx.
func (c *Client) DNSZoneShowContext(ctx context.Context, name string) (*DNSZone, error) {
	if name == "" {
		return nil, errZoneRequired
	}
	e, _, err := Call[Entry](ctx, c, "dnszone_show", []string{name}, Options{"all": true})
	if err != nil {
		return nil, err
	}
	return dnsZoneFrom(e), nil
}

// DNSZoneFind finds zones with `dnszone_find`; options are passed through
// (e.g. `idnsname`, `sizelimit`). A truncated search returns the zones found
// and ErrTruncated. It requires the DNS Administrators privilege (System:
// Read DNS Entries).
func (c *Client) DNSZoneFind(options Options) ([]*DNSZone, error) {
	return c.DNSZoneFindContext(context.Background(), options)
}

// DNSZoneFindContext is like DNSZoneFind but bounds the request with ctx.
func (c *Client) DNSZoneFindContext(ctx context.Context, options Options) ([]*DNSZone, error) {
	return dnsFind(ctx, c, "dnszone_find", []string{""}, options, dnsZoneFrom)
}

// dnsFind is findTyped without no_members, which the dns commands lack.
func dnsFind[T any](ctx context.Context, c *Client, method string, args []string, options Options, conv func(Entry) *T) ([]*T, error) {
	entries, err := FindEntries(ctx, c, method, args, options, 0)
	if err != nil && !errors.Is(err, ErrTruncated) {
		return nil, err
	}
	out := make([]*T, len(entries))
	for i, e := range entries {
		out[i] = conv(e)
	}
	return out, err
}

// DNSZoneAdd creates a master zone with `dnszone_add` and returns it; force
// is FreeIPA's force flag, which skips the name server and overlap checks.
// It requires the DNS Administrators privilege (System: Add DNS Entries).
func (c *Client) DNSZoneAdd(name string, force bool) (*DNSZone, error) {
	return c.DNSZoneAddContext(context.Background(), name, force)
}

// DNSZoneAddContext is like DNSZoneAdd but bounds the request with ctx.
func (c *Client) DNSZoneAddContext(ctx context.Context, name string, force bool) (*DNSZone, error) {
	if name == "" {
		return nil, errZoneRequired
	}
	o := Options{"all": true}
	if force {
		o["force"] = true
	}
	e, _, err := Call[Entry](ctx, c, "dnszone_add", []string{name}, o)
	if err != nil {
		return nil, err
	}
	return dnsZoneFrom(e), nil
}

// DNSZoneDelete deletes zones, with all their records, with `dnszone_del`;
// it requires the DNS Administrators privilege (System: Remove DNS Entries).
func (c *Client) DNSZoneDelete(names ...string) error {
	return c.DNSZoneDeleteContext(context.Background(), names...)
}

// DNSZoneDeleteContext is like DNSZoneDelete but bounds the request with ctx.
func (c *Client) DNSZoneDeleteContext(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return errZoneRequired
	}
	_, err := c.rpc(ctx, "dnszone_del", names, nil)
	return err
}

// DNSZoneEnable activates a zone with `dnszone_enable`; it requires the DNS
// Administrators privilege (System: Update DNS Entries).
func (c *Client) DNSZoneEnable(name string) error {
	return c.DNSZoneEnableContext(context.Background(), name)
}

// DNSZoneEnableContext is like DNSZoneEnable but bounds the request with ctx.
func (c *Client) DNSZoneEnableContext(ctx context.Context, name string) error {
	return c.dnsZoneToggle(ctx, "dnszone_enable", name)
}

// DNSZoneDisable deactivates a zone with `dnszone_disable`; disabling a
// disabled zone succeeds. It requires the DNS Administrators privilege
// (System: Update DNS Entries).
func (c *Client) DNSZoneDisable(name string) error {
	return c.DNSZoneDisableContext(context.Background(), name)
}

// DNSZoneDisableContext is like DNSZoneDisable but bounds the request with ctx.
func (c *Client) DNSZoneDisableContext(ctx context.Context, name string) error {
	return c.dnsZoneToggle(ctx, "dnszone_disable", name)
}

func (c *Client) dnsZoneToggle(ctx context.Context, method, name string) error {
	if name == "" {
		return errZoneRequired
	}
	_, err := c.rpc(ctx, method, []string{name}, nil)
	return err
}

func dnsRecordArgs(zone, name string) ([]string, error) {
	switch {
	case zone == "":
		return nil, errZoneRequired
	case name == "":
		return nil, errRecordRequired
	}
	return []string{zone, name}, nil
}

// DNSRecordShow fetches the records at name in zone with `dnsrecord_show`;
// it requires the DNS Administrators privilege (System: Read DNS Entries).
func (c *Client) DNSRecordShow(zone, name string) (*DNSRecord, error) {
	return c.DNSRecordShowContext(context.Background(), zone, name)
}

// DNSRecordShowContext is like DNSRecordShow but bounds the request with ctx.
func (c *Client) DNSRecordShowContext(ctx context.Context, zone, name string) (*DNSRecord, error) {
	args, err := dnsRecordArgs(zone, name)
	if err != nil {
		return nil, err
	}
	e, _, err := Call[Entry](ctx, c, "dnsrecord_show", args, Options{"all": true})
	if err != nil {
		return nil, err
	}
	return dnsRecordFrom(e), nil
}

// DNSRecordFind finds the record names of zone with `dnsrecord_find`; options
// are passed through (e.g. `idnsname`, `arecord`, `sizelimit`). A truncated
// search returns the records found and ErrTruncated. It requires the DNS
// Administrators privilege (System: Read DNS Entries).
func (c *Client) DNSRecordFind(zone string, options Options) ([]*DNSRecord, error) {
	return c.DNSRecordFindContext(context.Background(), zone, options)
}

// DNSRecordFindContext is like DNSRecordFind but bounds the request with ctx.
func (c *Client) DNSRecordFindContext(ctx context.Context, zone string, options Options) ([]*DNSRecord, error) {
	if zone == "" {
		return nil, errZoneRequired
	}
	return dnsFind(ctx, c, "dnsrecord_find", []string{zone}, options, dnsRecordFrom)
}

func dnsRecordValues(zone, name, rtype string, values []string) ([]string, Options, error) {
	args, err := dnsRecordArgs(zone, name)
	if err != nil {
		return nil, nil, err
	}
	opt, err := recordOption(rtype)
	if err != nil {
		return nil, nil, err
	}
	if len(values) == 0 {
		return nil, nil, errValueRequired
	}
	return args, Options{opt: values}, nil
}

// DNSRecordAdd adds values of type rtype (case-insensitive, "A" or "txt") at
// name in zone with `dnsrecord_add`, creating the name if needed, and returns
// all its records. A type the command catalogue does not know fails with
// ErrInvalidCall before anything is sent. It requires the DNS Administrators
// privilege (System: Add DNS Entries, or Update DNS Entries for an existing
// name).
func (c *Client) DNSRecordAdd(zone, name, rtype string, values ...string) (*DNSRecord, error) {
	return c.DNSRecordAddContext(context.Background(), zone, name, rtype, values...)
}

// DNSRecordAddContext is like DNSRecordAdd but bounds the request with ctx.
func (c *Client) DNSRecordAddContext(ctx context.Context, zone, name, rtype string, values ...string) (*DNSRecord, error) {
	args, o, err := dnsRecordValues(zone, name, rtype, values)
	if err != nil {
		return nil, err
	}
	o["all"] = true
	e, _, err := Call[Entry](ctx, c, "dnsrecord_add", args, o)
	if err != nil {
		return nil, err
	}
	return dnsRecordFrom(e), nil
}

// DNSRecordRemove removes values of type rtype at name in zone with
// `dnsrecord_del`; FreeIPA deletes the name when no records are left. It
// requires the DNS Administrators privilege (System: Update DNS Entries).
func (c *Client) DNSRecordRemove(zone, name, rtype string, values ...string) error {
	return c.DNSRecordRemoveContext(context.Background(), zone, name, rtype, values...)
}

// DNSRecordRemoveContext is like DNSRecordRemove but bounds the request with ctx.
func (c *Client) DNSRecordRemoveContext(ctx context.Context, zone, name, rtype string, values ...string) error {
	args, o, err := dnsRecordValues(zone, name, rtype, values)
	if err != nil {
		return err
	}
	_, err = c.rpc(ctx, "dnsrecord_del", args, o)
	return err
}

// DNSRecordDelete deletes name and all its records from zone with
// `dnsrecord_del` del_all; it requires the DNS Administrators privilege
// (System: Remove DNS Entries).
func (c *Client) DNSRecordDelete(zone, name string) error {
	return c.DNSRecordDeleteContext(context.Background(), zone, name)
}

// DNSRecordDeleteContext is like DNSRecordDelete but bounds the request with ctx.
func (c *Client) DNSRecordDeleteContext(ctx context.Context, zone, name string) error {
	args, err := dnsRecordArgs(zone, name)
	if err != nil {
		return err
	}
	_, err = c.rpc(ctx, "dnsrecord_del", args, Options{"del_all": true})
	return err
}
