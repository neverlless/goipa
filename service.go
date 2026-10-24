// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"

	"github.com/tidwall/gjson"
)

// KeytabAccess lists who may retrieve or create a service's keytab.
type KeytabAccess struct{ Users, Groups, Hosts, HostGroups []string }

func (a KeytabAccess) lists() map[string][]string {
	return map[string][]string{"user": a.Users, "group": a.Groups, "host": a.Hosts, "hostgroup": a.HostGroups}
}

// Service is a FreeIPA Kerberos service principal. Attribute changes go
// through Modify with `service_mod`.
type Service struct {
	Principal      string   // krbcanonicalname
	Aliases        []string // krbprincipalname
	ManagedBy      []string // managedby_host
	HasKeytab      bool     // has_keytab
	Certificates   [][]byte // usercertificate (DER)
	AuthIndicators []string // krbprincipalauthind
	// ipakrbokasdelegate, ipakrboktoauthasdelegate, ipakrbrequirespreauth
	OKAsDelegate, OKToAuthAsDelegate, RequiresPreAuth bool
	// ipaallowedtoperform_read_keys_{user,group,host,hostgroup} and
	// ipaallowedtoperform_write_keys_*
	KeytabRetrieve, KeytabCreate KeytabAccess
}

func keytabAccess(e Entry, op string) KeytabAccess {
	p := "ipaallowedtoperform_" + op + "_keys_"
	return KeytabAccess{Users: e.Strs(p + "user"), Groups: e.Strs(p + "group"), Hosts: e.Strs(p + "host"), HostGroups: e.Strs(p + "hostgroup")}
}

func serviceFromEntry(e Entry) *Service {
	s := &Service{
		Principal:          e.Str("krbcanonicalname"),
		Aliases:            e.Strs("krbprincipalname"),
		ManagedBy:          e.Strs("managedby_host"),
		HasKeytab:          e.Bool("has_keytab"),
		AuthIndicators:     e.Strs("krbprincipalauthind"),
		OKAsDelegate:       e.Bool("ipakrbokasdelegate"),
		OKToAuthAsDelegate: e.Bool("ipakrboktoauthasdelegate"),
		RequiresPreAuth:    e.Bool("ipakrbrequirespreauth"),
		KeytabRetrieve:     keytabAccess(e, "read"),
		KeytabCreate:       keytabAccess(e, "write"),
	}
	gjson.GetBytes(e.Raw(), "usercertificate").ForEach(func(_, v gjson.Result) bool {
		if der, err := base64.StdEncoding.DecodeString(v.Get("__base64__").String()); err == nil && len(der) > 0 {
			s.Certificates = append(s.Certificates, der)
		}
		return true
	})
	return s
}

var errServicePrincipal = errors.New("ipa: service principal is required")

// ServiceShow fetches a service with `service_show`; the realm may be left
// out of principal. Any authenticated user may read services (System: Read
// Services).
func (c *Client) ServiceShow(principal string) (*Service, error) {
	return c.ServiceShowContext(context.Background(), principal)
}

// ServiceShowContext is like ServiceShow but bounds the request with ctx.
func (c *Client) ServiceShowContext(ctx context.Context, principal string) (*Service, error) {
	if principal == "" {
		return nil, errServicePrincipal
	}
	return showEntry(ctx, c, "service_show", []string{principal}, serviceFromEntry)
}

// ServiceFind finds services with `service_find`; options are passed through
// (e.g. `krbcanonicalname`, `man_by_host`, `sizelimit`). A truncated result
// comes back with ErrTruncated. Any authenticated user may read services
// (System: Read Services).
func (c *Client) ServiceFind(options Options) ([]*Service, error) {
	return c.ServiceFindContext(context.Background(), options)
}

// ServiceFindContext is like ServiceFind but bounds the request with ctx.
func (c *Client) ServiceFindContext(ctx context.Context, options Options) ([]*Service, error) {
	return findTyped(ctx, c, "service_find", []string{""}, options, serviceFromEntry)
}

// ServiceAdd creates a service with `service_add` for a host FreeIPA already
// knows; it requires the Service Administrators privilege (System: Add
// Services). force skips FreeIPA's DNS check of the host.
func (c *Client) ServiceAdd(principal string, force bool) (*Service, error) {
	return c.ServiceAddContext(context.Background(), principal, force)
}

// ServiceAddContext is like ServiceAdd but bounds the request with ctx.
func (c *Client) ServiceAddContext(ctx context.Context, principal string, force bool) (*Service, error) {
	if principal == "" {
		return nil, errServicePrincipal
	}
	o := Options{"all": true, "no_members": false}
	if force {
		o["force"] = true
	}
	e, _, err := Call[Entry](ctx, c, "service_add", []string{principal}, o)
	if err != nil {
		return nil, err
	}
	return serviceFromEntry(e), nil
}

// ServiceDelete deletes services with `service_del`; it requires the Service
// Administrators privilege (System: Remove Services).
func (c *Client) ServiceDelete(principals ...string) error {
	return c.ServiceDeleteContext(context.Background(), principals...)
}

// ServiceDeleteContext is like ServiceDelete but bounds the request with ctx.
func (c *Client) ServiceDeleteContext(ctx context.Context, principals ...string) error {
	if len(principals) == 0 || slices.Contains(principals, "") {
		return errServicePrincipal
	}
	_, err := c.rpc(ctx, "service_del", principals, Options{"continue": false})
	return err
}

func (c *Client) serviceMembers(ctx context.Context, method, principal string, lists map[string][]string) (*Service, error) {
	if principal == "" {
		return nil, errServicePrincipal
	}
	return members(ctx, c, method, []string{principal}, lists, serviceFromEntry)
}

// ServiceAddHost lets hosts manage a service (managedby) with
// `service_add_host`; no FreeIPA permission grants writing a
// service's managedby, so it needs an admin. Per-host problems come back as
// *MemberError with the service as it stands.
func (c *Client) ServiceAddHost(principal string, hosts []string) (*Service, error) {
	return c.ServiceAddHostContext(context.Background(), principal, hosts)
}

// ServiceAddHostContext is like ServiceAddHost but bounds the request with ctx.
func (c *Client) ServiceAddHostContext(ctx context.Context, principal string, hosts []string) (*Service, error) {
	return c.serviceMembers(ctx, "service_add_host", principal, map[string][]string{"host": hosts})
}

// ServiceRemoveHost stops hosts managing a service with
// `service_remove_host`; no FreeIPA permission grants writing a
// service's managedby, so it needs an admin. Per-host problems come back as
// *MemberError with the service as it stands.
func (c *Client) ServiceRemoveHost(principal string, hosts []string) (*Service, error) {
	return c.ServiceRemoveHostContext(context.Background(), principal, hosts)
}

// ServiceRemoveHostContext is like ServiceRemoveHost but bounds the request with ctx.
func (c *Client) ServiceRemoveHostContext(ctx context.Context, principal string, hosts []string) (*Service, error) {
	return c.serviceMembers(ctx, "service_remove_host", principal, map[string][]string{"host": hosts})
}

// ServiceAllowRetrieveKeytab lets a's users, groups, hosts and host groups
// retrieve the service's keytab with `service_allow_retrieve_keytab`; it
// requires the Service Administrators privilege (System: Manage Service
// Keytab Permissions). Per-member problems come back as *MemberError with the
// service as it stands.
func (c *Client) ServiceAllowRetrieveKeytab(principal string, a KeytabAccess) (*Service, error) {
	return c.ServiceAllowRetrieveKeytabContext(context.Background(), principal, a)
}

// ServiceAllowRetrieveKeytabContext is like ServiceAllowRetrieveKeytab but bounds the request with ctx.
func (c *Client) ServiceAllowRetrieveKeytabContext(ctx context.Context, principal string, a KeytabAccess) (*Service, error) {
	return c.serviceMembers(ctx, "service_allow_retrieve_keytab", principal, a.lists())
}

// ServiceDisallowRetrieveKeytab revokes what ServiceAllowRetrieveKeytab
// granted, with `service_disallow_retrieve_keytab`; it requires the Service
// Administrators privilege (System: Manage Service Keytab Permissions).
// Per-member problems come back as *MemberError with the service as it
// stands.
func (c *Client) ServiceDisallowRetrieveKeytab(principal string, a KeytabAccess) (*Service, error) {
	return c.ServiceDisallowRetrieveKeytabContext(context.Background(), principal, a)
}

// ServiceDisallowRetrieveKeytabContext is like ServiceDisallowRetrieveKeytab but bounds the request with ctx.
func (c *Client) ServiceDisallowRetrieveKeytabContext(ctx context.Context, principal string, a KeytabAccess) (*Service, error) {
	return c.serviceMembers(ctx, "service_disallow_retrieve_keytab", principal, a.lists())
}

// ServiceAllowCreateKeytab lets a's users, groups, hosts and host groups
// create (and so reset) the service's keys with
// `service_allow_create_keytab`; it requires the Service Administrators
// privilege (System: Manage Service Keytab Permissions). Per-member problems
// come back as *MemberError with the service as it stands.
func (c *Client) ServiceAllowCreateKeytab(principal string, a KeytabAccess) (*Service, error) {
	return c.ServiceAllowCreateKeytabContext(context.Background(), principal, a)
}

// ServiceAllowCreateKeytabContext is like ServiceAllowCreateKeytab but bounds the request with ctx.
func (c *Client) ServiceAllowCreateKeytabContext(ctx context.Context, principal string, a KeytabAccess) (*Service, error) {
	return c.serviceMembers(ctx, "service_allow_create_keytab", principal, a.lists())
}

// ServiceDisallowCreateKeytab revokes what ServiceAllowCreateKeytab granted,
// with `service_disallow_create_keytab`; it requires the Service
// Administrators privilege (System: Manage Service Keytab Permissions).
// Per-member problems come back as *MemberError with the service as it
// stands.
func (c *Client) ServiceDisallowCreateKeytab(principal string, a KeytabAccess) (*Service, error) {
	return c.ServiceDisallowCreateKeytabContext(context.Background(), principal, a)
}

// ServiceDisallowCreateKeytabContext is like ServiceDisallowCreateKeytab but bounds the request with ctx.
func (c *Client) ServiceDisallowCreateKeytabContext(ctx context.Context, principal string, a KeytabAccess) (*Service, error) {
	return c.serviceMembers(ctx, "service_disallow_create_keytab", principal, a.lists())
}

// ServiceDisable removes a service's keys, and revokes and removes the
// certificates FreeIPA's CA issued it, with `service_disable`; it requires
// the Service Administrators privilege (System: Manage Service Keytab).
// Before FreeIPA 4.13 certificates from elsewhere stay, and a service with
// neither keys nor CA-issued certificates is the server's *IpaError 4010
// (AlreadyInactive); 4.13 removes those certificates too.
func (c *Client) ServiceDisable(principal string) error {
	return c.ServiceDisableContext(context.Background(), principal)
}

// ServiceDisableContext is like ServiceDisable but bounds the request with ctx.
func (c *Client) ServiceDisableContext(ctx context.Context, principal string) error {
	if principal == "" {
		return errServicePrincipal
	}
	_, err := c.rpc(ctx, "service_disable", []string{principal}, nil)
	return err
}
