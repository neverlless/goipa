// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/tidwall/gjson"
)

// Automember rule types: a rule adds users to a group or hosts to a host
// group.
const (
	AutomemberGroup     = "group"
	AutomemberHostGroup = "hostgroup"
)

// AutomemberCondition is one regular expression on an entry attribute,
// stored by FreeIPA as "key=regex".
type AutomemberCondition struct{ Key, Regex string }

// AutomemberRule is a FreeIPA automember rule. Its name is the target group
// or host group. A description change goes through RPC with automember_mod:
// that command needs the type option, which Modify does not send.
type AutomemberRule struct {
	Name, Type, Description string // cn, the type the call used, description
	// automemberinclusiveregex, automemberexclusiveregex
	Inclusive, Exclusive []AutomemberCondition
}

func conditions(vals []string) []AutomemberCondition {
	var out []AutomemberCondition
	for _, v := range vals {
		k, re, _ := strings.Cut(v, "=")
		out = append(out, AutomemberCondition{Key: k, Regex: re})
	}
	return out
}

func automemberRule(typ string) func(Entry) *AutomemberRule {
	return func(e Entry) *AutomemberRule {
		return &AutomemberRule{
			Name: e.Str("cn"), Type: typ, Description: e.Str("description"),
			Inclusive: conditions(e.Strs("automemberinclusiveregex")),
			Exclusive: conditions(e.Strs("automemberexclusiveregex")),
		}
	}
}

func checkAutomemberType(typ string) error {
	if typ != AutomemberGroup && typ != AutomemberHostGroup {
		return errors.New(`ipa: automember type must be "group" or "hostgroup"`)
	}
	return nil
}

func checkAutomemberRule(typ, name string) error {
	if err := checkAutomemberType(typ); err != nil {
		return err
	}
	if name == "" {
		return errors.New("ipa: automember rule name is required")
	}
	return nil
}

// AutomemberShow fetches a rule of type typ (AutomemberGroup or
// AutomemberHostGroup) with `automember_show`; it requires the Automember
// Readers privilege (System: Read Automember Rules).
func (c *Client) AutomemberShow(typ, name string) (*AutomemberRule, error) {
	return c.AutomemberShowContext(context.Background(), typ, name)
}

// AutomemberShowContext is like AutomemberShow but bounds the request with ctx.
func (c *Client) AutomemberShowContext(ctx context.Context, typ, name string) (*AutomemberRule, error) {
	if err := checkAutomemberRule(typ, name); err != nil {
		return nil, err
	}
	// showEntry does not send the type option.
	e, _, err := Call[Entry](ctx, c, "automember_show", []string{name}, Options{"type": typ, "all": true})
	if err != nil {
		return nil, err
	}
	return automemberRule(typ)(e), nil
}

// AutomemberFind lists the rules of type typ with `automember_find`; options
// are passed through (e.g. `description`). A truncated search returns the
// rules found and ErrTruncated. It requires the Automember Readers privilege
// (System: Read Automember Rules).
func (c *Client) AutomemberFind(typ string, options Options) ([]*AutomemberRule, error) {
	return c.AutomemberFindContext(context.Background(), typ, options)
}

// AutomemberFindContext is like AutomemberFind but bounds the request with ctx.
func (c *Client) AutomemberFindContext(ctx context.Context, typ string, options Options) ([]*AutomemberRule, error) {
	if err := checkAutomemberType(typ); err != nil {
		return nil, err
	}
	o := maps.Clone(options)
	if o == nil {
		o = Options{}
	}
	o["type"] = typ
	return findTyped(ctx, c, "automember_find", []string{""}, o, automemberRule(typ))
}

// AutomemberAdd creates a rule with `automember_add`. name is the target
// group or host group, which must exist. FreeIPA ships no privilege for
// changing automember rules, so this and the other rule changes need an
// admin.
func (c *Client) AutomemberAdd(typ, name, description string) (*AutomemberRule, error) {
	return c.AutomemberAddContext(context.Background(), typ, name, description)
}

// AutomemberAddContext is like AutomemberAdd but bounds the request with ctx.
func (c *Client) AutomemberAddContext(ctx context.Context, typ, name, description string) (*AutomemberRule, error) {
	if err := checkAutomemberRule(typ, name); err != nil {
		return nil, err
	}
	o := Options{"type": typ, "all": true}
	if description != "" {
		o["description"] = description
	}
	e, _, err := Call[Entry](ctx, c, "automember_add", []string{name}, o)
	if err != nil {
		return nil, err
	}
	return automemberRule(typ)(e), nil
}

// AutomemberDelete deletes rules with `automember_del`; it needs an admin.
// FreeIPA deletes the rules named before the first missing one and then
// fails.
func (c *Client) AutomemberDelete(typ string, names ...string) error {
	return c.AutomemberDeleteContext(context.Background(), typ, names...)
}

// AutomemberDeleteContext is like AutomemberDelete but bounds the request
// with ctx.
func (c *Client) AutomemberDeleteContext(ctx context.Context, typ string, names ...string) error {
	if err := checkAutomemberType(typ); err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("ipa: automember rule name is required")
	}
	_, err := c.rpc(ctx, "automember_del", names, Options{"type": typ})
	return err
}

// AutomemberAddCondition adds inclusive and exclusive regular expressions on
// attribute key to a rule with `automember_add_condition` and returns the
// rule; it needs an admin. Conditions the rule already has are skipped
// silently.
func (c *Client) AutomemberAddCondition(typ, name, key string, inclusive, exclusive []string) (*AutomemberRule, error) {
	return c.AutomemberAddConditionContext(context.Background(), typ, name, key, inclusive, exclusive)
}

// AutomemberAddConditionContext is like AutomemberAddCondition but bounds the
// request with ctx.
func (c *Client) AutomemberAddConditionContext(ctx context.Context, typ, name, key string, inclusive, exclusive []string) (*AutomemberRule, error) {
	return c.automemberCondition(ctx, "automember_add_condition", typ, name, key, inclusive, exclusive)
}

// AutomemberRemoveCondition removes conditions on attribute key from a rule
// with `automember_remove_condition` and returns the rule; it needs an admin.
// Conditions the rule lacks come back as *MemberError (Type the regex
// attribute, Name "key=regex") together with the rule.
func (c *Client) AutomemberRemoveCondition(typ, name, key string, inclusive, exclusive []string) (*AutomemberRule, error) {
	return c.AutomemberRemoveConditionContext(context.Background(), typ, name, key, inclusive, exclusive)
}

// AutomemberRemoveConditionContext is like AutomemberRemoveCondition but
// bounds the request with ctx.
func (c *Client) AutomemberRemoveConditionContext(ctx context.Context, typ, name, key string, inclusive, exclusive []string) (*AutomemberRule, error) {
	return c.automemberCondition(ctx, "automember_remove_condition", typ, name, key, inclusive, exclusive)
}

func (c *Client) automemberCondition(ctx context.Context, method, typ, name, key string, inclusive, exclusive []string) (*AutomemberRule, error) {
	if err := checkAutomemberRule(typ, name); err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("ipa: automember condition key is required")
	}
	if len(inclusive) == 0 && len(exclusive) == 0 {
		return nil, errors.New("ipa: " + method + ": nothing to add or remove")
	}
	o := Options{"type": typ, "key": key, "all": true}
	if len(inclusive) > 0 {
		o["automemberinclusiveregex"] = inclusive
	}
	if len(exclusive) > 0 {
		o["automemberexclusiveregex"] = exclusive
	}
	e, res, err := Call[Entry](ctx, c, method, []string{name}, o)
	if err != nil {
		return nil, err
	}
	rule := automemberRule(typ)(e)
	if res.Completed == 0 {
		// With nothing changed FreeIPA returns only the regex attributes.
		if rule, err = c.AutomemberShowContext(ctx, typ, name); err != nil {
			return nil, err
		}
	}
	// failed is {"failed": {"automemberinclusiveregex": ["key=regex", …], …}}.
	var f []MemberFailure
	gjson.GetBytes(res.Failed, "failed").ForEach(func(attr, vals gjson.Result) bool {
		for _, v := range vals.Array() {
			f = append(f, MemberFailure{Kind: "condition", Type: attr.String(), Name: v.String(), Message: "no such condition"})
		}
		return true
	})
	if len(f) > 0 {
		return rule, &MemberError{Failures: f}
	}
	return rule, nil
}

// AutomemberDefaultGroup returns the fallback group of type typ, which gets
// the entries no rule matches, with `automember_default_group_show`; "" when
// none is set. It requires the Automember Readers privilege (System: Read
// Automember Definitions).
func (c *Client) AutomemberDefaultGroup(typ string) (string, error) {
	return c.AutomemberDefaultGroupContext(context.Background(), typ)
}

// AutomemberDefaultGroupContext is like AutomemberDefaultGroup but bounds the
// request with ctx.
func (c *Client) AutomemberDefaultGroupContext(ctx context.Context, typ string) (string, error) {
	if err := checkAutomemberType(typ); err != nil {
		return "", err
	}
	e, _, err := Call[Entry](ctx, c, "automember_default_group_show", nil, Options{"type": typ})
	if err != nil {
		return "", err
	}
	// The attribute is the group's DN, or a message when none is set.
	rdn, ok := strings.CutPrefix(e.DN("automemberdefaultgroup"), "cn=")
	if !ok {
		return "", nil
	}
	cn, _, _ := strings.Cut(rdn, ",")
	return cn, nil
}

// AutomemberSetDefaultGroup sets the fallback group of type typ with
// `automember_default_group_set`; setting the current one fails with
// ErrEmptyModlist. It needs an admin.
func (c *Client) AutomemberSetDefaultGroup(typ, group string) error {
	return c.AutomemberSetDefaultGroupContext(context.Background(), typ, group)
}

// AutomemberSetDefaultGroupContext is like AutomemberSetDefaultGroup but
// bounds the request with ctx.
func (c *Client) AutomemberSetDefaultGroupContext(ctx context.Context, typ, group string) error {
	if err := checkAutomemberType(typ); err != nil {
		return err
	}
	if group == "" {
		return errors.New("ipa: automember default group is required")
	}
	_, err := c.rpc(ctx, "automember_default_group_set", nil, Options{"type": typ, "automemberdefaultgroup": group})
	return err
}

// AutomemberRemoveDefaultGroup unsets the fallback group of type typ with
// `automember_default_group_remove`; with none set it fails with ErrNotFound.
// It needs an admin.
func (c *Client) AutomemberRemoveDefaultGroup(typ string) error {
	return c.AutomemberRemoveDefaultGroupContext(context.Background(), typ)
}

// AutomemberRemoveDefaultGroupContext is like AutomemberRemoveDefaultGroup
// but bounds the request with ctx.
func (c *Client) AutomemberRemoveDefaultGroupContext(ctx context.Context, typ string) error {
	if err := checkAutomemberType(typ); err != nil {
		return err
	}
	_, err := c.rpc(ctx, "automember_default_group_remove", nil, Options{"type": typ})
	return err
}

// AutomemberRebuild reapplies the rules of type typ to every existing user or
// host with `automember_rebuild` and waits for the task to finish. It
// requires the Automember Task Administrator privilege (Add Automember
// Rebuild Membership Task).
func (c *Client) AutomemberRebuild(typ string) error {
	return c.AutomemberRebuildContext(context.Background(), typ)
}

// AutomemberRebuildContext is like AutomemberRebuild but bounds the request
// with ctx.
func (c *Client) AutomemberRebuildContext(ctx context.Context, typ string) error {
	if err := checkAutomemberType(typ); err != nil {
		return err
	}
	_, err := c.rpc(ctx, "automember_rebuild", nil, Options{"type": typ})
	return err
}
