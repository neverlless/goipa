// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"sort"
	"strconv"

	ipa "github.com/neverlless/goipa"
)

const (
	subIDBaseDN = "cn=subids,cn=accounts,dc=test,dc=local"
	subIDFirst  = 2147483648
	subIDCount  = 65536
)

// SubID is a subordinate ID range of the fake server.
type SubID struct {
	ID, Owner, Description string
	UIDStart, UIDCount     int64
	GIDStart, GIDCount     int64
}

// AddSubID stores a range for r.Owner, replacing any it had. Defaults: ID a
// random UUID, the next free range, counts 65536, GID equal to UID.
func (s *Server) AddSubID(r SubID) SubID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addSubID(r)
}

func (s *Server) addSubID(r SubID) SubID {
	if r.ID == "" {
		r.ID = newUUID()
	}
	if r.UIDCount == 0 {
		r.UIDCount = subIDCount
	}
	if r.UIDStart == 0 {
		r.UIDStart = subIDFirst
		for _, o := range s.subids {
			r.UIDStart = max(r.UIDStart, o.UIDStart+o.UIDCount)
		}
	}
	if r.GIDStart == 0 {
		r.GIDStart = r.UIDStart
	}
	if r.GIDCount == 0 {
		r.GIDCount = r.UIDCount
	}
	s.subids[r.Owner] = r
	return r
}

// SubID returns the range of owner.
func (s *Server) SubID(owner string) (SubID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.subids[owner]
	return r, ok
}

func renderSubID(r SubID) map[string]any {
	n := func(v int64) []string { return []string{strconv.FormatInt(v, 10)} }
	out := map[string]any{
		"ipauniqueid":     []string{r.ID},
		"ipaowner":        []string{r.Owner},
		"ipasubuidnumber": n(r.UIDStart),
		"ipasubuidcount":  n(r.UIDCount),
		"ipasubgidnumber": n(r.GIDStart),
		"ipasubgidcount":  n(r.GIDCount),
		"objectclass":     []string{"top", "ipasubordinateid"},
		"dn":              "ipauniqueid=" + r.ID + "," + subIDBaseDN,
	}
	if r.Description != "" {
		out["description"] = []string{r.Description}
	}
	return out
}

func subidFind(s *Server, c Call) (any, *ipa.IpaError) {
	var owners []string
	for owner, r := range s.subids {
		if matches(c, "ipaowner", owner) && matches(c, "ipauniqueid", r.ID) && matches(c, "description", r.Description) &&
			matches(c, "ipasubuidnumber", strconv.FormatInt(r.UIDStart, 10)) {
			owners = append(owners, owner)
		}
	}
	sort.Strings(owners)
	recs := make([]map[string]any, 0, len(owners))
	for _, o := range owners {
		recs = append(recs, renderSubID(s.subids[o]))
	}
	return list(recs), nil
}

func subidGenerate(s *Server, c Call) (any, *ipa.IpaError) {
	owner := c.User
	if v, ok := c.Options["ipaowner"]; ok {
		owner = str(v)
	}
	if s.users[owner] == nil {
		return nil, notFound(owner, "user")
	}
	if old, ok := s.subids[owner]; ok {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Name: "DuplicateEntry",
			Message: fmt.Sprintf("Subordinate id with with name %q or for user %q already exists.", old.ID, owner)}
	}
	r := s.addSubID(SubID{Owner: owner})
	return entry(r.ID, renderSubID(r), ""), nil
}

func init() {
	builtins["subid_find"] = subidFind
	builtins["subid_generate"] = subidGenerate
}
