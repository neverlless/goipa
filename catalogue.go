// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import "sync"

//go:generate go run ./internal/gencatalogue -o catalogue_gen.go

// Command describes a FreeIPA JSON-RPC command as published in the API.txt
// of the FreeIPA releases the catalogue was generated from.
type Command struct {
	Name    string  // e.g. "user_add"
	Since   string  // first catalogued release with it; "4.9.0" means 4.9.0 or earlier
	Args    []Param // positional, in API.txt order
	Options []Param // in API.txt order
}

// Param is a positional argument or an option of a Command. Type and the
// required/multi flags are those of the newest catalogued release.
type Param struct {
	Name     string // without the ?*+ suffix
	Type     string // API.txt class: "Str", "Flag", "Int", "DNParam", …
	Required bool   // the caller must send it
	Multi    bool   // takes a list of values
	Since    string
}

var catalogueIndex = sync.OnceValue(func() map[string]int {
	m := make(map[string]int, len(catalogue))
	for i, c := range catalogue {
		m[c.Name] = i
	}
	return m
})

// Commands returns the commands a FreeIPA server of the given version has,
// sorted by name, with only the arguments and options that version has.
// An empty or unparsable version returns everything catalogued. A version
// newer than the newest catalogued release gets that release's commands, so
// commands added after it are not listed.
func Commands(version string) []Command {
	limit, all := catalogueLimit(version)
	out := make([]Command, 0, len(catalogue))
	for i := range catalogue {
		if c, ok := filterCommand(&catalogue[i], limit, all); ok {
			out = append(out, c)
		}
	}
	return out
}

// LookupCommand returns the named command as Commands(version) would list
// it, and false when that version does not have it.
func LookupCommand(name, version string) (Command, bool) {
	i, ok := catalogueIndex()[name]
	if !ok {
		return Command{}, false
	}
	limit, all := catalogueLimit(version)
	return filterCommand(&catalogue[i], limit, all)
}

func catalogueLimit(version string) (limit [3]int, all bool) {
	v, ok := parseVersion(version)
	if !ok {
		return v, true
	}
	if oldest, _ := parseVersion(catalogueReleases[0]); versionLess(v, oldest) {
		v = oldest
	}
	return v, false
}

func sinceOK(since string, limit [3]int, all bool) bool {
	s, _ := parseVersion(since)
	return all || !versionLess(limit, s)
}

// filterCommand copies c so callers cannot change the catalogue.
func filterCommand(c *Command, limit [3]int, all bool) (Command, bool) {
	if !sinceOK(c.Since, limit, all) {
		return Command{}, false
	}
	return Command{
		Name:    c.Name,
		Since:   c.Since,
		Args:    filterParams(c.Args, limit, all),
		Options: filterParams(c.Options, limit, all),
	}, true
}

func filterParams(ps []Param, limit [3]int, all bool) []Param {
	out := make([]Param, 0, len(ps))
	for _, p := range ps {
		if sinceOK(p.Since, limit, all) {
			out = append(out, p)
		}
	}
	return out
}
