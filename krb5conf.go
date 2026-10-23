// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
)

const maxKrb5IncludeDepth = 8

// MIT krb5 reads only these names from an includedir, which skips editor
// backups and .rpmsave files.
var krb5IncludeName = regexp.MustCompile(`^([A-Za-z0-9_-]+|[^.].*\.conf)$`)

// loadKrb5Config is config.Load with include and includedir resolved as MIT
// krb5 does: ipa-client-install 4.13 keeps [realms] in /etc/krb5.conf.d.
func loadKrb5Config(path string) (*config.Config, error) {
	var lines []string
	found, err := expandKrb5Conf(path, nil, &lines)
	if err != nil {
		return nil, err
	}
	if found {
		lines = mergeKrb5Sections(lines)
	}
	return config.NewFromString(strings.Join(lines, "\n"))
}

// expandKrb5Conf appends the lines of path to out with include directives
// replaced by the included files, and reports whether there were any.
func expandKrb5Conf(path string, stack []string, out *[]string) (bool, error) {
	path = filepath.Clean(path)
	if slices.Contains(stack, path) {
		return false, fmt.Errorf("krb5.conf include loop at %s", path)
	}
	if len(stack) > maxKrb5IncludeDepth {
		return false, fmt.Errorf("krb5.conf include nesting too deep at %s", path)
	}
	stack = append(stack, path)

	f, err := os.Open(path) // #nosec G304 -- the system krb5.conf and the files it includes
	if err != nil {
		if len(stack) == 1 {
			return false, errors.New("configuration file could not be opened: " + path + " " + err.Error())
		}
		return false, fmt.Errorf("krb5.conf include: %w", err)
	}
	defer func() { _ = f.Close() }()

	found := false
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		directive, arg := "", ""
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(line, fields[0]) {
			directive, arg = fields[0], strings.TrimSpace(line[len(fields[0]):])
		}

		var files []string
		switch directive {
		case "include":
			files = []string{arg}
		case "includedir":
			entries, err := os.ReadDir(arg)
			if err != nil {
				return false, fmt.Errorf("krb5.conf includedir: %w", err)
			}
			for _, e := range entries {
				name := filepath.Join(arg, e.Name())
				if !krb5IncludeName.MatchString(e.Name()) {
					continue
				}
				fi, err := os.Stat(name)
				if err != nil {
					return false, fmt.Errorf("krb5.conf includedir: %w", err)
				}
				if fi.Mode().IsRegular() {
					files = append(files, name)
				}
			}
		default:
			if strings.HasPrefix(strings.TrimSpace(line), "[") {
				section = line
			}
			*out = append(*out, line)
			continue
		}

		found = true
		for _, inc := range files {
			if _, err := expandKrb5Conf(inc, stack, out); err != nil {
				return false, err
			}
		}
		// MIT parses an included file on its own, so the lines after the
		// directive stay in this file's section.
		if section != "" {
			*out = append(*out, section)
		}
	}
	return found, scanner.Err()
}

// mergeKrb5Sections rewrites expanded krb5.conf lines so that gokrb5 sees
// what MIT krb5 sees. MIT merges sections and same-named realms and uses the
// first value of a single-valued relation; gokrb5 v8.4.4 lets the last
// libdefaults and domain_realm value win, replaces all realms with each
// [realms] section (config/krb5conf.go:583-606) and uses the last realm entry
// of a name (config/hosts.go:23-28).
func mergeKrb5Sections(lines []string) []string {
	var order []string
	body := map[string][]string{}
	name := ""
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '[' {
			if i := strings.IndexByte(t, ']'); i > 0 {
				t = t[:i+1]
			}
			name = t
			if _, ok := body[name]; !ok {
				order = append(order, name)
				body[name] = nil
			}
			continue
		}
		if name != "" {
			body[name] = append(body[name], l)
		}
	}

	var out []string
	for _, name := range order {
		out = append(out, name)
		switch name {
		case "[libdefaults]", "[domain_realm]":
			out = append(out, firstKrb5Values(body[name])...)
		case "[realms]":
			out = append(out, mergeKrb5Realms(body[name])...)
		default:
			out = append(out, body[name]...)
		}
	}
	return out
}

func firstKrb5Values(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		if k, _, ok := strings.Cut(l, "="); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		out = append(out, l)
	}
	return out
}

// mergeKrb5Realms joins the blocks of a realm defined more than once, so
// gokrb5 collects every kdc in order as MIT does.
func mergeKrb5Realms(lines []string) []string {
	var order []string
	body := map[string][]string{}
	name, depth := "", 0
	for _, l := range lines {
		code := l
		if i := strings.IndexAny(code, "#;"); i >= 0 {
			code = code[:i]
		}
		open, closing := strings.Contains(code, "{"), strings.Contains(code, "}")
		switch {
		case depth == 0 && open:
			name, _, _ = strings.Cut(code, "=")
			name = strings.TrimSpace(name)
			if _, ok := body[name]; !ok {
				order = append(order, name)
				body[name] = nil
			}
			if !closing {
				depth = 1
			}
		case depth == 0:
		default:
			if open {
				depth++
			}
			if closing {
				depth--
			}
			if depth > 0 {
				body[name] = append(body[name], l)
			}
		}
	}

	var out []string
	for _, name := range order {
		out = append(out, name+" = {")
		out = append(out, body[name]...)
		out = append(out, "}")
	}
	return out
}
