// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"fmt"
	"io/fs"
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
	path = filepath.Clean(path)
	data, err := os.ReadFile(path) // #nosec G304 -- the system krb5.conf the caller trusts
	if err != nil {
		return nil, errors.New("configuration file could not be opened: " + path + " " + err.Error())
	}

	var lines []string
	found, err := expandKrb5Conf(path, data, nil, &lines)
	if err != nil {
		return nil, err
	}
	if !found {
		return config.NewFromString(string(data))
	}

	cfg, err := config.NewFromString(strings.Join(mergeKrb5Sections(lines), "\n"))
	if cfg != nil {
		mergeKrb5Realms(cfg)
	}
	return cfg, err
}

// expandKrb5Conf appends the lines of path (content data) to out with include
// directives replaced by the included files, and reports whether there were
// any. Every file starts in the dummy section "[]", which mergeKrb5Sections
// drops: MIT ignores lines before a file's first section header.
func expandKrb5Conf(path string, data []byte, stack []string, out *[]string) (bool, error) {
	if slices.Contains(stack, path) {
		return false, fmt.Errorf("krb5.conf include loop at %s", path)
	}
	if len(stack) > maxKrb5IncludeDepth {
		return false, fmt.Errorf("krb5.conf include nesting too deep at %s", path)
	}
	stack = append(stack, path)

	found := false
	section := "[]"
	*out = append(*out, section)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		directive, arg := "", ""
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(line, fields[0]) {
			directive, arg = fields[0], strings.TrimSpace(line[len(fields[0]):])
		}

		var files []string
		switch directive {
		case "include":
			files = []string{arg}
		case "includedir":
			var err error
			if files, err = krb5IncludeDir(arg); err != nil {
				return false, err
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
			inc = filepath.Clean(inc)
			data, err := os.ReadFile(inc) // #nosec G304 G703 -- named by the system krb5.conf
			// Before v0.2.1 includes were ignored, so pure-Go apps that mount only
			// /etc/krb5.conf (RHEL ships includedir /etc/krb5.conf.d/) must keep
			// working: unlike MIT, a missing include is skipped.
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return false, fmt.Errorf("krb5.conf include: %w", err)
			}
			if _, err := expandKrb5Conf(inc, data, stack, out); err != nil {
				return false, err
			}
		}
		// MIT parses an included file on its own, so the lines after the
		// directive stay in this file's section.
		*out = append(*out, section)
	}
	return found, nil
}

// krb5IncludeDir lists the files MIT krb5 reads from an includedir, in order.
// A missing dir or dangling symlink is skipped, see expandKrb5Conf.
func krb5IncludeDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("krb5.conf includedir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !krb5IncludeName.MatchString(e.Name()) {
			continue
		}
		name := filepath.Join(dir, e.Name())
		fi, err := os.Stat(name) // #nosec G703 -- listed from an includedir named by the system krb5.conf
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("krb5.conf includedir: %w", err)
		}
		if fi.Mode().IsRegular() {
			files = append(files, name)
		}
	}
	return files, nil
}

// mergeKrb5Sections joins repeated sections of expanded krb5.conf lines and
// keeps the first value of each [libdefaults] and [domain_realm] key, as MIT
// does. gokrb5 v8.4.4 lets the last value win and replaces all realms with
// each [realms] section (config/krb5conf.go:583-606).
func mergeKrb5Sections(lines []string) []string {
	var order []string
	body := map[string][]string{}
	name := "[]"
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
			if _, ok := body[name]; !ok && name != "[]" {
				order = append(order, name)
			}
			continue
		}
		if name != "[]" {
			body[name] = append(body[name], l)
		}
	}

	var out []string
	for _, name := range order {
		out = append(out, name)
		if name == "[libdefaults]" || name == "[domain_realm]" {
			out = append(out, firstKrb5Values(body[name])...)
		} else {
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

// mergeKrb5Realms folds realms defined more than once into the first entry,
// as MIT merges them. gokrb5 keeps one entry per block and GetKDCs uses the
// last one (config/hosts.go:23-28).
func mergeKrb5Realms(cfg *config.Config) {
	var realms []config.Realm
	index := map[string]int{}
	for _, r := range cfg.Realms {
		i, ok := index[r.Realm]
		if !ok {
			index[r.Realm] = len(realms)
			realms = append(realms, r)
			continue
		}
		m := &realms[i]
		m.KDC = append(m.KDC, r.KDC...)
		m.AdminServer = append(m.AdminServer, r.AdminServer...)
		m.KPasswdServer = append(m.KPasswdServer, r.KPasswdServer...)
		m.MasterKDC = append(m.MasterKDC, r.MasterKDC...)
		if m.DefaultDomain == "" {
			m.DefaultDomain = r.DefaultDomain
		}
	}
	cfg.Realms = realms
}
