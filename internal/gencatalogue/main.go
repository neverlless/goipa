// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Command gencatalogue writes the FreeIPA command catalogue from the API.txt
// of every FreeIPA release since 4.9.0.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	repo   = "https://github.com/freeipa/freeipa"
	oldest = "4.9.0"
)

var tagRe = regexp.MustCompile(`^refs/tags/release-(\d+)-(\d+)-(\d+)$`)

func main() {
	out := flag.String("o", "", "output file (required)")
	src := flag.String("src", "", "read API-<x.y.z>.txt files from this directory instead of the network")
	flag.Parse()
	if *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*out, *src); err != nil {
		fmt.Fprintln(os.Stderr, "gencatalogue:", err)
		os.Exit(1)
	}
}

func run(out, src string) error {
	var (
		rels []release
		err  error
	)
	if src != "" {
		rels, err = readDir(src)
	} else {
		rels, err = fetch()
	}
	if err != nil {
		return err
	}
	if len(rels) == 0 {
		return fmt.Errorf("no releases found")
	}
	cmds, versions, err := merge(rels)
	if err != nil {
		return err
	}
	b, err := render(cmds, versions)
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644) // #nosec G306 -- generated source, world-readable like the rest of the repo
}

// readDir accepts API-4.13.4.txt and API-4-13-4.txt alike.
func readDir(dir string) ([]release, error) {
	files, err := filepath.Glob(filepath.Join(dir, "API-*.txt"))
	if err != nil {
		return nil, err
	}
	var rels []release
	for _, f := range files {
		v := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "API-"), ".txt"), "-", ".")
		if _, ok := parseVersion(v); !ok || compareVersions(v, oldest) < 0 {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- listed from the -src directory
		if err != nil {
			return nil, err
		}
		cmds, err := parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		rels = append(rels, release{Version: v, Commands: cmds})
	}
	return rels, nil
}

func fetch() ([]release, error) {
	refs, err := exec.Command("git", "ls-remote", "--tags", repo).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote: %w", err)
	}
	client := &http.Client{Timeout: time.Minute}
	var rels []release
	for _, line := range strings.Split(string(refs), "\n") {
		_, ref, _ := strings.Cut(line, "\t")
		m := tagRe.FindStringSubmatch(ref)
		if m == nil {
			continue
		}
		v := m[1] + "." + m[2] + "." + m[3]
		if compareVersions(v, oldest) < 0 {
			continue
		}
		tag := strings.TrimPrefix(ref, "refs/tags/")
		cmds, err := fetchOne(client, "https://raw.githubusercontent.com/freeipa/freeipa/"+tag+"/API.txt")
		if err != nil {
			return nil, err
		}
		rels = append(rels, release{Version: v, Commands: cmds})
	}
	return rels, nil
}

func fetchOne(client *http.Client, url string) ([]command, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	cmds, err := parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return cmds, nil
}
