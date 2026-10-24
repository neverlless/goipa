// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

//go:embed replay
var embedded embed.FS

func shippedReplay() fs.FS {
	sub, err := fs.Sub(embedded, "replay")
	if err != nil {
		panic(err) // "replay" is a valid path, so this cannot happen
	}
	return sub
}

// SetReplay sets the recorded responses the server answers for a command it
// neither models nor has a Handle override for (Q130): fsys holds
// <release>/<method>.json files as NewRecorder writes them. The default is
// the recordings shipped in ipatest/replay; nil disables replay, so such a
// command is 905 again.
func (s *Server) SetReplay(fsys fs.FS) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replay = fsys
}

// replayed returns the recording of method from the greatest release not
// newer than version, else from the oldest release, or nil without one.
func replayed(fsys fs.FS, method, version string) json.RawMessage {
	if fsys == nil || !methodName.MatchString(method) {
		return nil
	}
	dirs, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	want, ok := parseRelease(version)
	if !ok {
		want = [3]int{math.MaxInt, math.MaxInt, math.MaxInt} // as the catalogue: newest
	}
	var best, oldest string
	var bestV, oldestV [3]int
	for _, d := range dirs {
		v, ok := parseRelease(d.Name())
		if !d.IsDir() || !ok {
			continue
		}
		if _, err := fs.Stat(fsys, d.Name()+"/"+method+".json"); err != nil {
			continue
		}
		if oldest == "" || slices.Compare(v[:], oldestV[:]) < 0 {
			oldest, oldestV = d.Name(), v
		}
		if slices.Compare(v[:], want[:]) <= 0 && (best == "" || slices.Compare(v[:], bestV[:]) > 0) {
			best, bestV = d.Name(), v
		}
	}
	if best == "" {
		best = oldest
	}
	if best == "" {
		return nil
	}
	b, err := fs.ReadFile(fsys, best+"/"+method+".json")
	if err != nil || !json.Valid(b) {
		return nil
	}
	return b
}

var methodName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func parseRelease(s string) (v [3]int, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// redactKeys are the attributes whose values never reach a recording.
var redactKeys = map[string]bool{
	"randompassword":       true,
	"userpassword":         true,
	"krbprincipalkey":      true,
	"ipatokenotpkey":       true,
	"uri":                  true, // otpauth:// URIs carry the OTP key
	"ipatokenradiussecret": true,
	"ipasecretkey":         true,
}

func redact(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if redactKeys[strings.ToLower(k)] {
				v[k] = "REDACTED"
			} else {
				v[k] = redact(x)
			}
		}
	case []any:
		for i, x := range v {
			v[i] = redact(x)
		}
	}
	return v
}

type recorder struct {
	next http.RoundTripper
	dir  string
	mu   sync.Mutex // serialises file writes
}

// NewRecorder returns a transport that sends each request through next and,
// for every JSON-RPC call to /ipa/json or /ipa/session/json that succeeds,
// writes the response's result object to <dir>/<version>/<method>.json,
// version being the release the server reports. A later call of the same
// method overwrites the file; batch calls are not recorded. The values of
// randompassword, userpassword, krbprincipalkey, ipatokenotpkey, uri,
// ipatokenradiussecret and ipasecretkey are replaced with "REDACTED" at any
// depth. A nil next means http.DefaultTransport.
//
// Wrap a real server's transport with it to collect recordings for
// Server.SetReplay.
func NewRecorder(next http.RoundTripper, dir string) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &recorder{next: next, dir: dir}
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var method string
	if req.Method == http.MethodPost && (req.URL.Path == "/ipa/json" || req.URL.Path == "/ipa/session/json") && req.Body != nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		// A RoundTripper must not modify the caller's request.
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
		var call struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(b, &call) == nil && call.Method != "batch" {
			method = call.Method
		}
	}
	resp, err := r.next.RoundTrip(req)
	if err != nil || method == "" {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	if err := r.record(method, b); err != nil {
		return nil, fmt.Errorf("ipatest: recording %s: %w", method, err)
	}
	return resp, nil
}

func (r *recorder) record(method string, body []byte) error {
	var env struct {
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
		Version string          `json:"version"`
	}
	if json.Unmarshal(body, &env) != nil || (len(env.Error) > 0 && string(env.Error) != "null") {
		return nil
	}
	if _, ok := parseRelease(env.Version); !ok || !methodName.MatchString(method) {
		return nil
	}
	var result map[string]any
	dec := json.NewDecoder(bytes.NewReader(env.Result))
	dec.UseNumber()
	if dec.Decode(&result) != nil || result == nil {
		return nil
	}
	out, err := json.MarshalIndent(redact(result), "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(r.dir, env.Version)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, method+".json"), append(out, '\n'), 0o600)
}
