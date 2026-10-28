// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"

	ipa "github.com/neverlless/goipa"
)

// OTPToken is an OTP token of the fake server.
type OTPToken struct {
	UUID        string // default: random
	Owner       string // uid
	Type        string // default "totp"
	Algorithm   string // default "sha1"
	Digits      int    // default 6
	TimeStep    int    // default 30
	Disabled    bool
	Description string
	Vendor      string
	Model       string
	Serial      string
	NotBefore   time.Time
	NotAfter    time.Time
}

// AddOTPToken stores t with defaults applied and returns it as stored.
func (s *Server) AddOTPToken(t OTPToken) OTPToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putToken(t)
}

// OTPTokens returns the tokens of owner, or all of them if owner is "", in
// insertion order.
func (s *Server) OTPTokens(owner string) []OTPToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []OTPToken{}
	for _, t := range s.tokens {
		if owner == "" || t.Owner == owner {
			out = append(out, *t)
		}
	}
	return out
}

// putToken needs s.mu held.
func (s *Server) putToken(t OTPToken) OTPToken {
	if t.UUID == "" {
		t.UUID = newUUID()
	}
	if t.Type == "" {
		t.Type = ipa.TokenTypeTOTP
	}
	if t.Algorithm == "" {
		t.Algorithm = ipa.AlgorithmSHA1
	}
	if t.Digits == 0 {
		t.Digits = 6
	}
	if t.TimeStep == 0 {
		t.TimeStep = 30
	}
	t.NotBefore, t.NotAfter = t.NotBefore.UTC(), t.NotAfter.UTC()
	s.tokens = append(s.tokens, &t)
	return t
}

func (t *OTPToken) render() map[string]any {
	out := map[string]any{
		"dn":                   "ipatokenuniqueid=" + t.UUID + ",cn=otp,dc=test,dc=local",
		"ipatokenuniqueid":     []string{t.UUID},
		"type":                 t.Type,
		"ipatokenotpalgorithm": []string{t.Algorithm},
		"ipatokenotpdigits":    []string{strconv.Itoa(t.Digits)},
		"ipatokentotptimestep": []string{strconv.Itoa(t.TimeStep)},
	}
	if t.Disabled {
		out["ipatokendisabled"] = []bool{true}
	}
	for k, v := range map[string]string{
		"ipatokenowner":  t.Owner,
		"managedby_user": t.Owner,
		"description":    t.Description,
		"ipatokenvendor": t.Vendor,
		"ipatokenmodel":  t.Model,
		"ipatokenserial": t.Serial,
	} {
		if v != "" {
			out[k] = []string{v}
		}
	}
	for k, v := range map[string]time.Time{"ipatokennotbefore": t.NotBefore, "ipatokennotafter": t.NotAfter} {
		if !v.IsZero() {
			out[k] = []map[string]string{{"__datetime__": v.Format(ipa.IpaDatetimeFormat)}}
		}
	}
	return out
}

func invalid(msg string) *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeValidation, Message: msg}
}

// number reads a numeric option: JSON number or numeric string.
func number(c Call, name string, def int) (int, *ipa.IpaError) {
	v, ok := c.Options[name]
	if !ok {
		return def, nil
	}
	if f, ok := v.(float64); ok {
		return int(f), nil
	}
	n, err := strconv.Atoi(str(v))
	if err != nil {
		return 0, invalid(fmt.Sprintf("invalid '%s': must be an integer", name))
	}
	return n, nil
}

// datetime reads a {"__datetime__": s} option as UTC (Q8).
func datetime(c Call, name string) (time.Time, *ipa.IpaError) {
	v, ok := c.Options[name]
	if !ok {
		return time.Time{}, nil
	}
	m, _ := v.(map[string]any)
	s, _ := m["__datetime__"].(string)
	t, err := time.Parse(ipa.IpaDatetimeFormat, s)
	if err != nil {
		return time.Time{}, invalid(fmt.Sprintf("invalid '%s': must be a datetime like 20060102150405Z", name))
	}
	return t.UTC(), nil
}

func (s *Server) tokenArg(c Call) (*OTPToken, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("ipatokenuniqueid")
	}
	for _, t := range s.tokens {
		if t.UUID == c.Args[0] {
			return t, nil
		}
	}
	return nil, notFound(c.Args[0], "OTP token")
}

func otptokenAdd(s *Server, c Call) (any, *ipa.IpaError) {
	t := OTPToken{
		Owner:       c.User,
		Type:        str(c.Options["type"]),
		Algorithm:   str(c.Options["ipatokenotpalgorithm"]),
		Description: str(c.Options["description"]),
		Vendor:      str(c.Options["ipatokenvendor"]),
		Model:       str(c.Options["ipatokenmodel"]),
		Serial:      str(c.Options["ipatokenserial"]),
	}
	if o := str(c.Options["ipatokenowner"]); o != "" {
		t.Owner = o
	}
	var err *ipa.IpaError
	if t.Digits, err = number(c, "ipatokenotpdigits", 0); err != nil {
		return nil, err
	}
	if t.TimeStep, err = number(c, "ipatokentotptimestep", 0); err != nil {
		return nil, err
	}
	if t.NotBefore, err = datetime(c, "ipatokennotbefore"); err != nil { // Q8
		return nil, err
	}
	if t.NotAfter, err = datetime(c, "ipatokennotafter"); err != nil {
		return nil, err
	}
	t = s.putToken(t)

	secret := make([]byte, 20)
	_, _ = rand.Read(secret)
	label := realm + ":" + t.Owner + "@" + realm
	uri := fmt.Sprintf("otpauth://%s/%s?secret=%s&digits=%d&algorithm=%s&period=%d&issuer=%s",
		t.Type, url.PathEscape(label), base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret),
		t.Digits, t.Algorithm, t.TimeStep, realm)
	rec := t.render()
	rec["uri"] = uri
	return entry(t.UUID, rec, fmt.Sprintf("Added OTP token %q", t.UUID)), nil
}

func otptokenFind(s *Server, c Call) (any, *ipa.IpaError) {
	owner := str(c.Options["ipatokenowner"])
	recs := []map[string]any{}
	for _, t := range s.tokens {
		if owner == "" || t.Owner == owner {
			recs = append(recs, t.render())
		}
	}
	return listLimited(c, recs), nil
}

// lastActive implements Q7: the guard for the last enabled token of a user
// who may log in with OTP only.
func (s *Server) lastActive(t *OTPToken) bool {
	u := s.users[t.Owner]
	if t.Disabled || u == nil || !slices.Equal(u.AuthTypes, []string{"otp"}) {
		return false
	}
	for _, o := range s.tokens {
		if o != t && o.Owner == t.Owner && !o.Disabled {
			return false
		}
	}
	return true
}

func lastTokenError() *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeDatabase, Message: "Can't delete last active token while OTP is enabled"}
}

func otptokenMod(s *Server, c Call) (any, *ipa.IpaError) {
	t, err := s.tokenArg(c)
	if err != nil {
		return nil, err
	}
	if _, ok := c.Options["ipatokendisabled"]; ok {
		disable := flag(c, "ipatokendisabled")
		if disable && s.lastActive(t) { // Q7
			return nil, lastTokenError()
		}
		t.Disabled = disable
	}
	return entry(t.UUID, t.render(), fmt.Sprintf("Modified OTP token %q", t.UUID)), nil
}

func otptokenDel(s *Server, c Call) (any, *ipa.IpaError) {
	t, err := s.tokenArg(c)
	if !s.isAdmin(c.User) { // Q154
		if err != nil && err.Code == ipa.CodeNotFound {
			return nil, &ipa.IpaError{Code: ipa.CodeACI, Message: "Insufficient access: "}
		}
		if err == nil && t.Owner != c.User {
			return nil, &ipa.IpaError{Code: ipa.CodeACI, Message: "Insufficient access: Insufficient 'delete' privilege to delete the entry 'ipatokenuniqueid=" +
				t.UUID + ",cn=otp,dc=test,dc=local'."}
		}
	}
	if err != nil {
		return nil, err
	}
	if s.lastActive(t) { // Q7
		return nil, lastTokenError()
	}
	s.tokens = slices.DeleteFunc(s.tokens, func(o *OTPToken) bool { return o == t })
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   []string{t.UUID},
		"summary": fmt.Sprintf("Deleted OTP token %q", t.UUID),
	}, nil
}

func init() {
	builtins["otptoken_add"] = otptokenAdd
	builtins["otptoken_find"] = otptokenFind
	builtins["otptoken_mod"] = otptokenMod
	builtins["otptoken_del"] = otptokenDel
}
