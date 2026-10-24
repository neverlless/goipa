// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// Entry is one FreeIPA record as the server sent it. The accessors read
// FreeIPA's encodings (single values in lists, "TRUE" strings, datetime and
// base64 class hints) so callers need no JSON handling; Raw gives the rest.
type Entry struct{ raw json.RawMessage }

// UnmarshalJSON keeps a copy of the object.
func (e *Entry) UnmarshalJSON(b []byte) error {
	if !gjson.ValidBytes(b) {
		return errors.New("ipa: invalid entry json")
	}
	e.raw = append(e.raw[:0], b...)
	return nil
}

// MarshalJSON returns the object the entry was decoded from.
func (e Entry) MarshalJSON() ([]byte, error) {
	if len(e.raw) == 0 {
		return []byte("null"), nil
	}
	return e.raw, nil
}

// Raw returns the entry's JSON object; do not modify it.
func (e Entry) Raw() json.RawMessage { return e.raw }

var attrEscaper = strings.NewReplacer(".", `\.`, "*", `\*`, "?", `\?`, "|", `\|`, "#", `\#`, "@", `\@`, "!", `\!`, "=", `\=`, "<", `\<`, ">", `\>`, "%", `\%`)

func (e Entry) get(attr string) (gjson.Result, string) {
	return gjson.ParseBytes(e.raw), attrEscaper.Replace(attr)
}

// first is the value itself or the first element of a list.
func (e Entry) first(attr string) gjson.Result {
	res, p := e.get(attr)
	v := res.Get(p)
	if v.IsArray() {
		v = v.Get("0")
	}
	return v
}

// Has reports whether the attribute is present, even as null.
func (e Entry) Has(attr string) bool {
	res, p := e.get(attr)
	return res.Get(p).Exists()
}

// Str returns the attribute's first value, or "" when absent.
func (e Entry) Str(attr string) string { return e.first(attr).String() }

// DN is Str, named for attributes that hold a DN.
func (e Entry) DN(attr string) string { return e.Str(attr) }

// Strs returns all values of the attribute; a scalar is one element. It is
// nil when the attribute is absent or null.
func (e Entry) Strs(attr string) []string {
	res, p := e.get(attr)
	return strList(res, p)
}

// Bool reads true, [true], "TRUE" or ["TRUE"].
func (e Entry) Bool(attr string) bool {
	res, p := e.get(attr)
	return boolAttr(res, p)
}

// Int parses a number or numeric string; ok is false when absent or not an
// integer.
func (e Entry) Int(attr string) (int64, bool) {
	v := e.first(attr)
	if !v.Exists() {
		return 0, false
	}
	n, err := strconv.ParseInt(v.String(), 10, 64)
	return n, err == nil
}

// Time reads a {"__datetime__": ...} hint or an RFC 3339 string; the zero
// time otherwise.
func (e Entry) Time(attr string) time.Time {
	v := e.first(attr)
	if v.IsObject() {
		v = v.Get("__datetime__")
	}
	if t := ParseDateTime(v.String()); !t.IsZero() {
		return t
	}
	t, _ := time.Parse(time.RFC3339, v.String())
	return t.UTC()
}

// Bytes decodes a {"__base64__": ...} hint; nil otherwise.
func (e Entry) Bytes(attr string) []byte {
	v := e.first(attr)
	if !v.IsObject() {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(v.Get("__base64__").String())
	if err != nil {
		return nil
	}
	return b
}
