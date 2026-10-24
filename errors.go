// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// FreeIPA error codes (ipalib.errors).
const (
	CodeVersion              = 901
	CodeCommand              = 905
	CodeReferer              = 911
	CodeACI                  = 2100
	CodeOption               = 3005
	CodeRequirement          = 3007
	CodeConversion           = 3008
	CodeValidation           = 3009
	CodeNotFound             = 4001
	CodeDuplicateEntry       = 4002
	CodeAlreadyActive        = 4009
	CodeAlreadyInactive      = 4010
	CodeNotGroupMember       = 4012
	CodeAlreadyGroupMember   = 4014
	CodeAttrValueNotFound    = 4026
	CodeAlreadyContainsValue = 4038
	CodeEmptyModlist         = 4202
	CodeDatabase             = 4203
	CodeOnlyOneValueAllowed  = 4207
)

// Sentinels for common FreeIPA errors. They are matched with errors.Is by
// code only; any other code is available through errors.As and IpaError.Code.
var (
	ErrNotFound       = &IpaError{Code: CodeNotFound, Name: "NotFound", Message: "not found"}
	ErrDuplicateEntry = &IpaError{Code: CodeDuplicateEntry, Name: "DuplicateEntry", Message: "entry already exists"}
	ErrACI            = &IpaError{Code: CodeACI, Name: "ACIError", Message: "insufficient access"}
	ErrEmptyModlist   = &IpaError{Code: CodeEmptyModlist, Name: "EmptyModlist", Message: "no modifications to be performed"}
)

// Is reports whether target is an *IpaError with the same Code.
func (e *IpaError) Is(target error) bool {
	t, ok := target.(*IpaError)
	return ok && t != nil && e != nil && t.Code == e.Code
}

// HTTPError is returned when the server answers a JSON-RPC call with a
// status other than 200. HTTP 401 (for example an expired session) also
// matches ErrUnauthorized with errors.Is.
type HTTPError struct {
	StatusCode int
	Status     string
}

// Error returns the message used before HTTPError existed.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("IPA RPC called failed with HTTP status code: %d", e.StatusCode)
}

// Is reports whether target is ErrUnauthorized and the status is 401.
func (e *HTTPError) Is(target error) bool {
	return target == ErrUnauthorized && e.StatusCode == http.StatusUnauthorized
}

var (
	// ErrPasswordPolicy is returned when a password does not conform to the password policy
	ErrPasswordPolicy = errors.New("password does not conform to policy")

	// ErrInvalidPassword is returned when a password is invalid
	ErrInvalidPassword = errors.New("invalid current password")

	// ErrInvalidCredentials is returned by SyncOTPToken when FreeIPA rejects
	// the user, password or codes (X-IPA-TokenSync-Result: invalid-credentials).
	ErrInvalidCredentials = errors.New("invalid user, password or OTP codes")

	// ErrExpiredPassword is returned when a password is expired
	ErrExpiredPassword = errors.New("password expired")

	// ErrUnauthorized is returned when user is not authorized
	ErrUnauthorized = errors.New("unauthorized")

	// ErrUserExists is returned when user account already exists. UserAdd
	// returns it for FreeIPA's DuplicateEntry (4002).
	ErrUserExists = errors.New("user exists")
)

// FreeIPA error
type IpaError struct {
	Message string
	Code    int
	Name    string `json:"name"`
	// Data is the raw JSON of the exception's keyword arguments, e.g.
	// {"reason":"..."}. A string so IpaError stays comparable.
	Data string `json:"data"`
}

// UnmarshalJSON keeps Data as raw JSON text; Message and Code still match the
// "message" and "code" keys case-insensitively.
func (e *IpaError) UnmarshalJSON(b []byte) error {
	var v struct {
		Message string
		Code    int
		Name    string
		Data    json.RawMessage
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*e = IpaError{Message: v.Message, Code: v.Code, Name: v.Name, Data: string(v.Data)}
	return nil
}

// MarshalJSON writes FreeIPA's error shape; an empty or non-JSON Data becomes {}.
func (e *IpaError) MarshalJSON() ([]byte, error) {
	data := json.RawMessage(e.Data)
	if len(data) == 0 || !json.Valid(data) {
		data = json.RawMessage("{}")
	}
	return json.Marshal(struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Name    string          `json:"name"`
		Data    json.RawMessage `json:"data"`
	}{e.Code, e.Message, e.Name, data})
}

func (e *IpaError) Error() string {
	return fmt.Sprintf("ipa: error %d - %s", e.Code, e.Message)
}
