// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

// FreeIPA error codes (ipalib.errors).
const (
	CodeVersion              = 901
	CodeCommand              = 905
	CodeReferer              = 911
	CodeACI                  = 2100
	CodeRequirement          = 3007
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
	return ok && t.Code == e.Code
}
