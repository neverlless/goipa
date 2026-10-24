// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"encoding/json"
	"fmt"

	ipa "github.com/neverlless/goipa"
)

// batch runs each entry of methods as the caller through dispatch (Q42).
func (s *Server) batch(c Call, methods json.RawMessage) (any, *ipa.IpaError) {
	var reqs []map[string]json.RawMessage
	if err := json.Unmarshal(methods, &reqs); len(methods) > 0 && err != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeRequirement, Message: "methods must be a list of dicts"}
	}
	results := make([]any, 0, len(reqs))
	for _, req := range reqs {
		results = append(results, s.batchOne(c, req))
	}
	return map[string]any{"count": len(results), "results": results}, nil
}

func (s *Server) batchOne(outer Call, req map[string]json.RawMessage) map[string]any {
	n := Call{User: outer.User, Options: map[string]any{}, session: outer.session}
	var params []json.RawMessage
	var ierr *ipa.IpaError
	switch {
	case req["method"] == nil:
		ierr = requirement("method")
	case req["params"] == nil:
		ierr = requirement("params")
	case json.Unmarshal(req["method"], &n.Method) != nil || json.Unmarshal(req["params"], &params) != nil || len(params) != 2 || decodeParams(&n, params) != nil:
		ierr = requirement("params")
	}
	var result any
	if ierr == nil {
		if v, ok := outer.Options["version"]; ok && n.Options["version"] == nil {
			n.Options["version"] = v
		}
		result, ierr, _ = s.dispatch(n, params[0])
	}
	if ierr != nil {
		kw := json.RawMessage(ierr.Data)
		if !json.Valid(kw) {
			kw = json.RawMessage("{}")
		}
		name := ierr.Name
		if name == "" {
			name = errorNames[ierr.Code]
		}
		return map[string]any{"error": ierr.Message, "error_code": ierr.Code, "error_name": name, "error_kw": kw}
	}
	out := map[string]any{}
	if b, err := json.Marshal(result); err == nil {
		_ = json.Unmarshal(b, &out) // command outputs are objects
	}
	out["error"] = nil
	return out
}

func requirement(name string) *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeRequirement, Message: fmt.Sprintf("'%s' is required", name), Data: fmt.Sprintf(`{"name":%q}`, name)}
}
