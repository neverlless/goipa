// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// BatchCall is one command of a Batch: what RPC would take.
type BatchCall struct {
	Method  string
	Args    []string
	Options Options
}

// BatchResult is the outcome of one BatchCall: Result on success, otherwise
// Err, always a bare *IpaError with FreeIPA's error_code, error_name, error
// and error_kw (as Data); errors.Is, errors.As and err.(*ipa.IpaError) work
// on it. Err is an error, not *IpaError, so Err != nil holds only on failure.
type BatchResult struct {
	Result *Result
	Err    error
}

// Batch runs calls in one FreeIPA batch request, in order, and returns one
// BatchResult per call. A failed command does not stop the others and does
// not make err non-nil; err is set only when the whole batch fails. The
// commands are not atomic: earlier ones stay applied when a later one fails.
// A result the client cannot decode fails the whole call, although the
// server ran the commands. No call's Options is modified.
func (c *Client) Batch(ctx context.Context, calls ...BatchCall) ([]BatchResult, error) {
	if len(calls) == 0 {
		return nil, errors.New("ipa: batch: no calls")
	}
	methods := make([]any, len(calls))
	for i, bc := range calls {
		args, opts := bc.Args, bc.Options
		if c.validate {
			if err := validateCall(bc.Method, c.ServerVersion(), len(args), opts); err != nil {
				return nil, fmt.Errorf("ipa: batch call %d: %w", i, err)
			}
		}
		if args == nil {
			args = []string{}
		}
		if opts == nil {
			opts = Options{}
		}
		methods[i] = Options{"method": bc.Method, "params": []any{args, opts}}
	}
	res, err := c.rpcParams(ctx, "batch", methods, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(res.Result.Raw, &out); err != nil {
		return nil, fmt.Errorf("ipa: decode batch result: %w", err)
	}
	if len(out.Results) != len(calls) {
		return nil, fmt.Errorf("ipa: batch returned %d results for %d calls", len(out.Results), len(calls))
	}
	results := make([]BatchResult, len(calls))
	for i, raw := range out.Results {
		var e struct {
			Error *string         `json:"error"`
			Code  int             `json:"error_code"`
			Name  string          `json:"error_name"`
			Kw    json.RawMessage `json:"error_kw"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("ipa: decode batch result %d: %w", i, err)
		}
		if e.Error != nil {
			results[i].Err = &IpaError{Message: *e.Error, Code: e.Code, Name: e.Name, Data: string(e.Kw)}
			continue
		}
		results[i].Result = new(Result)
		if err := json.Unmarshal(raw, results[i].Result); err != nil {
			return nil, fmt.Errorf("ipa: decode batch result %d: %w", i, err)
		}
	}
	return results, nil
}
