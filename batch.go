// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tidwall/gjson"
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

// DecodeUser decodes the result of a batched user_show (or stageuser_show)
// into a User, as UserShow does. Send UserShow's options (all: true,
// no_members: false) so the result matches. r.Err is returned as it is.
func DecodeUser(r BatchResult) (*User, error) {
	if err := batchData(r); err != nil {
		return nil, err
	}
	u := new(User)
	if err := u.fromJSON(r.Result.Data); err != nil {
		return nil, err
	}
	return u, nil
}

// DecodeGroups decodes the result of a batched group_find into Groups, as
// GroupFind does. Send GroupFind's options (all: true, no_members: false).
// A truncated search is flagged in r.Result.Truncated, not as an error.
func DecodeGroups(r BatchResult) ([]*Group, error) {
	if err := batchData(r); err != nil {
		return nil, err
	}
	groups := make([]*Group, 0)
	for _, t := range gjson.ParseBytes(r.Result.Data).Array() {
		g := new(Group)
		if err := g.fromJSON([]byte(t.Raw)); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// DecodeOTPTokens decodes the result of a batched otptoken_find into
// OTPTokens, as FetchOTPTokens does. Send its options (ipatokenowner,
// all: true). A truncated search is flagged in r.Result.Truncated.
func DecodeOTPTokens(r BatchResult) ([]*OTPToken, error) {
	if err := batchData(r); err != nil {
		return nil, err
	}
	tokens := make([]*OTPToken, 0)
	for _, t := range gjson.ParseBytes(r.Result.Data).Array() {
		tok := new(OTPToken)
		if err := tok.fromJSON([]byte(t.Raw)); err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
	}
	return tokens, nil
}

func batchData(r BatchResult) error {
	if r.Err != nil {
		return r.Err
	}
	if r.Result == nil {
		return errors.New("ipa: batch result is empty")
	}
	return nil
}
