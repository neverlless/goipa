// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ipa "github.com/neverlless/goipa"
)

type rpcCall struct {
	Path, Cookie, Method string
	Args                 json.RawMessage // params[0] verbatim, to tell [] from null
	Options              map[string]any  // params[1]
}

type fakeIPA struct {
	mu     sync.Mutex
	calls  []rpcCall
	status int
	body   string
}

func newFakeIPA(t *testing.T, status int, body string) (*ipa.Client, *fakeIPA) {
	t.Helper()
	f := &fakeIPA{status: status, body: body}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Method string
			Params []json.RawMessage
		}
		call := rpcCall{Path: r.URL.Path, Cookie: r.Header.Get("Cookie")}
		if json.Unmarshal(raw, &req) == nil {
			call.Method = req.Method
			if len(req.Params) > 0 {
				call.Args = req.Params[0]
			}
			if len(req.Params) > 1 {
				_ = json.Unmarshal(req.Params[1], &call.Options)
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, call)
		f.mu.Unlock()
		w.WriteHeader(f.status)
		io.WriteString(w, f.body)
	}))
	t.Cleanup(ts.Close)
	return ipa.NewClientCustomHttp(strings.TrimPrefix(ts.URL, "https://"), "EXAMPLE.COM", ts.Client()), f
}

func (f *fakeIPA) Calls() []rpcCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]rpcCall(nil), f.calls...)
}

func envelope(result string) string {
	return `{"error":null,"id":0,"principal":"admin@EXAMPLE.COM","version":"4.13.4","result":` + result + `}`
}

func errorBody(code int, name, message string) string {
	return fmt.Sprintf(`{"result":null,"error":{"code":%d,"message":%q,"name":%q,"data":{"reason":%q}},"id":0,"principal":"admin@EXAMPLE.COM","version":"4.13.4"}`, code, message, name, message)
}
