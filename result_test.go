// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestResultFindFields(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`{"result":[{"uid":["a"]}],"count":1,"truncated":true,"summary":"1 user matched",`+
		`"messages":[{"type":"warning","name":"SearchResultTruncated","message":"Search result has been truncated","code":13017,"data":{"msg":"x"}}]}`))
	res, err := c.RPC("user_find", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Result
	if r.Count != 1 || !r.Truncated || r.Summary != "1 user matched" || len(r.Messages) != 1 {
		t.Fatalf("unexpected result: %+v", r)
	}
	m := r.Messages[0]
	if m.Code != 13017 || m.Name != "SearchResultTruncated" || m.Type != "warning" || string(m.Data) != `{"msg":"x"}` {
		t.Errorf("unexpected message: %+v", m)
	}
	if string(r.Data) != `[{"uid":["a"]}]` {
		t.Errorf("Data = %s", r.Data)
	}
}

func TestResultMemberFields(t *testing.T) {
	failed := `{"member":{"user":[["bob","This entry is already a member"]]}}`
	c, _ := newFakeIPA(t, 200, envelope(`{"result":{"cn":["g"]},"completed":1,"failed":`+failed+`}`))
	res, err := c.RPC("group_add_member", []string{"g"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result.Completed != 1 || string(res.Result.Failed) != failed {
		t.Errorf("Completed=%d Failed=%s", res.Result.Completed, res.Result.Failed)
	}
}

func TestResultRawWithoutResultKey(t *testing.T) {
	raw := `{"summary":"Access granted: True","value":true,"matched":["allow_all"],"notmatched":null,"error":null,"warning":null}`
	c, _ := newFakeIPA(t, 200, envelope(raw))
	res, err := c.RPC("hbactest", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result.Data != nil || res.Result.Value != true || string(res.Result.Raw) != raw {
		t.Errorf("Data=%s Value=%v Raw=%s", res.Result.Data, res.Result.Value, res.Result.Raw)
	}
}

func TestRPCNullResult(t *testing.T) {
	c, _ := newFakeIPA(t, 200, envelope(`null`))
	if res, err := c.RPC("ping", nil, nil); err == nil || res != nil {
		t.Errorf("RPC = %v, %v; want error", res, err)
	}
	if _, err := c.UserShow("bob"); err == nil {
		t.Error("UserShow: want error")
	}
}

func TestRPCNonJSONBody(t *testing.T) {
	c, _ := newFakeIPA(t, 200, "<html>proxy error</html>")
	if res, err := c.RPC("ping", nil, nil); err == nil || res != nil {
		t.Errorf("RPC = %v, %v; want error", res, err)
	}
}

func TestRPCResponseTooLarge(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat(" ", 1<<20))
		for i := 0; i < 64; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(" "))
	}))
	defer ts.Close()
	c := ipa.NewClientCustomHttp(strings.TrimPrefix(ts.URL, "https://"), "EXAMPLE.COM", ts.Client())
	_, err := c.RPC("ping", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}
