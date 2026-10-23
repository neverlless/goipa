// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// The contract tests run the same bodies against the ipatest fake and, with
// -tags integration, a real FreeIPA, so the fake cannot drift from the server.

type backend struct {
	name  string
	host  string
	realm string
	http  *http.Client // trusts the server CA
	admin *ipa.Client  // admin session
}

func (b backend) client() *ipa.Client { return ipa.NewClientCustomHttp(b.host, b.realm, b.http) }

// extraBackends is set by contract_integration_test.go.
var extraBackends func(t *testing.T) []backend

func backends(t *testing.T) []backend {
	srv := ipatest.NewServer(t)
	out := []backend{{"ipatest", srv.Host(), srv.Realm(), srv.HTTPClient(), srv.ClientAs("admin")}}
	if extraBackends != nil {
		out = append(out, extraBackends(t)...)
	}
	return out
}

func forEachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	t.Helper()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
}

func randHex(t *testing.T, n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

// newUID returns an unused uid and deletes that user when the test ends.
func newUID(t *testing.T, b backend) string {
	uid := "gt" + randHex(t, 4)
	t.Cleanup(func() { _ = b.admin.UserDelete(false, false, uid) })
	return uid
}

// newUserWithPassword adds a user whose password pw is not expired.
func newUserWithPassword(t *testing.T, b backend, pw string) string {
	uid := newUID(t, b)
	u := &ipa.User{Username: uid, First: "Go", Last: "Test"}
	if _, err := b.admin.UserAddWithPassword(u, pw); err != nil {
		t.Fatal(err)
	}
	return uid
}

func rawPost(t *testing.T, b backend, path string, form url.Values, referer bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", "https://"+b.host+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if referer {
		req.Header.Set("Referer", "https://"+b.host+"/ipa")
	}
	res, err := b.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func rawLogin(t *testing.T, b backend, uid, pw string) *http.Response {
	t.Helper()
	return rawPost(t, b, "/ipa/session/login_password", url.Values{"user": {uid}, "password": {pw}}, true)
}

func mustLogin(t *testing.T, b backend, uid, pw string) *ipa.Client {
	t.Helper()
	c := b.client()
	if err := c.RemoteLogin(uid, pw); err != nil {
		t.Fatal(err)
	}
	return c
}

func wantIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

const goodPW = "Contract-Passw0rd-1"

// TestContractUserNotFound pins the not-found error of user_show.
func TestContractUserNotFound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		_, err := b.admin.UserShow(newUID(t, b))
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractUserAddDefaults pins Q19: UserAdd leaves unset attributes to
// the server's defaults instead of sending "".
func TestContractUserAddDefaults(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		rec, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if rec.HomeDir != "/home/"+uid {
			t.Errorf("homedirectory %q", rec.HomeDir)
		}
		_, err = b.admin.RPC("user_add", []string{newUID(t, b)}, ipa.Options{"givenname": "Go", "sn": "Test", "homedirectory": ""})
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != 4205 {
			t.Fatalf("empty homedirectory: got %v, want error 4205", err)
		}
	})
}

// TestContractDuplicateUser pins Q10.
func TestContractDuplicateUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		u := &ipa.User{Username: uid, First: "Go", Last: "Test"}
		if _, err := b.admin.UserAdd(u, false); err != nil {
			t.Fatal(err)
		}
		_, err := b.admin.UserAdd(u, false)
		wantIs(t, err, ipa.ErrUserExists)
	})
}

// TestContractRandomPasswordExpired pins Q3.
func TestContractRandomPasswordExpired(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		rec, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, true)
		if err != nil {
			t.Fatal(err)
		}
		if rec.RandomPassword == "" {
			t.Fatal("no random password")
		}
		shown, err := b.admin.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		if shown.PasswdExpire.IsZero() || shown.PasswdExpire.After(time.Now()) {
			t.Errorf("PasswdExpire %v after random password, want set and not after now", shown.PasswdExpire)
		}
		wantIs(t, b.client().RemoteLogin(uid, rec.RandomPassword), ipa.ErrExpiredPassword)
		if err := b.client().SetPassword(uid, rec.RandomPassword, goodPW, ""); err != nil {
			t.Fatal(err)
		}
		if err := b.client().RemoteLogin(uid, goodPW); err != nil {
			t.Fatal(err)
		}
	})
}

// TestContractLoginRejection pins Q5.
func TestContractLoginRejection(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		if err := b.admin.UserDisable(uid); err != nil {
			t.Fatal(err)
		}
		wantIs(t, b.client().RemoteLogin(uid, goodPW), ipa.ErrUnauthorized)
		if got := rawLogin(t, b, uid, goodPW).Header.Get("X-IPA-Rejection-Reason"); got != "user-locked" {
			t.Fatalf("rejection reason %q, want user-locked", got)
		}
	})
}

// TestContractLockout pins Q6.
func TestContractLockout(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		for i := 0; i < 6; i++ {
			wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		}
		wantIs(t, b.client().RemoteLogin(uid, goodPW), ipa.ErrUnauthorized)
		if got := rawLogin(t, b, uid, goodPW).Header.Get("X-IPA-Rejection-Reason"); got != "user-locked" {
			t.Fatalf("rejection reason %q, want user-locked", got)
		}
	})
}

// TestContractSetPasswordResults pins Q4.
func TestContractSetPasswordResults(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		wantIs(t, b.client().SetPassword(uid, "wrong", "Another-Passw0rd-2", ""), ipa.ErrInvalidPassword)
		wantIs(t, b.client().SetPassword(uid, goodPW, "short", ""), ipa.ErrPasswordPolicy)
		res := rawPost(t, b, "/ipa/session/change_password", url.Values{
			"user": {uid}, "old_password": {goodPW}, "new_password": {"short"}, "otp": {""},
		}, true)
		if res.Header.Get("X-IPA-Pwchange-Policy-Error") == "" {
			t.Fatal("no X-IPA-Pwchange-Policy-Error header")
		}
	})
}

// TestContractChangePasswordWrongCurrent pins Q9.
func TestContractChangePasswordWrongCurrent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)
		wantIs(t, c.ChangePassword(uid, "wrong", "Another-Passw0rd-2", ""), ipa.ErrACI)
	})
}

// TestContractUserModNoChange pins Q11.
func TestContractUserModNoChange(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		rec, err := b.admin.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.UserMod(rec)
		if err != nil {
			t.Fatal(err)
		}
		if got.Username != uid {
			t.Fatalf("Username %q, want %q", got.Username, uid)
		}
		rec.First = "Changed"
		got, err = b.admin.UserMod(rec)
		if err != nil {
			t.Fatal(err)
		}
		if got.First != "Changed" {
			t.Fatalf("First %q, want Changed", got.First)
		}
	})
}

// TestContractAlreadyInactive pins Q17.
func TestContractAlreadyInactive(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if err := b.admin.UserDisable(uid); err != nil {
			t.Fatal(err)
		}
		wantIs(t, b.admin.UserDisable(uid), &ipa.IpaError{Code: ipa.CodeAlreadyInactive})
		if err := b.admin.UserEnable(uid); err != nil {
			t.Fatal(err)
		}
		wantIs(t, b.admin.UserEnable(uid), &ipa.IpaError{Code: ipa.CodeAlreadyActive})
	})
}

// TestContractFindOmitsUserclass pins Q1.
func TestContractFindOmitsUserclass(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test", Category: "contract"}, false); err != nil {
			t.Fatal(err)
		}
		res, err := b.admin.RPC("user_find", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var recs []map[string]any
		if err := json.Unmarshal(res.Result.Data, &recs); err != nil || len(recs) != 1 {
			t.Fatalf("user_find data %s: %v", res.Result.Data, err)
		}
		if _, ok := recs[0]["userclass"]; ok {
			t.Fatal("user_find returned userclass")
		}
		rec, err := b.admin.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Category != "contract" {
			t.Fatalf("Category %q, want contract", rec.Category)
		}
	})
}

// TestContractAttributeShapes pins Q16.
func TestContractAttributeShapes(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		res, err := b.admin.RPC("user_show", []string{uid}, ipa.Options{"all": true})
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(res.Result.Data, &rec); err != nil {
			t.Fatal(err)
		}
		var list []string
		if err := json.Unmarshal(rec["uid"], &list); err != nil {
			t.Fatalf("uid is not an array: %s", rec["uid"])
		}
		var locked bool
		if err := json.Unmarshal(rec["nsaccountlock"], &locked); err != nil {
			t.Fatalf("nsaccountlock is not a bool: %s", rec["nsaccountlock"])
		}
	})
}

// TestContractResultShapes pins Q18.
func TestContractResultShapes(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		keys := func(res *ipa.Response) map[string]json.RawMessage {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(res.Result.Raw, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
		res, err := b.admin.RPC("user_show", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"result", "value", "summary"} {
			if _, ok := keys(res)[k]; !ok {
				t.Errorf("user_show has no %q", k)
			}
		}
		res, err = b.admin.RPC("user_find", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		m := keys(res)
		var recs []json.RawMessage
		if err := json.Unmarshal(m["result"], &recs); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := json.Unmarshal(m["count"], &count); err != nil || count != len(recs) {
			t.Errorf("user_find count %s, result has %d", m["count"], len(recs))
		}
		if _, ok := m["truncated"]; !ok {
			t.Error("user_find has no truncated")
		}
		res, err = b.admin.RPC("user_del", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var value []any
		if err := json.Unmarshal(keys(res)["value"], &value); err != nil {
			t.Errorf("user_del value is not an array: %v", err)
		}
	})
}

// TestContractUnknownCommand pins Q14.
func TestContractUnknownCommand(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		_, err := b.admin.RPC("goipa_no_such_cmd", nil, nil)
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != 905 {
			t.Fatalf("got %v, want error 905", err)
		}
	})
}

// TestContractInvalidSession pins Q13.
func TestContractInvalidSession(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.client()
		c.SetSessionID("MagBearerToken=bogus")
		_, err := c.Ping()
		wantIs(t, err, ipa.ErrUnauthorized)
	})
}

// TestContractSessionCookieFormat pins Q15.
func TestContractSessionCookieFormat(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)
		if !strings.HasPrefix(c.SessionID(), "MagBearerToken=") {
			t.Fatalf("session id %q", c.SessionID())
		}
	})
}

// TestContractReferer pins Q12.
func TestContractReferer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		res := rawPost(t, b, "/ipa/session/login_password", url.Values{"user": {newUID(t, b)}, "password": {"x"}}, false)
		if res.StatusCode != 400 {
			t.Fatalf("login_password without Referer: HTTP %d, want 400", res.StatusCode)
		}

		body := `{"method":"ping","params":[[],{"version":"2.251"}]}`
		req, err := http.NewRequest("POST", "https://"+b.host+"/ipa/session/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cookie", "ipa_session="+b.admin.SessionID())
		jr, err := b.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer jr.Body.Close()
		var env struct {
			Error *struct{ Code int } `json:"error"`
		}
		if err := json.NewDecoder(jr.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		if env.Error == nil || env.Error.Code != 911 {
			t.Fatalf("ping without Referer: error %+v, want code 911", env.Error)
		}
	})
}

// TestContractOTPLifecycle pins Q8.
func TestContractOTPLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)
		nb := time.Now().UTC().Truncate(time.Second)
		tok, err := c.AddOTPToken(&ipa.OTPToken{NotBefore: nb, Algorithm: ipa.AlgorithmSHA256})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.RemoveOTPToken(tok.UUID) })

		check := func(enabled bool) {
			t.Helper()
			toks, err := c.FetchOTPTokens(uid)
			if err != nil || len(toks) != 1 {
				t.Fatalf("FetchOTPTokens: %d tokens, err %v", len(toks), err)
			}
			if toks[0].Enabled != enabled {
				t.Fatalf("Enabled %v, want %v", toks[0].Enabled, enabled)
			}
			if !toks[0].NotBefore.Equal(nb) {
				t.Fatalf("NotBefore %v, want %v", toks[0].NotBefore, nb)
			}
			if !strings.EqualFold(toks[0].Type, ipa.TokenTypeTOTP) {
				t.Fatalf("Type %q, want %q (any case)", toks[0].Type, ipa.TokenTypeTOTP)
			}
		}
		check(true)
		if err := c.DisableOTPToken(tok.UUID); err != nil {
			t.Fatal(err)
		}
		check(false)
		if err := c.EnableOTPToken(tok.UUID); err != nil {
			t.Fatal(err)
		}
		check(true)
		wantIs(t, c.RemoveOTPToken("goipa-missing"), ipa.ErrNotFound)
	})
}

// TestContractLastOTPToken pins Q7.
func TestContractLastOTPToken(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)
		tok, err := c.AddOTPToken(nil)
		if err != nil {
			t.Fatal(err)
		}
		// Runs before newUID's user delete; the guard must be off to remove the token.
		t.Cleanup(func() {
			_ = b.admin.SetAuthTypes(uid, nil)
			_ = b.admin.RemoveOTPToken(tok.UUID)
		})
		if err := b.admin.SetAuthTypes(uid, []string{"otp"}); err != nil {
			t.Fatal(err)
		}
		err = c.RemoveOTPToken(tok.UUID)
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != 4203 {
			t.Fatalf("got %v, want error 4203", err)
		}
	})
}
