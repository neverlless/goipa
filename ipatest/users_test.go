// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"golang.org/x/crypto/ssh"
)

func sshLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " laptop"
}

func postForm(t *testing.T, s *ipatest.Server, path string, v url.Values, referer bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.URL()+path, strings.NewReader(v.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if referer {
		req.Header.Set("Referer", s.URL()+"/ipa")
	}
	res, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func ipaCode(t *testing.T, err error) int {
	t.Helper()
	var ie *ipa.IpaError
	if !errors.As(err, &ie) {
		t.Fatalf("err = %v, want *ipa.IpaError", err)
	}
	return ie.Code
}

func TestUserFieldsRoundTrip(t *testing.T) {
	s := ipatest.NewServer(t)
	expire := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.AddUser("jesse", ipatest.User{
		Password: "pw", Locked: true, Groups: []string{"g1", "g2"}, AuthTypes: []string{"password", "otp"},
		Email: "j@example.org", First: "Jesse", Last: "Pinkman", DisplayName: "Jesse P",
		Category: "gold", Telephone: "+1 555", Mobile: "+1 666", Shell: "/bin/zsh", HomeDir: "/h/jesse",
		SSHPubKeys: []string{sshLine(t)}, PasswdExpire: expire,
		Emails: []string{"j@example.org", "j2@example.org"}, Street: "1 Main", City: "Town", State: "ST",
		PostalCode: "12345", PreferredLanguage: "en", Title: "Dr", OrgUnit: "Lab", Passkeys: []string{"passkey:a,b"},
	})
	got, err := s.ClientAs("admin").UserShow("jesse")
	if err != nil {
		t.Fatal(err)
	}
	// Not modelled, or planned for v0.5.
	skip := map[string]string{
		"HasKeytab":        "no keytabs",
		"Preserved":        "false for a live user",
		"SudoRules":        "v0.5",
		"HbacRules":        "v0.5",
		"PrincipalExpire":  "not modelled",
		"LastLoginSuccess": "not modelled",
		"LastLoginFail":    "not modelled",
		"LastPasswdChange": "not modelled",
		"RandomPassword":   "only in add/mod responses",
		"IndirectGroups":   "derived from group records",
	}
	v := reflect.ValueOf(*got)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if _, ok := skip[name]; ok {
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("ipa.User.%s is zero: ipatest does not fill it", name)
		}
	}
	if !got.PasswdExpire.Equal(expire) || got.Email != "j@example.org" || len(got.SSHAuthKeys) != 1 {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jesse", ipatest.User{Groups: []string{"a"}})
	u, _ := s.User("jesse")
	u.Groups = append(u.Groups, "b")
	u.Groups[0] = "z"
	again, _ := s.User("jesse")
	if !slices.Equal(again.Groups, []string{"a"}) {
		t.Errorf("Groups = %v", again.Groups)
	}
	if _, ok := s.User("nobody"); ok {
		t.Error("User(nobody) ok")
	}
}

func TestUpdateUser(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jesse", ipatest.User{Password: "pw"})
	if !s.UpdateUser("jesse", func(u *ipatest.User) { u.Locked = true }) {
		t.Fatal("UpdateUser = false")
	}
	if err := s.Client().RemoteLogin("jesse", "pw"); !errors.Is(err, ipa.ErrUnauthorized) {
		t.Errorf("RemoteLogin = %v, want ErrUnauthorized", err)
	}
	if s.UpdateUser("nobody", func(*ipatest.User) {}) {
		t.Error("UpdateUser(nobody) = true")
	}
}

func TestMissingPrimaryKey(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("user_show", nil, nil)
	if got := ipaCode(t, err); got != ipa.CodeRequirement {
		t.Errorf("code = %d", got)
	}
}

func TestParamsNullOptions(t *testing.T) {
	s := ipatest.NewServer(t)
	req, _ := http.NewRequest(http.MethodPost, s.URL()+"/ipa/session/json", strings.NewReader(`{"method":"ping","params":[[],null]}`))
	req.Header.Set("Referer", s.URL()+"/ipa")
	req.Header.Set("Cookie", "ipa_session="+s.Session("admin"))
	res, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	calls := s.Calls()
	if res.StatusCode != 200 || len(calls) != 1 || calls[0].Options == nil {
		t.Errorf("status %d, calls %+v", res.StatusCode, calls)
	}
}

func TestFormsNeedReferer(t *testing.T) {
	s := ipatest.NewServer(t)
	for _, p := range []string{"/ipa/session/login_password", "/ipa/session/change_password"} {
		if res := postForm(t, s, p, url.Values{"user": {"x"}}, false); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", p, res.StatusCode)
		}
	}
}

func TestUserFindFilters(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{Email: "bob@example.com", Category: "c"})
	s.AddUser("alice", ipatest.User{})
	s.AddUser("carol", ipatest.User{Preserved: true})
	c := s.ClientAs("admin")
	names := func(opts ipa.Options) []string {
		us, err := c.UserFind(opts)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, u := range us {
			out = append(out, u.Username)
		}
		return out
	}
	if got := names(ipa.Options{"mail": "bob@example.com"}); !slices.Equal(got, []string{"bob"}) {
		t.Errorf("mail filter: %v", got)
	}
	if got := names(nil); !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("nil: %v", got)
	}
	if got := names(ipa.Options{"preserved": true}); !slices.Equal(got, []string{"carol"}) {
		t.Errorf("preserved: %v", got)
	}
	// the search argument is a case-insensitive substring
	resp, err := c.RPC("user_find", []string{"ALI"}, ipa.Options{})
	if err != nil || resp.Result.Count != 1 {
		t.Fatalf("substring: %v %+v", err, resp)
	}
	if strings.Contains(string(resp.Result.Data), "userclass") {
		t.Errorf("user_find without all leaked userclass: %s", resp.Result.Data)
	}
	resp, _ = c.RPC("user_find", []string{"bob"}, ipa.Options{"all": true})
	if !strings.Contains(string(resp.Result.Data), "userclass") {
		t.Errorf("user_find all: userclass missing: %s", resp.Result.Data)
	}
	resp, _ = c.RPC("user_show", []string{"bob"}, nil)
	if !strings.Contains(string(resp.Result.Data), "userclass") {
		t.Errorf("user_show: userclass missing")
	}
}

func TestUserAddModDel(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	u := &ipa.User{Username: "walt", First: "Walter", Last: "White"}
	rec, err := c.UserAdd(u, true)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RandomPassword == "" || rec.Uid == "" || rec.UUID == "" || rec.Principal != "walt@TEST.LOCAL" || !rec.HasPassword {
		t.Errorf("add: %+v", rec)
	}
	if st, _ := s.User("walt"); !expired(st) || st.Email != "walt@example.com" || st.HomeDir != "/home/walt" || st.Shell != "/bin/sh" {
		t.Errorf("stored: %+v", st)
	}
	if _, err := c.UserAdd(u, false); !errors.Is(err, ipa.ErrUserExists) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := c.UserAdd(&ipa.User{Username: "x", First: "X"}, false); ipaCode(t, err) != ipa.CodeRequirement {
		t.Errorf("empty sn: %v", err)
	}
	other, _ := c.UserAdd(&ipa.User{Username: "skyler", First: "S", Last: "W"}, false)
	if other.HasPassword || other.Uid == rec.Uid {
		t.Errorf("second user: %+v", other)
	}

	// Unchanged ToOptions: EmptyModlist, which UserMod swallows.
	if _, err := c.RPC("user_mod", []string{"walt"}, ipa.Options{"givenname": "Walter"}); ipaCode(t, err) != ipa.CodeEmptyModlist {
		t.Errorf("empty modlist: %v", err)
	}
	u.Email = "heisenberg@example.com"
	u.SSHAuthKeys = nil
	if _, err := c.UserMod(u); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.User("walt"); st.Email != "heisenberg@example.com" {
		t.Errorf("mod: %+v", st)
	}
	if _, err := c.RPC("user_mod", []string{"nobody"}, ipa.Options{"sn": "x"}); !errors.Is(err, ipa.ErrNotFound) && ipaCode(t, err) != ipa.CodeNotFound {
		t.Errorf("mod missing: %v", err)
	}
	if err := c.SetAuthTypes("walt", []string{"otp"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.User("walt"); !slices.Equal(st.AuthTypes, []string{"otp"}) {
		t.Errorf("authtypes: %v", st.AuthTypes)
	}
	if err := c.SetAuthTypes("walt", nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.User("walt"); len(st.AuthTypes) != 0 {
		t.Errorf("authtypes: %v", st.AuthTypes)
	}
	if pw, err := c.ResetPassword("walt"); err != nil || pw == "" {
		t.Errorf("ResetPassword: %q %v", pw, err)
	}

	// delete: missing without continue fails and deletes nothing
	if err := c.UserDelete(false, true, "walt", "ghost"); ipaCode(t, err) != ipa.CodeNotFound {
		t.Errorf("del missing: %v", err)
	}
	if _, ok := s.User("walt"); !ok {
		t.Error("walt deleted despite error")
	}
	if err := c.UserDelete(true, false, "walt", "ghost"); err != nil {
		t.Fatal(err)
	}
	if st, ok := s.User("walt"); !ok || !st.Preserved || !st.Locked {
		t.Errorf("preserve: %+v %v", st, ok)
	}
	if err := c.UserDelete(false, false, "walt", "skyler"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.User("walt"); ok {
		t.Error("walt still there")
	}
	resp, _ := c.RPC("user_del", []string{"ghost"}, ipa.Options{"continue": true})
	if string(resp.Result.Data) != `{"failed":["ghost"]}` {
		t.Errorf("failed list: %s", resp.Result.Data)
	}
}

func TestUserAddEmptyHomeDir(t *testing.T) {
	c := ipatest.NewServer(t).ClientAs("admin")
	_, err := c.RPC("user_add", []string{"x"}, ipa.Options{"givenname": "X", "sn": "Y", "homedirectory": ""})
	if ipaCode(t, err) != 4205 {
		t.Errorf("empty homedirectory: %v", err)
	}
}

func TestUserDisableEnable(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jesse", ipatest.User{})
	c := s.ClientAs("admin")
	if err := c.UserEnable("jesse"); ipaCode(t, err) != ipa.CodeAlreadyActive {
		t.Errorf("enable enabled: %v", err)
	}
	if err := c.UserDisable("jesse"); err != nil {
		t.Fatal(err)
	}
	if err := c.UserDisable("jesse"); ipaCode(t, err) != ipa.CodeAlreadyInactive {
		t.Errorf("disable disabled: %v", err)
	}
	if u, _ := s.User("jesse"); !u.Locked {
		t.Error("not locked")
	}
	if err := c.UserEnable("jesse"); err != nil {
		t.Fatal(err)
	}
	if err := c.UserDisable("ghost"); ipaCode(t, err) != ipa.CodeNotFound {
		t.Errorf("disable missing: %v", err)
	}
}

func TestLoginFormRejections(t *testing.T) {
	s := ipatest.NewServer(t)
	past := time.Now().Add(-time.Hour)
	s.AddUser("ok", ipatest.User{Password: "right"})
	s.AddUser("nopw", ipatest.User{})
	s.AddUser("expired", ipatest.User{Password: "right", PasswdExpire: time.Now()})
	s.AddUser("pastexp", ipatest.User{Password: "right", PasswdExpire: past})
	s.AddUser("locked", ipatest.User{Password: "right", Locked: true})
	s.AddUser("preserved", ipatest.User{Password: "right", Preserved: true})
	s.AddUser("lockout", ipatest.User{Password: "right"})
	login := func(uid, pw string) *http.Response {
		return postForm(t, s, "/ipa/session/login_password", url.Values{"user": {uid}, "password": {pw}}, true)
	}
	for i := 0; i < 6; i++ {
		login("lockout", "wrong")
	}
	for _, tc := range []struct {
		uid, pw string
		status  int
		reason  string
	}{
		{"ok", "right", 200, ""},
		{"ok", "wrong", 401, "invalid-password"},
		{"ghost", "x", 401, "invalid-password"},
		{"nopw", "", 401, "invalid-password"},
		{"expired", "right", 401, "password-expired"},
		{"pastexp", "right", 401, "password-expired"},
		{"locked", "right", 401, "user-locked"},
		{"preserved", "right", 401, "user-locked"},
		{"lockout", "right", 401, "user-locked"},
	} {
		res := login(tc.uid, tc.pw)
		if res.StatusCode != tc.status || res.Header.Get("X-IPA-Rejection-Reason") != tc.reason {
			t.Errorf("%s/%s: %d %q, want %d %q", tc.uid, tc.pw, res.StatusCode, res.Header.Get("X-IPA-Rejection-Reason"), tc.status, tc.reason)
		}
	}
	// a failed login counts, a good one resets
	s.AddUser("count", ipatest.User{Password: "right"})
	login("count", "wrong")
	if u, _ := s.User("count"); u.FailedLogins != 1 {
		t.Errorf("FailedLogins = %d", u.FailedLogins)
	}
	login("count", "right")
	if u, _ := s.User("count"); u.FailedLogins != 0 {
		t.Errorf("FailedLogins after success = %d", u.FailedLogins)
	}
	c := s.Client()
	if err := c.RemoteLogin("expired", "right"); !errors.Is(err, ipa.ErrExpiredPassword) {
		t.Errorf("RemoteLogin expired: %v", err)
	}
	if err := c.RemoteLogin("ok", "right"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ping(); err != nil {
		t.Errorf("session from login: %v", err)
	}
}

func TestChangePasswordForm(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jesse", ipatest.User{Password: "oldpass12", PasswdExpire: time.Now().Add(-time.Hour)})
	c := s.Client()
	if err := c.SetPassword("jesse", "wrong", "newpass12", ""); !errors.Is(err, ipa.ErrInvalidPassword) {
		t.Errorf("wrong old: %v", err)
	}
	if err := c.SetPassword("ghost", "x", "newpass12", ""); !errors.Is(err, ipa.ErrInvalidPassword) {
		t.Errorf("ghost: %v", err)
	}
	if err := c.SetPassword("jesse", "oldpass12", "short", ""); !errors.Is(err, ipa.ErrPasswordPolicy) {
		t.Errorf("short: %v", err)
	}
	if err := c.SetPassword("jesse", "oldpass12", "newpass12", ""); err != nil {
		t.Fatal(err)
	}
	u, _ := s.User("jesse")
	if u.Password != "newpass12" || expired(u) || u.PasswdExpire.Before(time.Now().Add(89*24*time.Hour)) {
		t.Errorf("after change: %+v", u)
	}
	if err := c.RemoteLogin("jesse", "newpass12"); err != nil {
		t.Errorf("login with new password: %v", err)
	}
}

func TestChangePasswordPolicyHeader(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jesse", ipatest.User{Password: "oldpass12"})
	res := postForm(t, s, "/ipa/session/change_password", url.Values{"user": {"jesse"}, "old_password": {"oldpass12"}, "new_password": {"short"}}, true)
	if res.StatusCode != 200 || res.Header.Get("X-IPA-Pwchange-Result") != "policy-error" || res.Header.Get("X-IPA-Pwchange-Policy-Error") == "" {
		t.Errorf("%d %v", res.StatusCode, res.Header)
	}
}

func expired(u ipatest.User) bool {
	return !u.PasswdExpire.IsZero() && !u.PasswdExpire.After(time.Now())
}

func TestPasswdByAdminExpires(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{Password: "old"})
	if err := s.ClientAs("admin").ChangePassword("bob", "old", "newpass12", ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User("bob"); !expired(u) || u.Password != "newpass12" {
		t.Errorf("by admin: %+v", u)
	}
	if err := s.ClientAs("bob").ChangePassword("bob", "newpass12", "another12", ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User("bob"); expired(u) || u.PasswdExpire.IsZero() {
		t.Errorf("by self: %+v", u)
	}
	err := s.ClientAs("bob").ChangePassword("bob", "wrong", "x", "")
	if ipaCode(t, err) != ipa.CodeACI || !strings.Contains(err.Error(), "Invalid credentials") {
		t.Errorf("wrong current: %v", err)
	}
	if err := s.ClientAs("bob").ChangePassword("ghost", "a", "b", ""); ipaCode(t, err) != ipa.CodeNotFound {
		t.Errorf("ghost: %v", err)
	}
}

func TestUserModRequiredNames(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("walt", ipatest.User{})
	c := s.ClientAs("admin")
	for _, opt := range []string{"givenname", "sn"} {
		if _, err := c.RPC("user_mod", []string{"walt"}, ipa.Options{opt: ""}); ipaCode(t, err) != ipa.CodeRequirement {
			t.Errorf("%s cleared: %v", opt, err)
		}
	}
	if u, _ := s.User("walt"); u.First != "Test" || u.Last != "User" {
		t.Errorf("stored: %+v", u)
	}
}

func TestUserModEmptySliceUnchanged(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("walt", ipatest.User{SSHPubKeys: []string{}, Groups: []string{}})
	if _, err := s.ClientAs("admin").RPC("user_mod", []string{"walt"}, ipa.Options{"ipasshpubkey": []string{}}); ipaCode(t, err) != ipa.CodeEmptyModlist {
		t.Errorf("unchanged mod: %v", err)
	}
}

func TestUserFind_MatchesAllMails(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("dave", ipatest.User{Emails: []string{"d1@example.com", "d2@example.com"}})
	c := s.ClientAs("admin")
	if us, err := c.UserFind(ipa.Options{"mail": "d2@example.com"}); err != nil || len(us) != 1 {
		t.Errorf("mail option: %v, %v", us, err)
	}
	res := rpc(t, c, "user_find", []string{"d2@"}, nil)
	if res.Result.Count != 1 {
		t.Errorf("needle: Count = %d", res.Result.Count)
	}
}

func TestStageUserSeedAndActivate(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddStageUser("sam", ipatest.User{Category: "staff"})
	u, ok := s.StageUser("sam")
	if !ok || !u.Locked || u.Email != "sam@example.com" {
		t.Fatalf("StageUser = %+v, %v", u, ok)
	}
	if _, ok := s.User("sam"); ok {
		t.Fatal("stage user is active")
	}
	if _, err := s.ClientAs("admin").StageUserActivate("sam"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.StageUser("sam"); ok {
		t.Error("stage entry kept")
	}
	if a, ok := s.User("sam"); !ok || a.Locked || a.Category != "staff" {
		t.Errorf("User = %+v, %v", a, ok)
	}
}

func TestStageUserDuplicateAndDelete(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	s.AddGroup("g", ipatest.Group{Members: []string{"x"}})
	s.AddUser("x", ipatest.User{})
	s.AddStageUser("x", ipatest.User{})

	_, err := c.StageUserAdd(&ipa.User{Username: "x", First: "A", Last: "B"})
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeDuplicateEntry || ie.Message != `stage user with name "x" already exists` {
		t.Errorf("duplicate = %v", err)
	}

	res, err := c.RPC("stageuser_del", []string{"x"}, ipa.Options{"preserve": true})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Result.Data) != `{"failed":[]}` {
		t.Errorf("result = %s", res.Result.Data)
	}
	if v, ok := res.Result.Value.([]any); !ok || len(v) != 1 || v[0] != "x" {
		t.Errorf("value = %v", res.Result.Value)
	}
	if res.Result.Summary != `Deleted stage user "x"` {
		t.Errorf("summary = %q", res.Result.Summary)
	}
	if _, ok := s.StageUser("x"); ok {
		t.Error("stage entry kept (preserve must be ignored)")
	}
	if u, ok := s.User("x"); !ok || u.Preserved {
		t.Errorf("active user changed: %+v, %v", u, ok)
	}
	if u, err := c.UserShow("x"); err != nil || !u.HasGroup("g") {
		t.Errorf("active x lost its group membership: %+v, %v", u, err)
	}

	err = c.StageUserDelete("x")
	if !errors.As(err, &ie) || ie.Code != ipa.CodeNotFound || ie.Message != "x: stage user not found" {
		t.Errorf("missing = %v", err)
	}

	s.AddStageUser("y", ipatest.User{})
	if _, err := c.StageUserActivate("y"); err != nil {
		t.Fatal(err)
	}
	if u, err := c.UserShow("y"); err != nil || u.Uid == "" {
		t.Errorf("uidnumber after activate: %+v, %v", u, err)
	}
}
