// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func fullUser() ipatest.User {
	return ipatest.User{
		Email: "a@x", Emails: []string{"a@x", "b@x"},
		Street: "1 Main St", City: "Town", State: "ST", PostalCode: "12345",
		PreferredLanguage: "en", Title: "Dr", OrgUnit: "Lab",
		Passkeys: []string{"passkey:id1,key1"},
		Groups:   []string{"g1"},
	}
}

func TestUserShow_NewFields(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g1", ipatest.Group{})
	s.AddGroup("g2", ipatest.Group{MemberGroups: []string{"g1"}})
	s.AddUser("jdoe", fullUser())
	u, err := c.UserShow("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "a@x" || !slices.Equal(u.Emails, []string{"a@x", "b@x"}) {
		t.Errorf("Email/Emails = %q %v", u.Email, u.Emails)
	}
	for name, p := range map[string][2]string{
		"Street": {u.Street, "1 Main St"}, "City": {u.City, "Town"}, "State": {u.State, "ST"},
		"PostalCode": {u.PostalCode, "12345"}, "PreferredLanguage": {u.PreferredLanguage, "en"},
		"Title": {u.Title, "Dr"}, "OrgUnit": {u.OrgUnit, "Lab"},
	} {
		if p[0] != p[1] {
			t.Errorf("%s = %q, want %q", name, p[0], p[1])
		}
	}
	if !slices.Equal(u.Passkeys, []string{"passkey:id1,key1"}) {
		t.Errorf("Passkeys = %v", u.Passkeys)
	}
	if !slices.Equal(u.Groups, []string{"g1"}) || !slices.Equal(u.IndirectGroups, []string{"g2"}) {
		t.Errorf("Groups/IndirectGroups = %v %v", u.Groups, u.IndirectGroups)
	}
}

func TestIpatest_AddressNeedsAll(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("jdoe", fullUser())
	for _, all := range []bool{false, true} {
		res, err := c.RPC("user_show", []string{"jdoe"}, ipa.Options{"all": all})
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]any
		if err := json.Unmarshal(res.Result.Data, &rec); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"street", "l", "st", "postalcode", "preferredlanguage"} {
			if _, ok := rec[k]; ok != all {
				t.Errorf("all=%v: key %q present = %v", all, k, ok)
			}
		}
		for _, k := range []string{"title", "ou", "ipapasskey"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("all=%v: key %q missing", all, k)
			}
		}
	}
}

func TestUserFind_IndirectGroupsEmpty(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g1", ipatest.Group{})
	s.AddGroup("g2", ipatest.Group{MemberGroups: []string{"g1"}})
	s.AddUser("jdoe", ipatest.User{Groups: []string{"g1"}})
	us, err := c.UserFind(ipa.Options{"uid": "jdoe"})
	if err != nil || len(us) != 1 {
		t.Fatalf("UserFind = %v, %v", us, err)
	}
	for _, g := range []string{"g1", "g2"} {
		if !us[0].HasGroup(g) {
			t.Errorf("Groups %v lacks %s", us[0].Groups, g)
		}
	}
	if len(us[0].IndirectGroups) != 0 {
		t.Errorf("IndirectGroups = %v, want empty", us[0].IndirectGroups)
	}
}

// Every exported ipa.User field is seeded through ipatest and must come back.
func TestIpatest_UserFieldsRoundTrip(t *testing.T) {
	skip := map[string]string{
		"RandomPassword":   "only in the response of a random=true call",
		"LastPasswdChange": "time, not modelled",
		"PrincipalExpire":  "time, not modelled",
		"LastLoginSuccess": "time, not modelled",
		"LastLoginFail":    "time, not modelled",
		"PasswdExpire":     "time, covered by the password tests",
		"SudoRules":        "sudo rules are not modelled",
		"HbacRules":        "HBAC rules are not modelled",
		"Category":         "covered by TestUserModFields",
		"SSHAuthKeys":      "parsed type, covered by TestUserModFields",
		"UUID":             "assigned by the server",
		"DN":               "assigned by the server",
		"Principal":        "assigned by the server",
		"Uid":              "assigned by the server",
		"Gid":              "assigned by the server",
		"HasKeytab":        "always false in ipatest",
		"Preserved":        "set by user_del preserve",
		"IndirectGroups":   "derived from group records, see TestUserShow_NewFields",
		"Groups":           "see TestUserShow_NewFields",
		"AuthTypes":        "covered by TestUserAuthTypes",
		"Locked":           "set by user_disable",
		"HasPassword":      "set by a password",
	}
	s, c := newFake(t)
	seed := fullUser()
	seed.Groups = nil
	seed.First, seed.Last, seed.DisplayName = "F", "L", "F L"
	seed.Telephone, seed.Mobile, seed.Shell, seed.HomeDir = "1", "2", "/bin/zsh", "/h/jdoe"
	s.AddUser("jdoe", seed)
	u, err := c.UserShow("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	rv, rt := reflect.ValueOf(*u), reflect.TypeOf(*u)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if _, ok := skip[f.Name]; ok || !f.IsExported() {
			continue
		}
		if rv.Field(i).IsZero() {
			t.Errorf("field %s did not round-trip (zero); add it to the seed or to skip with a reason", f.Name)
		}
	}
}

func TestToOptions_SingleEmailIsString(t *testing.T) {
	if got := (&ipa.User{Email: "a@x"}).ToOptions()["mail"]; got != "a@x" {
		t.Errorf("mail = %#v, want string a@x", got)
	}
}

func TestToOptions_NoEmailClears(t *testing.T) {
	if got := (&ipa.User{}).ToOptions()["mail"]; got != "" {
		t.Errorf("mail = %#v, want empty string", got)
	}
}

func TestToOptions_Extras(t *testing.T) {
	got := (&ipa.User{Email: "a@x", Emails: []string{"a@x", "b@x"}}).ToOptions()["mail"]
	if !reflect.DeepEqual(got, []string{"a@x", "b@x"}) {
		t.Errorf("mail = %#v", got)
	}
}

func TestToOptions_DedupCaseInsensitive(t *testing.T) {
	if got := (&ipa.User{Email: "B@x", Emails: []string{"a@x", "b@x"}}).ToOptions()["mail"]; got != "B@x" {
		t.Errorf("mail = %#v, want string B@x", got)
	}
}

func TestUserMod_KeepsExtras(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("jdoe", ipatest.User{Emails: []string{"a@x", "b@x"}})
	u, err := c.UserShow("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	u.Mobile = "1"
	if _, err := c.UserMod(u); err != nil {
		t.Fatal(err)
	}
	got, _ := s.User("jdoe")
	if !slices.Equal(got.Emails, []string{"a@x", "b@x"}) || got.Mobile != "1" {
		t.Errorf("server Emails/Mobile = %v %q", got.Emails, got.Mobile)
	}
}

func TestUserMod_ReplacePrimaryKeepsExtras(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("jdoe", ipatest.User{Emails: []string{"a@x", "b@x"}})
	u, err := c.UserShow("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "c@x"
	ret, err := c.UserMod(u)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"c@x", "b@x"}
	if got, _ := s.User("jdoe"); !slices.Equal(got.Emails, want) {
		t.Errorf("server Emails = %v, want %v", got.Emails, want)
	}
	if ret.Email != "c@x" || !slices.Equal(ret.Emails, want) {
		t.Errorf("returned Email/Emails = %q %v", ret.Email, ret.Emails)
	}
}

type captureTransport struct {
	rt   http.RoundTripper
	form url.Values
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/change_password") {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		c.form, _ = url.ParseQuery(string(b))
	}
	return c.rt.RoundTrip(r)
}

func TestSetPassword_OmitsEmptyOTP(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("jdoe", ipatest.User{Password: "old-password-1"})
	ct := &captureTransport{rt: s.HTTPClient().Transport}
	c := ipa.NewClientCustomHttp(s.Host(), s.Realm(), &http.Client{Transport: ct})

	if err := c.SetPassword("jdoe", "old-password-1", "new-password-1", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := ct.form["otp"]; ok {
		t.Errorf("empty OTP was sent: %v", ct.form)
	}
	if err := c.SetPassword("jdoe", "new-password-1", "new-password-2", "123456"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ct.form["otp"], []string{"123456"}) {
		t.Errorf("otp = %v", ct.form["otp"])
	}
}

func resetWithHandler(t *testing.T, rec map[string]any) (string, error) {
	s, c := newFake(t)
	s.AddUser("jdoe", ipatest.User{})
	if rec != nil {
		s.Handle("user_mod", func(ipatest.Call) (any, *ipa.IpaError) {
			return map[string]any{"result": rec, "value": "jdoe", "summary": ""}, nil
		})
	}
	return c.ResetPassword("jdoe")
}

func TestResetPassword_ListForm(t *testing.T) {
	pw, err := resetWithHandler(t, map[string]any{"uid": []string{"jdoe"}, "randompassword": []string{"s3cret"}})
	if err != nil || pw != "s3cret" {
		t.Errorf("ResetPassword = %q, %v", pw, err)
	}
}

func TestResetPassword_StringForm(t *testing.T) {
	pw, err := resetWithHandler(t, nil)
	if err != nil || pw == "" {
		t.Errorf("ResetPassword = %q, %v", pw, err)
	}
}

func TestResetPassword_IgnoresValue(t *testing.T) {
	pw, err := resetWithHandler(t, map[string]any{"uid": []string{"jdoe"}})
	if err == nil {
		t.Errorf("ResetPassword = %q, want an error", pw)
	}
}
