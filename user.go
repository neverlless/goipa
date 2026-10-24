// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh"
)

// User encapsulates user data returned from ipa user commands
type User struct {
	UUID             string              `json:"ipauniqueid"`
	DN               string              `json:"dn"`
	First            string              `json:"givenname"`
	Last             string              `json:"sn"`
	DisplayName      string              `json:"displayname"`
	Principal        string              `json:"krbprincipalname"`
	Username         string              `json:"uid"`
	Uid              string              `json:"uidnumber"`
	Gid              string              `json:"gidnumber"`
	Groups           []string            `json:"memberof_group"`
	SSHAuthKeys      []*SSHAuthorizedKey `json:"ipasshpubkey"`
	AuthTypes        []string            `json:"ipauserauthtype"`
	HasKeytab        bool                `json:"has_keytab"`
	HasPassword      bool                `json:"has_password"`
	Locked           bool                `json:"nsaccountlock"`
	Preserved        bool                `json:"preserved"`
	HomeDir          string              `json:"homedirectory"`
	Email            string              `json:"mail"`
	TelephoneNumber  string              `json:"telephonenumber"`
	Mobile           string              `json:"mobile"`
	Shell            string              `json:"loginshell"`
	Category         string              `json:"userclass"`
	SudoRules        []string            `json:"memberofindirect_sudorule"`
	HbacRules        []string            `json:"memberofindirect_hbacrule"`
	LastPasswdChange time.Time           `json:"krblastpwdchange"`
	PasswdExpire     time.Time           `json:"krbpasswordexpiration"`
	PrincipalExpire  time.Time           `json:"krbprincipalexpiration"`
	LastLoginSuccess time.Time           `json:"krblastsuccessfulauth"`
	LastLoginFail    time.Time           `json:"krblastfailedauth"`
	RandomPassword   string              `json:"randompassword"`

	// Emails holds every mail value; Email is the first. UserMod and UserAdd
	// send Email first, then Emails[1:] (see ToOptions), so Emails[0] is
	// ignored on write. To set the whole list, set Email = list[0] and
	// Emails = list.
	Emails []string `json:"emails"`
	// IndirectGroups: nested groups; filled by UserShow only, UserFind puts
	// nested groups in Groups (FreeIPA).
	IndirectGroups []string `json:"memberofindirect_group"`
	// Street, City, State, PostalCode and PreferredLanguage are returned only
	// with all, which UserShow and UserFind send.
	Street            string `json:"street"`
	City              string `json:"l"`
	State             string `json:"st"`
	PostalCode        string `json:"postalcode"`
	PreferredLanguage string `json:"preferredlanguage"`
	Title             string `json:"title"`
	OrgUnit           string `json:"ou"`
	// Passkeys: FreeIPA 4.11+, format passkey:<id>,<key>[,<userid>].
	Passkeys []string `json:"ipapasskey"`
}

// SSH Public Key
type SSHAuthorizedKey struct {
	Comment     string
	Options     []string
	PublicKey   ssh.PublicKey
	Fingerprint string
}

func NewSSHAuthorizedKey(in string) (*SSHAuthorizedKey, error) {
	k := new(SSHAuthorizedKey)
	var err error
	k.PublicKey, k.Comment, k.Options, _, err = ssh.ParseAuthorizedKey([]byte(in))
	if err != nil {
		return nil, err
	}

	k.Fingerprint = ssh.FingerprintSHA256(k.PublicKey)

	return k, nil
}

func (k *SSHAuthorizedKey) String() string {
	out := []string{}
	if len(k.Options) > 0 {
		out = append(out, strings.Join(k.Options, ","))
	}

	out = append(out, string(bytes.TrimSuffix(ssh.MarshalAuthorizedKey(k.PublicKey), []byte{'\n'})))
	if k.Comment != "" {
		out = append(out, k.Comment)
	}

	return strings.Join(out, " ")
}

func (k *SSHAuthorizedKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (u *User) ToOptions() Options {
	options := Options{
		"mail":            u.mailOption(),
		"givenname":       u.First,
		"sn":              u.Last,
		"homedirectory":   u.HomeDir,
		"loginshell":      u.Shell,
		"displayname":     u.DisplayName,
		"ipasshpubkey":    u.FormatSSHAuthorizedKeys(),
		"telephonenumber": u.TelephoneNumber,
		"mobile":          u.Mobile,
		"userclass":       u.Category,
	}

	return options
}

// mailOption is Email followed by Emails[1:] without repeats of Email, as a
// string when it is one value (the v0.0.7 wire form) and "" when none.
func (u *User) mailOption() any {
	var mail []string
	if u.Email != "" {
		mail = append(mail, u.Email)
	}
	for _, e := range u.Emails[min(1, len(u.Emails)):] {
		if e != "" && !slices.ContainsFunc(mail, func(m string) bool { return strings.EqualFold(m, e) }) {
			mail = append(mail, e)
		}
	}
	switch len(mail) {
	case 0:
		return ""
	case 1:
		return mail[0]
	}
	return mail
}

func (u *User) fromJSON(raw []byte) error {
	if !gjson.ValidBytes(raw) {
		return errors.New("invalid user record json")
	}

	res := gjson.ParseBytes(raw)

	u.UUID = res.Get("ipauniqueid.0").String()
	u.DN = res.Get("dn").String()
	u.First = res.Get("givenname.0").String()
	u.Last = res.Get("sn.0").String()
	u.DisplayName = res.Get("displayname.0").String()
	u.Principal = res.Get("krbprincipalname.0").String()
	u.Username = res.Get("uid.0").String()
	u.Uid = res.Get("uidnumber.0").String()
	u.Gid = res.Get("gidnumber.0").String()
	u.HasKeytab = res.Get("has_keytab").Bool()
	u.HasPassword = res.Get("has_password").Bool()
	u.Locked = res.Get("nsaccountlock").Bool()
	u.Preserved = res.Get("preserved").Bool()
	u.HomeDir = res.Get("homedirectory.0").String()
	u.Email = res.Get("mail.0").String()
	u.Street = res.Get("street.0").String()
	u.City = res.Get("l.0").String()
	u.State = res.Get("st.0").String()
	u.PostalCode = res.Get("postalcode.0").String()
	u.PreferredLanguage = res.Get("preferredlanguage.0").String()
	u.Title = res.Get("title.0").String()
	u.OrgUnit = res.Get("ou.0").String()
	u.Mobile = res.Get("mobile.0").String()
	u.TelephoneNumber = res.Get("telephonenumber.0").String()
	u.Shell = res.Get("loginshell.0").String()
	u.Category = res.Get("userclass.0").String()
	r := res.Get("randompassword")
	if r.IsArray() {
		r = r.Get("0")
	}
	u.RandomPassword = r.String()
	u.LastPasswdChange = ParseDateTime(res.Get("krblastpwdchange.0.__datetime__").String())
	u.PasswdExpire = ParseDateTime(res.Get("krbpasswordexpiration.0.__datetime__").String())
	u.PrincipalExpire = ParseDateTime(res.Get("krbprincipalexpiration.0.__datetime__").String())
	u.LastLoginSuccess = ParseDateTime(res.Get("krblastsuccessfulauth.0.__datetime__").String())
	u.LastLoginFail = ParseDateTime(res.Get("krblastfailedauth.0.__datetime__").String())
	res.Get("memberof_group").ForEach(func(key, value gjson.Result) bool {
		u.Groups = append(u.Groups, value.String())
		return true
	})
	u.Emails, u.IndirectGroups, u.Passkeys = strList(res, "mail"), strList(res, "memberofindirect_group"), strList(res, "ipapasskey")
	res.Get("ipasshpubkey").ForEach(func(key, value gjson.Result) bool {
		k, err := NewSSHAuthorizedKey(value.String())
		if err == nil {
			u.SSHAuthKeys = append(u.SSHAuthKeys, k)
		}
		return true
	})
	res.Get("ipauserauthtype").ForEach(func(key, value gjson.Result) bool {
		u.AuthTypes = append(u.AuthTypes, value.String())
		return true
	})
	res.Get("memberof_hbacrule").ForEach(func(key, value gjson.Result) bool {
		u.HbacRules = append(u.HbacRules, value.String())
		return true
	})
	res.Get("memberofindirect_hbacrule").ForEach(func(key, value gjson.Result) bool {
		u.HbacRules = append(u.HbacRules, value.String())
		return true
	})
	res.Get("memberofindirect_sudorule").ForEach(func(key, value gjson.Result) bool {
		u.SudoRules = append(u.SudoRules, value.String())
		return true
	})

	return nil
}

// Returns true if OTP is the only authentication type enabled
func (u *User) OTPOnly() bool {
	if len(u.AuthTypes) == 1 && u.AuthTypes[0] == "otp" {
		return true
	}

	return false
}

// Returns true if the User is in group
func (u *User) HasGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}

	return false
}

// Removes ssh authorized key
func (u *User) RemoveSSHAuthorizedKey(fingerprint string) {
	index := -1
	for i, k := range u.SSHAuthKeys {
		if k.Fingerprint == fingerprint {
			index = i
			break
		}
	}

	if index != -1 {
		u.SSHAuthKeys = append(u.SSHAuthKeys[:index], u.SSHAuthKeys[index+1:]...)
	}
}

// Add ssh authorized key
func (u *User) AddSSHAuthorizedKey(key *SSHAuthorizedKey) {
	index := -1
	for i, k := range u.SSHAuthKeys {
		if key.Fingerprint == k.Fingerprint {
			index = i
		}
	}

	if index == -1 {
		u.SSHAuthKeys = append(u.SSHAuthKeys, key)
	} else {
		u.SSHAuthKeys[index] = key
	}
}

// Format ssh authorized keys
func (u *User) FormatSSHAuthorizedKeys() []string {
	keys := []string{}
	for _, k := range u.SSHAuthKeys {
		keys = append(keys, k.String())
	}

	return keys
}

// Fetch user details by call the FreeIPA user-show method
func (c *Client) UserShow(username string) (*User, error) {
	return c.UserShowContext(context.Background(), username)
}

// UserShowContext is like UserShow but bounds the request with ctx.
func (c *Client) UserShowContext(ctx context.Context, username string) (*User, error) {

	options := Options{
		"no_members": false,
		"all":        true,
	}

	res, err := c.rpc(ctx, "user_show", []string{username}, options)

	if err != nil {
		return nil, err
	}

	userRec := new(User)
	err = userRec.fromJSON(res.Result.Data)
	if err != nil {
		return nil, err
	}

	return userRec, nil
}

// Find users.
//
// A truncated search is not reported (kept for compatibility); use FindEntries
// with the same method to detect it.
func (c *Client) UserFind(options Options) ([]*User, error) {
	return c.UserFindContext(context.Background(), options)
}

// UserFindContext is like UserFind but bounds the request with ctx.
func (c *Client) UserFindContext(ctx context.Context, options Options) ([]*User, error) {
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}

	options["no_members"] = false
	options["all"] = true

	res, err := c.rpc(ctx, "user_find", []string{""}, options)

	if err != nil {
		return nil, err
	}

	users := make([]*User, 0)
	data := gjson.ParseBytes(res.Result.Data)
	for _, t := range data.Array() {
		user := new(User)
		err := user.fromJSON([]byte(t.Raw))
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

// Reset user password and return new random password
func (c *Client) ResetPassword(username string) (string, error) {
	return c.ResetPasswordContext(context.Background(), username)
}

// ResetPasswordContext is like ResetPassword but bounds the request with ctx.
func (c *Client) ResetPasswordContext(ctx context.Context, username string) (string, error) {

	options := Options{
		"no_members": false,
		"random":     true,
		"all":        true}

	res, err := c.rpc(ctx, "user_mod", []string{username}, options)

	if err != nil {
		return "", err
	}

	userRec := new(User)
	err = userRec.fromJSON(res.Result.Data)
	if err != nil {
		return "", err
	}

	if len(userRec.RandomPassword) == 0 {
		return "", errors.New("ipa: failed to reset user password. empty random password returned")
	}

	return userRec.RandomPassword, nil
}

// Change user password. This will run the passwd ipa command. Optionally
// provide an OTP if required
//
// Unlike SetPassword, it needs a session (or Kerberos) to run passwd.
func (c *Client) ChangePassword(username, oldPasswd, newPasswd, otpcode string) error {
	return c.ChangePasswordContext(context.Background(), username, oldPasswd, newPasswd, otpcode)
}

// ChangePasswordContext is like ChangePassword but bounds the request with ctx.
func (c *Client) ChangePasswordContext(ctx context.Context, username, oldPasswd, newPasswd, otpcode string) error {

	options := Options{
		"current_password": oldPasswd,
		"password":         newPasswd,
	}

	if len(otpcode) > 0 {
		options["otp"] = otpcode
	}

	_, err := c.rpc(ctx, "passwd", []string{username}, options)

	if err != nil {
		return err
	}

	return nil
}

// Set user password. In FreeIPA when a password is first set or when a
// password is later reset it is marked as immediately expired and requires the
// owner to perform a password change. See here
// https://www.freeipa.org/page/New_Passwords_Expired for more details. This
// function exists to circumvent the "new passwords expired" feature of FreeIPA
// and allow an administrator to set a new password for a user without it being
// expired. This is acheived, for example, by first calling ResetPassword()
// then immediately calling this function. *WARNING* See
// https://www.freeipa.org/page/Self-Service_Password_Reset for security issues
// and possible weaknesses of this approach.
//
// Unlike ChangePassword, it uses the form endpoint and needs no session.
func (c *Client) SetPassword(username, oldPasswd, newPasswd, otpcode string) error {
	return c.SetPasswordContext(context.Background(), username, oldPasswd, newPasswd, otpcode)
}

// SetPasswordContext is like SetPassword but bounds the request with ctx.
func (c *Client) SetPasswordContext(ctx context.Context, username, oldPasswd, newPasswd, otpcode string) error {
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/change_password", c.host)

	form := url.Values{
		"user":         {username},
		"old_password": {oldPasswd},
		"new_password": {newPasswd},
	}
	if otpcode != "" {
		form.Set("otp", otpcode)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", ipaUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return newFormHTTPError("ipa: change password failed", res)
	}

	status := res.Header.Get("x-ipa-pwchange-result")
	if status == "policy-error" {
		return ErrPasswordPolicy
	} else if status == "invalid-password" {
		return ErrInvalidPassword
	} else if strings.ToLower(status) != "ok" {
		return fmt.Errorf("ipa: change password failed. Unknown status: %s", status)
	}

	return nil
}

// Update user authentication types.
func (c *Client) SetAuthTypes(username string, types []string) error {
	return c.SetAuthTypesContext(context.Background(), username, types)
}

// SetAuthTypesContext is like SetAuthTypes but bounds the request with ctx.
func (c *Client) SetAuthTypesContext(ctx context.Context, username string, types []string) error {
	options := Options{
		"no_members":      false,
		"ipauserauthtype": types,
		"all":             false,
	}

	if len(types) == 0 {
		options["ipauserauthtype"] = ""
	}

	_, err := c.rpc(ctx, "user_mod", []string{username}, options)

	if err != nil {
		return err
	}

	return nil
}

// Disable User Account
func (c *Client) UserDisable(username string) error {
	return c.UserDisableContext(context.Background(), username)
}

// UserDisableContext is like UserDisable but bounds the request with ctx.
func (c *Client) UserDisableContext(ctx context.Context, username string) error {
	_, err := c.rpc(ctx, "user_disable", []string{username}, nil)

	if err != nil {
		return err
	}

	return nil
}

// Enable User Account
func (c *Client) UserEnable(username string) error {
	return c.UserEnableContext(context.Background(), username)
}

// UserEnableContext is like UserEnable but bounds the request with ctx.
func (c *Client) UserEnableContext(ctx context.Context, username string) error {
	_, err := c.rpc(ctx, "user_enable", []string{username}, nil)

	if err != nil {
		return err
	}

	return nil
}

// Add new user and set password. Note this requires "User Administrators"
// Privilege in FreeIPA.
func (c *Client) UserAddWithPassword(user *User, password string) (*User, error) {
	return c.UserAddWithPasswordContext(context.Background(), user, password)
}

// UserAddWithPasswordContext is like UserAddWithPassword but bounds the request with ctx.
func (c *Client) UserAddWithPasswordContext(ctx context.Context, user *User, password string) (*User, error) {
	if user.Username == "" {
		return nil, errors.New("username is required")
	}
	if password == "" {
		return nil, errors.New("password is required")
	}

	rec, err := c.UserAddContext(ctx, user, true)
	if err != nil {
		return nil, err
	}

	err = c.SetPasswordContext(ctx, rec.Username, rec.RandomPassword, password, "")
	if err != nil {
		return nil, err
	}

	return rec, nil
}

// nonEmpty drops empty values. FreeIPA reads "" as "no value", which on an
// add drops its defaults: an empty homedirectory fails with 4205
// ObjectclassViolation.
func nonEmpty(o Options) Options {
	for k, v := range o {
		if s, ok := v.([]string); v == "" || ok && len(s) == 0 {
			delete(o, k)
		}
	}
	return o
}

// Add new user. If random is true a random password will be created for the
// user. Note this requires "User Administrators" Privilege in FreeIPA.
func (c *Client) UserAdd(user *User, random bool) (*User, error) {
	return c.UserAddContext(context.Background(), user, random)
}

// UserAddContext is like UserAdd but bounds the request with ctx.
func (c *Client) UserAddContext(ctx context.Context, user *User, random bool) (*User, error) {
	if user.Username == "" {
		return nil, errors.New("username is required")
	}

	options := nonEmpty(user.ToOptions())

	if random {
		options["random"] = true
	}

	res, err := c.rpc(ctx, "user_add", []string{user.Username}, options)
	if err != nil {
		if errors.Is(err, ErrDuplicateEntry) {
			return nil, ErrUserExists
		}
		return nil, err
	}

	userRec := new(User)
	err = userRec.fromJSON(res.Result.Data)
	if err != nil {
		return nil, err
	}

	return userRec, nil
}

// Delete user. If preserve is false the user will be permanetly deleted, if
// true the users is moved to the Delete container. If stopOnError is false the
// operation will be in continuous mode otherwise it will stop on errors
//
// stopOnError=false is FreeIPA's continue=true; other Delete calls always
// stop on the first error.
func (c *Client) UserDelete(preserve, stopOnError bool, usernames ...string) error {
	return c.UserDeleteContext(context.Background(), preserve, stopOnError, usernames...)
}

// UserDeleteContext is like UserDelete but bounds the request with ctx.
func (c *Client) UserDeleteContext(ctx context.Context, preserve, stopOnError bool, usernames ...string) error {
	var options = Options{
		"continue": !stopOnError,
		"preserve": preserve,
	}

	_, err := c.rpc(ctx, "user_del", usernames, options)
	if err != nil {
		return err
	}

	return nil
}

// Modify user. It is read-modify-write: send a User from UserShow with the
// changes, as every attribute ToOptions sends is set, an empty HomeDir
// included (FreeIPA rejects that with 4205). Currently only modifies a
// subset of user attributes: mail (all values, see Emails), givenname, sn,
// homedirectory, loginshell, displayname, ipasshpubkey, telephonenumber, and
// mobile
func (c *Client) UserMod(user *User) (*User, error) {
	return c.UserModContext(context.Background(), user)
}

// UserModContext is like UserMod but bounds the request with ctx.
func (c *Client) UserModContext(ctx context.Context, user *User) (*User, error) {
	if user.Username == "" {
		return nil, errors.New("username is required")
	}

	options := user.ToOptions()

	res, err := c.rpc(ctx, "user_mod", []string{user.Username}, options)
	if err != nil {
		if errors.Is(err, ErrEmptyModlist) {
			return user, nil
		}
		return nil, err
	}

	userRec := new(User)
	err = userRec.fromJSON(res.Result.Data)
	if err != nil {
		return nil, err
	}

	return userRec, nil
}
