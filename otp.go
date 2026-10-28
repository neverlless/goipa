// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// OTP Token hash Algorithms supported by FreeIPA
const (
	AlgorithmSHA1   = "sha1"
	AlgorithmSHA256 = "sha256"
	AlgorithmSHA384 = "sha384"
	AlgorithmSHA512 = "sha512"
)

// OTP Token types supported by FreeIPA
const (
	TokenTypeTOTP = "totp"
	TokenTypeHOTP = "hotp"
)

// OTPToken encapsulates FreeIPA otptokens
type OTPToken struct {
	DN          string    `json:"dn"`
	UUID        string    `json:"ipatokenuniqueid"`
	Algorithm   string    `json:"ipatokenotpalgorithm"`
	Digits      int       `json:"ipatokenotpdigits"`
	Owner       string    `json:"ipatokenowner"`
	TimeStep    int       `json:"ipatokentotptimestep"`
	ClockOffest int       `json:"ipatokentotpclockoffset"`
	ManagedBy   string    `json:"managedby_user"`
	Enabled     bool      `json:"-"`
	Type        string    `json:"type"`
	URI         string    `json:"uri"`
	Description string    `json:"description"`
	Vendor      string    `json:"ipatokenvendor"`
	Model       string    `json:"ipatokenmodel"`
	Serial      string    `json:"ipatokenserial"`
	NotBefore   time.Time `json:"ipatokennotbefore"`
	NotAfter    time.Time `json:"ipatokennotafter"`
}

// DefaultTOTPToken holds the defaults AddOTPToken applies to zero fields.
//
// Deprecated: use AddOTPToken(nil), or leave fields zero; the defaults apply
// field by field. Changing this variable while AddOTPToken runs is a data race.
var DefaultTOTPToken *OTPToken = &OTPToken{
	Type:      TokenTypeTOTP,
	Algorithm: AlgorithmSHA1,
	Digits:    6,
	TimeStep:  30,
}

func (t *OTPToken) DisplayName() string {
	if len(t.UUID) == 36 {
		return t.Owner + "-" + t.UUID[len(t.UUID)-6:]
	}
	return t.UUID
}

func (t *OTPToken) fromJSON(raw []byte) error {
	if !gjson.ValidBytes(raw) {
		return errors.New("invalid otp token record json")
	}

	res := gjson.ParseBytes(raw)

	t.DN = res.Get("dn").String()
	t.UUID = res.Get("ipatokenuniqueid.0").String()
	t.Algorithm = res.Get("ipatokenotpalgorithm.0").String()
	t.Digits = int(res.Get("ipatokenotpdigits.0").Int())
	t.Owner = res.Get("ipatokenowner.0").String()
	t.TimeStep = int(res.Get("ipatokentotptimestep.0").Int())
	t.ClockOffest = int(res.Get("ipatokentotpclockoffset.0").Int())
	t.ManagedBy = res.Get("managedby_user.0").String()
	t.Enabled = !res.Get("ipatokendisabled.0").Bool()
	t.Type = res.Get("type").String()
	t.URI = res.Get("uri").String()
	t.Description = res.Get("description.0").String()
	t.Vendor = res.Get("ipatokenvendor.0").String()
	t.Model = res.Get("ipatokenmodel.0").String()
	t.Serial = res.Get("ipatokenserial.0").String()
	t.NotBefore = ParseDateTime(res.Get("ipatokennotbefore.0.__datetime__").String())
	t.NotAfter = ParseDateTime(res.Get("ipatokennotafter.0.__datetime__").String())

	return nil
}

// Remove OTP token
func (c *Client) RemoveOTPToken(tokenUUID string) error {
	return c.RemoveOTPTokenContext(context.Background(), tokenUUID)
}

// RemoveOTPTokenContext is like RemoveOTPToken but bounds the request with ctx.
func (c *Client) RemoveOTPTokenContext(ctx context.Context, tokenUUID string) error {
	_, err := c.rpc(ctx, "otptoken_del", []string{tokenUUID}, nil)

	if err != nil {
		return err
	}

	return nil
}

// Fetch OTP tokens by owner.
//
// A truncated search is not reported unless the Client was built
// WithTruncationErrors; FindEntries reports it too.
func (c *Client) FetchOTPTokens(owner string) ([]*OTPToken, error) {
	return c.FetchOTPTokensContext(context.Background(), owner)
}

// FetchOTPTokensContext is like FetchOTPTokens but bounds the request with ctx.
func (c *Client) FetchOTPTokensContext(ctx context.Context, owner string) ([]*OTPToken, error) {
	options := Options{
		"ipatokenowner": owner,
		"all":           true,
	}

	res, err := c.rpc(ctx, "otptoken_find", []string{""}, options)

	if err != nil {
		return nil, err
	}

	tokens := make([]*OTPToken, 0)

	data := gjson.ParseBytes(res.Result.Data)
	for _, t := range data.Array() {
		tok := new(OTPToken)
		err := tok.fromJSON([]byte(t.Raw))
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, tok)
	}

	return tokens, c.truncated(res)
}

// Add OTP token. Returns new OTPToken
func (c *Client) AddOTPToken(token *OTPToken) (*OTPToken, error) {
	return c.AddOTPTokenContext(context.Background(), token)
}

// AddOTPTokenContext is like AddOTPToken but bounds the request with ctx.
func (c *Client) AddOTPTokenContext(ctx context.Context, token *OTPToken) (*OTPToken, error) {
	t := *DefaultTOTPToken
	if token != nil {
		t = *token
	}
	if t.Type == "" {
		t.Type = DefaultTOTPToken.Type
	}
	if t.Algorithm == "" {
		t.Algorithm = DefaultTOTPToken.Algorithm
	}
	if t.Digits == 0 {
		t.Digits = DefaultTOTPToken.Digits
	}
	if t.TimeStep == 0 {
		t.TimeStep = DefaultTOTPToken.TimeStep
	}

	options := Options{
		"type":                 t.Type,
		"ipatokenotpalgorithm": t.Algorithm,
		"ipatokenotpdigits":    t.Digits,
		"ipatokentotptimestep": t.TimeStep,
		"no_qrcode":            true,
		"qrcode":               false,
		"no_members":           false,
		"all":                  true,
	}

	if t.Description != "" {
		options["description"] = t.Description
	}
	if t.Vendor != "" {
		options["ipatokenvendor"] = t.Vendor
	}
	if t.Model != "" {
		options["ipatokenmodel"] = t.Model
	}
	if t.Serial != "" {
		options["ipatokenserial"] = t.Serial
	}
	if !t.NotBefore.IsZero() {
		options["ipatokennotbefore"] = map[string]interface{}{
			"__datetime__": t.NotBefore.UTC().Format(IpaDatetimeFormat),
		}
	}
	if !t.NotAfter.IsZero() {
		options["ipatokennotafter"] = map[string]interface{}{
			"__datetime__": t.NotAfter.UTC().Format(IpaDatetimeFormat),
		}
	}

	res, err := c.rpc(ctx, "otptoken_add", []string{}, options)

	if err != nil {
		return nil, err
	}

	tokenRec := new(OTPToken)
	err = tokenRec.fromJSON(res.Result.Data)
	if err != nil {
		return nil, err
	}

	return tokenRec, nil
}

// Enable OTP token.
func (c *Client) EnableOTPToken(tokenUUID string) error {
	return c.EnableOTPTokenContext(context.Background(), tokenUUID)
}

// EnableOTPTokenContext is like EnableOTPToken but bounds the request with ctx.
func (c *Client) EnableOTPTokenContext(ctx context.Context, tokenUUID string) error {
	options := Options{
		"ipatokendisabled": false,
		"all":              false,
	}

	_, err := c.rpc(ctx, "otptoken_mod", []string{tokenUUID}, options)

	return err
}

// Disable OTP token.
func (c *Client) DisableOTPToken(tokenUUID string) error {
	return c.DisableOTPTokenContext(context.Background(), tokenUUID)
}

// DisableOTPTokenContext is like DisableOTPToken but bounds the request with ctx.
func (c *Client) DisableOTPTokenContext(ctx context.Context, tokenUUID string) error {
	options := Options{
		"ipatokendisabled": true,
		"all":              false,
	}

	_, err := c.rpc(ctx, "otptoken_mod", []string{tokenUUID}, options)

	return err
}

// SyncOTPToken resynchronises an OTP token whose clock or counter drifted, from
// two consecutive codes, through /ipa/session/sync_token. password is the
// user's password without an OTP. tokenID selects the token (unique ID or DN);
// "" lets the server try the user's tokens. No session or Kerberos ticket is
// needed. Based on ubccr/goipa#2 by @farzandalaee.
func (c *Client) SyncOTPToken(username, password, firstCode, secondCode, tokenID string) error {
	return c.SyncOTPTokenContext(context.Background(), username, password, firstCode, secondCode, tokenID)
}

// SyncOTPTokenContext is like SyncOTPToken but bounds the request with ctx.
func (c *Client) SyncOTPTokenContext(ctx context.Context, username, password, firstCode, secondCode, tokenID string) error {
	if username == "" || password == "" || firstCode == "" || secondCode == "" {
		return errors.New("ipa: username, password and both codes are required")
	}
	form := url.Values{
		"user":        {username},
		"password":    {password},
		"first_code":  {firstCode},
		"second_code": {secondCode},
	}
	if tokenID != "" {
		form.Set("token", tokenID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s/ipa/session/sync_token", c.host), strings.NewReader(form.Encode()))
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
		return newFormHTTPError("ipa: token sync failed", res)
	}

	switch status := res.Header.Get("X-IPA-TokenSync-Result"); strings.ToLower(status) {
	case "ok":
		return nil
	case "invalid-credentials":
		return ErrInvalidCredentials
	default:
		return fmt.Errorf("ipa: token sync failed: %s", status)
	}
}
