//go:build integration

// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 test vector algorithm
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/neverlless/goipa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddTOTPToken(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	password := gofakeit.Password(true, true, true, true, false, 16)

	_, err = addTestUser(c, username, password)
	require.NoErrorf(err, "Failed to add test user")

	userClient := ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	require.NoErrorf(err, "Failed to login as new user account")
	require.NotEmptyf(c.SessionID(), "Missing sessionID for new user account")

	err = userClient.RemoveOTPToken("token_does_not_exist")
	assert.Errorf(err, "Removing a non-existing OTP token should error")

	token := &ipa.OTPToken{
		Type:        ipa.TokenTypeTOTP,
		Algorithm:   ipa.AlgorithmSHA256,
		Description: "this is a test token",
		NotBefore:   time.Now(),
	}

	tokenRec, err := userClient.AddOTPToken(token)
	require.NoErrorf(err, "Failed to add OTP token")

	assert.NotEmptyf(tokenRec.URI, "Token URI should not be empty")
	assert.Equalf(tokenRec.Algorithm, token.Algorithm, "Invalid Algorithm")
	assert.Equalf(tokenRec.Digits, ipa.DefaultTOTPToken.Digits, "Invalid Digits")
	assert.Truef(tokenRec.Enabled, "Token should be enabled")
	assert.Equalf(tokenRec.Description, token.Description, "Invalid description")
	assert.Equalf(tokenRec.NotBefore.Format(ipa.IpaDatetimeFormat), token.NotBefore.Format(ipa.IpaDatetimeFormat), "Invalid validity start date")

	tokens, err := userClient.FetchOTPTokens(username)
	require.NoErrorf(err, "Failed to fetch OTP tokens for user")
	assert.Lenf(tokens, 1, "Wrong number of tokens found")

	tok := tokens[0]
	assert.Equalf(tok.UUID, tokenRec.UUID, "UUIDs should be the same")
	assert.Equalf(tok.Algorithm, tokenRec.Algorithm, "Algorithm should be the same")
	assert.Equalf(tok.Digits, tokenRec.Digits, "Digits should be the same")
	assert.Equalf(tok.Enabled, tokenRec.Enabled, "Tokens should be enabled")
	assert.Equalf(tok.Description, tokenRec.Description, "Descriptions should be the same")
	assert.Equalf(tokenRec.NotBefore.Format(ipa.IpaDatetimeFormat), tokenRec.NotBefore.Format(ipa.IpaDatetimeFormat), "Validity start date should be the same")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

// totp is RFC 6238 with HMAC-SHA1, 6 digits and a 30 s step for step number n.
func totp(secret string, n uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], n)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}

func TestIntegrationSyncOTPToken(t *testing.T) {
	require := require.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	password := gofakeit.Password(true, true, true, true, false, 16)
	_, err = addTestUser(c, username, password)
	require.NoError(err)

	userClient := ipa.NewDefaultClient()
	require.NoError(userClient.RemoteLogin(username, password))

	token, err := userClient.AddOTPToken(&ipa.OTPToken{Type: ipa.TokenTypeTOTP, Algorithm: ipa.AlgorithmSHA1})
	require.NoError(err)

	uri, err := url.Parse(token.URI)
	require.NoError(err)
	secret := uri.Query().Get("secret")
	require.NotEmpty(secret)

	// Simulate a drifted device: codes for the steps 10 and 11 ahead.
	step := uint64(time.Now().Unix() / 30)
	c1, err := totp(secret, step+10)
	require.NoError(err)
	c2, err := totp(secret, step+11)
	require.NoError(err)

	anon := ipa.NewDefaultClient()
	require.NoError(anon.SyncOTPToken(username, password, c1, c2, token.UUID))

	err = anon.SyncOTPToken(username, password+"x", c1, c2, token.UUID)
	require.True(errors.Is(err, ipa.ErrInvalidCredentials), "err = %v", err)
}
