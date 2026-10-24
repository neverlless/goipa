// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors.
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

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// Return current FreeIPA sessionID
func (c *Client) SessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// SetSessionID restores a session saved from SessionID (for example in a web
// session store) on any client. An empty string clears it.
func (c *Client) SetSessionID(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = sessionID
}

// setKrbClient destroys the replaced client: gokrb5 runs a renewal goroutine
// per login and keeps the key material.
func (c *Client) setKrbClient(cl *client.Client) {
	c.krbMu.Lock()
	defer c.krbMu.Unlock()
	c.mu.Lock()
	old := c.krbClient
	c.krbClient = cl
	c.mu.Unlock()
	if old != nil {
		old.Destroy()
	}
}

// Clears out FreeIPA session id and the credentials kept by
// WithPasswordRelogin, so the Client does not log back in on its own.
func (c *Client) ClearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = ""
	c.reloginUser, c.reloginPass = "", ""
}

// Set stick sessions.
func (c *Client) StickySession(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sticky = enable
}

// Set FreeIPA sessionID from http response cookie
func (c *Client) setSessionID(res *http.Response) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.sticky {
		return nil
	}

	// Other cookies (e.g. a load balancer's) may come first and are not ours to reject.
	for _, cookie := range res.Cookies() {
		if cookie.Name != "ipa_session" {
			continue
		}
		if len(cookie.Value) != 32 && !strings.HasPrefix(cookie.Value, "MagBearerToken") {
			return errors.New("invalid set-cookie header")
		}
		if cookie.Value == "MagBearerToken=" { // FreeIPA's logout cookie
			c.sessionID = ""
			continue
		}
		c.sessionID = cookie.Value
	}

	return nil
}

// Login to FreeIPA using web API with uid/passwd and set the FreeIPA session
// id on the client for subsequent requests.
func (c *Client) RemoteLogin(uid, passwd string) error {
	return c.RemoteLoginContext(context.Background(), uid, passwd)
}

// RemoteLoginContext is like RemoteLogin but bounds the request with ctx.
func (c *Client) RemoteLoginContext(ctx context.Context, uid, passwd string) error {
	ipaURL := fmt.Sprintf("https://%s/ipa/session/login_password", c.host)

	form := url.Values{"user": {uid}, "password": {passwd}}
	req, err := http.NewRequestWithContext(ctx, "POST", ipaURL, strings.NewReader(form.Encode()))
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

	if res.StatusCode == 401 && res.Header.Get("X-IPA-Rejection-Reason") == "password-expired" {
		return ErrExpiredPassword
	}

	if res.StatusCode == 401 && res.Header.Get("X-IPA-Rejection-Reason") == "invalid-password" {
		return ErrInvalidPassword
	}

	if res.StatusCode == 401 {
		return ErrUnauthorized
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("IPA login failed with HTTP status code: %d", res.StatusCode)
	}

	if err = c.setSessionID(res); err != nil {
		return err
	}

	if c.relogin {
		c.mu.Lock()
		c.reloginUser, c.reloginPass = uid, passwd
		c.mu.Unlock()
	}

	return nil
}

// krb5Config returns the client's Kerberos configuration: WithKrb5ConfigData,
// else WithKrb5Config, else DefaultKerbConf.
func (c *Client) krb5Config() (*config.Config, error) {
	switch {
	case c.krb5Data != "":
		return loadKrb5ConfigData([]byte(c.krb5Data))
	case c.krb5Path != "":
		return loadKrb5Config(c.krb5Path)
	}
	return loadKrb5Config(DefaultKerbConf)
}

var errNoRealm = errors.New("ipa: realm is required for Kerberos login")

func (c *Client) krbLogin(cl *client.Client) error {
	if err := cl.Login(); err != nil {
		return err
	}
	c.setKrbClient(cl)
	return nil
}

// dropRelogin forgets the stored credentials if they are still uid/passwd.
func (c *Client) dropRelogin(uid, passwd string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reloginUser == uid && c.reloginPass == passwd {
		c.reloginUser, c.reloginPass = "", ""
	}
}

// Login to FreeIPA using local kerberos login username and password
func (c *Client) Login(username, password string) error {
	if c.realm == "" {
		return errNoRealm
	}
	cfg, err := c.krb5Config()
	if err != nil {
		return err
	}
	return c.krbLogin(client.NewWithPassword(username, c.realm, password, cfg))
}

// Login to FreeIPA using local kerberos login with keytab and username
func (c *Client) LoginWithKeytab(ktab, username string) error {
	kt, err := keytab.Load(ktab)
	if err != nil {
		return err
	}
	return c.loginKeytab(kt, username)
}

// LoginWithKeytabData is like LoginWithKeytab but takes the keytab contents,
// for containers and secret stores that have no file to point at.
func (c *Client) LoginWithKeytabData(ktab []byte, username string) error {
	kt := keytab.New()
	if err := kt.Unmarshal(ktab); err != nil {
		return fmt.Errorf("ipa: invalid keytab: %w", err)
	}
	return c.loginKeytab(kt, username)
}

func (c *Client) loginKeytab(kt *keytab.Keytab, username string) error {
	if c.realm == "" {
		return errNoRealm
	}
	cfg, err := c.krb5Config()
	if err != nil {
		return err
	}
	return c.krbLogin(client.NewWithKeytab(username, c.realm, kt, cfg))
}

// Login to FreeIPA using credentials cache
func (c *Client) LoginFromCCache(cpath string) error {
	ccache, err := credentials.LoadCCache(cpath)
	if err != nil {
		return err
	}
	return c.loginCCache(ccache)
}

// LoginFromCCacheData is like LoginFromCCache but takes the credentials cache
// contents.
func (c *Client) LoginFromCCacheData(ccache []byte) error {
	cc := new(credentials.CCache)
	if err := cc.Unmarshal(ccache); err != nil {
		return fmt.Errorf("ipa: invalid ccache: %w", err)
	}
	return c.loginCCache(cc)
}

func (c *Client) loginCCache(ccache *credentials.CCache) error {
	cfg, err := c.krb5Config()
	if err != nil {
		return err
	}
	cl, err := client.NewFromCCache(ccache, cfg, client.AssumePreAuthentication(true))
	if err != nil {
		return err
	}
	return c.krbLogin(cl)
}
