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
	c.mu.Lock()
	old := c.krbClient
	c.krbClient = cl
	c.mu.Unlock()
	if old != nil {
		old.Destroy()
	}
}

// Clears out FreeIPA session id
func (c *Client) ClearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = ""
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

	return nil
}

// Login to FreeIPA using local kerberos login username and password
func (c *Client) Login(username, password string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	cl := client.NewWithPassword(username, c.realm, password, cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.setKrbClient(cl)

	return nil
}

// Login to FreeIPA using local kerberos login with keytab and username
func (c *Client) LoginWithKeytab(ktab, username string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	kt, err := keytab.Load(ktab)
	if err != nil {
		return err
	}

	cl := client.NewWithKeytab(username, c.realm, kt, cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.setKrbClient(cl)

	return nil
}

// Login to FreeIPA using credentials cache
func (c *Client) LoginFromCCache(cpath string) error {
	cfg, err := config.Load(DefaultKerbConf)
	if err != nil {
		return err
	}

	ccache, err := credentials.LoadCCache(cpath)
	if err != nil {
		return err
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.AssumePreAuthentication(true))
	if err != nil {
		return err
	}

	err = cl.Login()
	if err != nil {
		return err
	}

	c.setKrbClient(cl)

	return nil
}
