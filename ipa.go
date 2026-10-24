// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
)

const (
	DefaultKerbConf   = "/etc/krb5.conf"
	IpaClientVersion  = "2.237"
	IpaDatetimeFormat = "20060102150405Z"
)

// FreeIPA Client
//
// Methods with a Context suffix bound the HTTP request with the given
// context. Kerberos login and SPNEGO header generation are not cancellable
// (gokrb5 has no context support), so Login, LoginWithKeytab,
// LoginFromCCache and their Data variants have no Context twins.
//
// When FreeIPA answers 401 for an expired session, the Client drops that
// session and, if it can, sends the request again once: a Kerberos client
// gets a new session through SPNEGO, a RemoteLogin client logs in again only
// with WithPasswordRelogin. Other clients get an error matching
// ErrUnauthorized. The retry assumes FreeIPA's httpd answers 401 before
// running the command, which a proxy answering 401 after forwarding breaks.
type Client struct {
	host       string
	realm      string
	httpClient *http.Client

	// reloginMu serializes password re-login. Lock order: reloginMu, krbMu,
	// mu; only reloginMu is held across an HTTP request.
	reloginMu sync.Mutex

	// krbMu keeps Destroy of a replaced Kerberos client out of an in-flight
	// SPNEGO step.
	krbMu sync.RWMutex

	mu        sync.Mutex // guards the fields below; a Client is shared across goroutines
	sessionID string
	sticky    bool
	krbClient *client.Client

	krb5Path    string // krb5.conf path; empty means DefaultKerbConf
	krb5Data    string // krb5.conf text (a string keeps Client comparable); wins over krb5Path
	relogin     bool
	reloginUser string // guarded by mu
	reloginPass string // guarded by mu
}

// FreeIPA api options map
type Options map[string]interface{}

func newHTTPClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: pool},
			DisableCompression:    false,
		},
	}
}

// New default IPA Client using host and realm from /etc/ipa/default.conf, read on first use
func NewDefaultClient() *Client {
	d := systemDefaults()
	return &Client{host: d.host, realm: d.realm, sticky: true, httpClient: newHTTPClient(d.pool)}
}

// New default IPA Client with existing sessionID using host and realm from /etc/ipa/default.conf, read on first use
func NewDefaultClientWithSession(sessionID string) *Client {
	d := systemDefaults()
	return &Client{host: d.host, realm: d.realm, sticky: true, sessionID: sessionID, httpClient: newHTTPClient(d.pool)}
}

// New IPA Client with host and realm
func NewClient(host, realm string) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: newHTTPClient(systemDefaults().pool),
	}
}

// New IPA Client with host, realm and custom http client
func NewClientCustomHttp(host, realm string, httpClient *http.Client) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: httpClient,
	}
}

// Returns FreeIPA server hostname
func (c *Client) Host() string {
	return c.host
}

// Returns FreeIPA realm
func (c *Client) Realm() string {
	return c.realm
}
