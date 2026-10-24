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
	DefaultKerbConf = "/etc/krb5.conf"
	// IpaClientVersion is the API version goipa sends by default; fixed for v1
	// so behaviour does not change with an upgrade. Override it per call with
	// the version option.
	IpaClientVersion  = "2.237"
	IpaDatetimeFormat = "20060102150405Z"
)

// FreeIPA Client
//
// Methods with a Context suffix bound the HTTP request with the given
// context. The generic and builder APIs (Call, FindEntries, Batch,
// Modification.Run) exist only in that form, by design. Kerberos login and
// SPNEGO header generation are not cancellable (gokrb5 has no context
// support), so Login, LoginWithKeytab, LoginFromCCache and their Data variants
// have no Context twins.
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

	// krbMu keeps Destroy of a replaced Kerberos client out of an in-flight
	// SPNEGO step. Lock order: krbMu, mu; neither is held across an HTTP
	// request.
	krbMu sync.RWMutex

	mu        sync.Mutex // guards the fields below; a Client is shared across goroutines
	sessionID string
	// reloginDone is non-nil while a password re-login runs and is closed when
	// it ends; a channel, not a mutex, so waiters can give up with their ctx.
	reloginDone chan struct{}
	sticky      bool
	krbClient   *client.Client

	serverVersion string // envelope version of the last successful response

	krb5Path    string // krb5.conf path; empty means DefaultKerbConf
	krb5Data    string // krb5.conf text (a string keeps Client comparable); wins over krb5Path
	relogin     bool
	validate    bool   // WithValidation
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
//
// Deprecated: use New, which reads the same files and returns an error when
// there is no host.
func NewDefaultClient() *Client {
	d := systemDefaults()
	return &Client{host: d.host, realm: d.realm, sticky: true, httpClient: newHTTPClient(d.pool)}
}

// New default IPA Client with existing sessionID using host and realm from /etc/ipa/default.conf, read on first use
//
// Deprecated: use New, then SetSessionID.
func NewDefaultClientWithSession(sessionID string) *Client {
	d := systemDefaults()
	return &Client{host: d.host, realm: d.realm, sticky: true, sessionID: sessionID, httpClient: newHTTPClient(d.pool)}
}

// New IPA Client with host and realm
//
// Deprecated: use New(WithHost(host), WithRealm(realm)).
func NewClient(host, realm string) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: newHTTPClient(systemDefaults().pool),
	}
}

// New IPA Client with host, realm and custom http client
//
// Deprecated: use New(WithHost(host), WithRealm(realm), WithHTTPClient(httpClient)).
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
