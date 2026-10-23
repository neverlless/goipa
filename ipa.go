// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-ini/ini"
	"github.com/jcmturner/gokrb5/v8/client"
)

const (
	DefaultKerbConf   = "/etc/krb5.conf"
	IpaClientVersion  = "2.237"
	IpaDatetimeFormat = "20060102150405Z"
)

var (
	ipaDefaultHost  string
	ipaDefaultRealm string
	ipaCertPool     *x509.CertPool
)

// FreeIPA Client
//
// Methods with a Context suffix bound the HTTP request with the given
// context. Kerberos login and SPNEGO header generation are not cancellable
// (gokrb5 has no context support), so Login, LoginWithKeytab and
// LoginFromCCache have no Context twins.
type Client struct {
	host       string
	realm      string
	httpClient *http.Client

	// krbMu keeps Destroy of a replaced Kerberos client out of an in-flight
	// SPNEGO step. Lock order: krbMu, then mu.
	krbMu sync.RWMutex

	mu        sync.Mutex // guards the fields below; a Client is shared across goroutines
	sessionID string
	sticky    bool
	krbClient *client.Client
}

// FreeIPA api options map
type Options map[string]interface{}

func init() {
	// If ca.crt for ipa exists, use it as the cert pool
	// otherwise default to system root ca.
	pem, err := os.ReadFile("/etc/ipa/ca.crt")
	if err == nil {
		ipaCertPool = x509.NewCertPool()
		if !ipaCertPool.AppendCertsFromPEM(pem) {
			ipaCertPool = nil
		}
	}

	// Load default IPA host
	cfg, err := ini.Load("/etc/ipa/default.conf")
	if err == nil {
		ipaServerURL, err := url.Parse(cfg.Section("global").Key("xmlrpc_uri").MustString("http://localhost"))
		if err == nil {
			ipaDefaultHost = ipaServerURL.Host
		}
		ipaDefaultRealm = cfg.Section("global").Key("realm").MustString("LOCAL")
	}
}

func newHTTPClient() *http.Client {
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
			TLSClientConfig:       &tls.Config{RootCAs: ipaCertPool},
			DisableCompression:    false,
		},
	}
}

// New default IPA Client using host and realm from /etc/ipa/default.conf
func NewDefaultClient() *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		sticky:     true,
		httpClient: newHTTPClient(),
	}
}

// New default IPA Client with existing sessionID using host and realm from /etc/ipa/default.conf
func NewDefaultClientWithSession(sessionID string) *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		httpClient: newHTTPClient(),
		sticky:     true,
		sessionID:  sessionID,
	}
}

// New IPA Client with host and realm
func NewClient(host, realm string) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: newHTTPClient(),
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
