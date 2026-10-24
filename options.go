// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/go-ini/ini"
)

type settings struct {
	host, realm string
	caPEM       []byte
	httpClient  *http.Client
	krb5Path    string
	krb5Data    []byte
	relogin     bool
}

// Option configures a Client built by New.
type Option func(*settings) error

func needsValue(name string) error { return errors.New("ipa: " + name + " needs a value") }

// WithHost sets the FreeIPA server, "ipa.example.com" or "ipa.example.com:8443".
func WithHost(host string) Option {
	return func(s *settings) error {
		if host == "" {
			return needsValue("WithHost")
		}
		s.host = host
		return nil
	}
}

// WithRealm sets the Kerberos realm.
func WithRealm(realm string) Option {
	return func(s *settings) error {
		if realm == "" {
			return needsValue("WithRealm")
		}
		s.realm = realm
		return nil
	}
}

// WithCACert trusts the PEM-encoded CA certificate(s) instead of
// /etc/ipa/ca.crt. It cannot be combined with WithHTTPClient.
func WithCACert(pem []byte) Option {
	return func(s *settings) error {
		s.caPEM = pem
		return nil
	}
}

// WithHTTPClient makes the Client use hc. The caller owns its timeouts, proxy
// and transport; it cannot be combined with WithCACert.
func WithHTTPClient(hc *http.Client) Option {
	return func(s *settings) error {
		if hc == nil {
			return needsValue("WithHTTPClient")
		}
		s.httpClient = hc
		return nil
	}
}

// WithKrb5Config reads the Kerberos configuration from path instead of
// DefaultKerbConf.
func WithKrb5Config(path string) Option {
	return func(s *settings) error {
		if path == "" {
			return needsValue("WithKrb5Config")
		}
		s.krb5Path = path
		return nil
	}
}

// WithKrb5ConfigData uses krb5.conf text instead of DefaultKerbConf.
// include and includedir directives in it are resolved from the filesystem.
func WithKrb5ConfigData(data []byte) Option {
	return func(s *settings) error {
		if len(data) == 0 {
			return needsValue("WithKrb5ConfigData")
		}
		s.krb5Data = data
		return nil
	}
}

// WithPasswordRelogin makes RemoteLogin keep the user name and password in
// process memory so an expired session can be renewed. Without it the
// password is never stored.
func WithPasswordRelogin() Option {
	return func(s *settings) error {
		s.relogin = true
		return nil
	}
}

// New builds a Client from options. Without WithHost and WithRealm it takes
// them from /etc/ipa/default.conf; without WithCACert or WithHTTPClient it
// trusts /etc/ipa/ca.crt (else the system roots); without a Kerberos option it
// reads DefaultKerbConf. /etc/ipa is read only when an option is missing.
//
// It fails when no host is known, when WithCACert holds no certificate, when
// WithCACert and WithHTTPClient are both given, or when an option gets an
// empty value. The realm may stay empty; only Kerberos login needs it.
func New(opts ...Option) (*Client, error) {
	var s settings
	for _, o := range opts {
		if err := o(&s); err != nil {
			return nil, err
		}
	}
	if s.caPEM != nil && s.httpClient != nil {
		return nil, errors.New("ipa: WithCACert and WithHTTPClient are mutually exclusive")
	}
	var pool *x509.CertPool
	if s.caPEM != nil {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(s.caPEM) {
			return nil, errors.New("ipa: no certificate in CA PEM")
		}
	}
	if s.host == "" || s.realm == "" || (pool == nil && s.httpClient == nil) {
		d := systemDefaults()
		if s.host == "" {
			s.host = d.host
		}
		if s.realm == "" {
			s.realm = d.realm
		}
		if pool == nil {
			pool = d.pool
		}
	}
	if s.host == "" {
		return nil, errors.New("ipa: no FreeIPA host: use WithHost or /etc/ipa/default.conf")
	}
	if s.httpClient == nil {
		s.httpClient = newHTTPClient(pool)
	}
	return &Client{
		host: s.host, realm: s.realm, httpClient: s.httpClient, sticky: true,
		krb5Path: s.krb5Path, krb5Data: string(s.krb5Data), relogin: s.relogin,
	}, nil
}

type ipaDefaults struct {
	host, realm string
	pool        *x509.CertPool
}

// loadIPADefaults ignores missing or unparsable files: callers then get zero
// values and the system roots.
func loadIPADefaults(confPath, caPath string) ipaDefaults {
	var d ipaDefaults
	if pem, err := os.ReadFile(caPath); err == nil {
		d.pool = x509.NewCertPool()
		if !d.pool.AppendCertsFromPEM(pem) {
			d.pool = nil
		}
	}
	if cfg, err := ini.Load(confPath); err == nil {
		g := cfg.Section("global")
		if u, err := url.Parse(g.Key("xmlrpc_uri").MustString("http://localhost")); err == nil {
			d.host = u.Host
		}
		d.realm = g.Key("realm").MustString("LOCAL")
	}
	return d
}

var defaultsLoads atomic.Int32

// systemDefaults is a var so tests can swap it.
var systemDefaults = sync.OnceValue(func() ipaDefaults {
	defaultsLoads.Add(1)
	return loadIPADefaults("/etc/ipa/default.conf", "/etc/ipa/ca.crt")
})
