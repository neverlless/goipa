// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client library for FreeIPA
package ipa

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ini/ini"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
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

	// ErrPasswordPolicy is returned when a password does not conform to the password policy
	ErrPasswordPolicy = errors.New("password does not conform to policy")

	// ErrInvalidPassword is returned when a password is invalid
	ErrInvalidPassword = errors.New("invalid current password")

	// ErrExpiredPassword is returned when a password is expired
	ErrExpiredPassword = errors.New("password expired")

	// ErrUnauthorized is returned when user is not authorized
	ErrUnauthorized = errors.New("unauthorized")

	// ErrUserExists is the UserAdd form of ErrDuplicateEntry.
	ErrUserExists = errors.New("user exists")
)

// FreeIPA Client
type Client struct {
	host       string
	realm      string
	httpClient *http.Client

	mu        sync.Mutex // guards the fields below; a Client is shared across goroutines
	sessionID string
	sticky    bool
	krbClient *client.Client
}

// FreeIPA api options map
type Options map[string]interface{}

const maxResponseSize = 64 << 20

// FreeIPA error
type IpaError struct {
	Message string
	Code    int
	Name    string `json:"name"`
	// Data is the raw JSON of the exception's keyword arguments, e.g.
	// {"reason":"..."}. A string so IpaError stays comparable.
	Data string `json:"data"`
}

// UnmarshalJSON keeps Data as raw JSON text; Message and Code still match the
// "message" and "code" keys case-insensitively.
func (e *IpaError) UnmarshalJSON(b []byte) error {
	var v struct {
		Message string
		Code    int
		Name    string
		Data    json.RawMessage
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*e = IpaError{Message: v.Message, Code: v.Code, Name: v.Name, Data: string(v.Data)}
	return nil
}

// Result returned from a FreeIPA JSON rpc call
type Result struct {
	Summary   string          `json:"summary"`
	Value     interface{}     `json:"value"`
	Data      json.RawMessage `json:"result"`
	Count     int             `json:"count"`
	Truncated bool            `json:"truncated"`
	Messages  []Message       `json:"messages"`
	Completed int             `json:"completed"`
	Failed    json.RawMessage `json:"failed"`
	// Raw is the whole FreeIPA result object, for shapes without a "result"
	// key such as hbactest.
	Raw json.RawMessage `json:"-"`
}

// Message is a server warning attached to a FreeIPA result.
type Message struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Message string          `json:"message"`
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
}

// UnmarshalJSON decodes the result and keeps a copy of the raw object in Raw.
func (r *Result) UnmarshalJSON(b []byte) error {
	type plain Result
	if err := json.Unmarshal(b, (*plain)(r)); err != nil {
		return err
	}
	r.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// Response returned from a FreeIPA JSON rpc call
type Response struct {
	Error     *IpaError `json:"error"`
	ID        int       `json:"id"`
	Principal string    `json:"principal"`
	Version   string    `json:"version"`
	Result    *Result   `json:"result"`
}

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

func (e *IpaError) Error() string {
	return fmt.Sprintf("ipa: error %d - %s", e.Code, e.Message)
}

// Call FreeIPA API with method, params and options
func (c *Client) rpc(ctx context.Context, method string, params []string, options Options) (*Response, error) {
	// The caller's map may be shared between goroutines; never write to it.
	opts := maps.Clone(options)
	if opts == nil {
		opts = Options{}
	}
	if _, ok := opts["version"]; !ok {
		opts["version"] = IpaClientVersion
	}
	if params == nil {
		params = []string{}
	}

	data := []interface{}{
		params,
		opts,
	}

	payload := Options{
		"id":     0,
		"method": method,
		"params": data,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	sessionID, krbClient := c.sessionID, c.krbClient
	c.mu.Unlock()

	ipaUrl := fmt.Sprintf("https://%s/ipa/json", c.host)
	if len(sessionID) > 0 {
		ipaUrl = fmt.Sprintf("https://%s/ipa/session/json", c.host)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", ipaUrl, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/xml", c.host))

	if len(sessionID) > 0 {
		// If session is set, use the session id
		req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", sessionID))
	} else if krbClient != nil {
		// use Kerberos auth (SPNEGO)
		if err := spnego.SetSPNEGOHeader(krbClient, req, ""); err != nil {
			return nil, err
		}
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, &HTTPError{StatusCode: res.StatusCode, Status: res.Status}
	}

	if err = c.setSessionID(res); err != nil {
		return nil, err
	}

	rawJson, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(rawJson) > maxResponseSize {
		return nil, fmt.Errorf("ipa: response larger than %d bytes", maxResponseSize)
	}

	var ipaRes Response
	err = json.Unmarshal(rawJson, &ipaRes)
	if err != nil {
		return nil, err
	}

	if ipaRes.Error != nil {
		return nil, ipaRes.Error
	}

	if ipaRes.Result == nil {
		return nil, errors.New("ipa: response has neither result nor error")
	}

	return &ipaRes, nil
}

// Returns FreeIPA server hostname
func (c *Client) Host() string {
	return c.host
}

// Returns FreeIPA realm
func (c *Client) Realm() string {
	return c.realm
}

// RPC calls any FreeIPA command, an escape hatch for commands goipa does not
// wrap. It uses the client's HTTP client, session or Kerberos credentials and
// API version. A FreeIPA failure is returned as a bare *IpaError. options is
// not modified; a "version" in options wins over IpaClientVersion.
func (c *Client) RPC(method string, args []string, options Options) (*Response, error) {
	return c.RPCContext(context.Background(), method, args, options)
}

// RPCContext is like RPC but ends the request when ctx is done.
func (c *Client) RPCContext(ctx context.Context, method string, args []string, options Options) (*Response, error) {
	return c.rpc(ctx, method, args, options)
}

// Ping FreeIPA server to check connection
func (c *Client) Ping() (*Response, error) {
	res, err := c.rpc(context.Background(), "ping", []string{}, nil)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// Return current FreeIPA sessionID
func (c *Client) SessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
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
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/login_password", c.host)

	form := url.Values{"user": {uid}, "password": {passwd}}
	req, err := http.NewRequest("POST", ipaUrl, strings.NewReader(form.Encode()))
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

	c.mu.Lock()
	c.krbClient = cl
	c.mu.Unlock()

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

	c.mu.Lock()
	c.krbClient = cl
	c.mu.Unlock()

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

	c.mu.Lock()
	c.krbClient = cl
	c.mu.Unlock()

	return nil
}

// Parse a FreeIPA datetime. Datetimes in FreeIPA are returned using a
// class-hint system. Values are stored as an array with a single element
// indicating the type and value, for example, '[{"__datetime__": "YYYY-MM-DDTHH:MM:SSZ"]}'
func ParseDateTime(str string) time.Time {
	dt, err := time.Parse(IpaDatetimeFormat, str)
	if err != nil {
		return time.Time{}
	}

	return dt
}
