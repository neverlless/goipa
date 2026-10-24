// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"time"

	"github.com/jcmturner/gokrb5/v8/spnego"
)

const maxResponseSize = 64 << 20

// setSPNEGOHeader is a var so tests can stand in for a KDC.
var setSPNEGOHeader = spnego.SetSPNEGOHeader

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

// Call FreeIPA API with method, params and options
func (c *Client) rpc(ctx context.Context, method string, params []string, options Options) (*Response, error) {
	anys := make([]any, len(params))
	for i, p := range params {
		anys[i] = p
	}
	return c.rpcParams(ctx, method, anys, options)
}

// rpcParams is rpc for positional arguments that are not all strings.
func (c *Client) rpcParams(ctx context.Context, method string, params []any, options Options) (*Response, error) {
	// The caller's map may be shared between goroutines; never write to it.
	opts := maps.Clone(options)
	if opts == nil {
		opts = Options{}
	}
	if _, ok := opts["version"]; !ok {
		opts["version"] = IpaClientVersion
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

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res, sent, spnego, err := c.send(ctx, b)
	var herr *HTTPError
	if spnego || !errors.As(err, &herr) || herr.StatusCode != http.StatusUnauthorized {
		return res, err
	}

	// The session expired, or was cleared by another goroutine's 401 before
	// this request was built. A 401 means FreeIPA rejected the request before
	// running the command, so sending it again is safe; at most once.
	c.mu.Lock()
	if c.sessionID == sent { // another goroutine may already hold a fresh one
		c.sessionID = ""
	}
	fresh, krb, sticky := c.sessionID, c.krbClient, c.sticky
	c.mu.Unlock()

	switch {
	case fresh != "" || krb != nil: // send uses the fresh session or SPNEGO
	case c.relogin && sticky: // without sticky sessions a new login is never used
		ok, lerr := c.passwordRelogin(ctx)
		if lerr != nil {
			return nil, lerr
		}
		if !ok {
			return nil, err
		}
	default:
		return nil, err
	}
	res, _, _, err = c.send(ctx, b)
	return res, err
}

// passwordRelogin logs in again with the stored credentials unless another
// goroutine already did; reloginMu makes concurrent 401s cost one login, so a
// changed password costs one failure, not one per goroutine. ok is false when
// no credentials are stored (never given, cleared, or dropped after a
// rejection), and the caller returns its 401.
func (c *Client) passwordRelogin(ctx context.Context) (ok bool, err error) {
	c.reloginMu.Lock()
	defer c.reloginMu.Unlock()
	c.mu.Lock()
	fresh, user, pass := c.sessionID, c.reloginUser, c.reloginPass
	c.mu.Unlock()
	switch {
	case fresh != "":
		return true, nil
	case user == "":
		return false, nil
	}
	if err := c.RemoteLoginContext(ctx, user, pass); err != nil {
		if errors.Is(err, ErrInvalidPassword) || errors.Is(err, ErrExpiredPassword) || errors.Is(err, ErrUnauthorized) {
			c.dropRelogin(user, pass) // retrying a rejected password ends in lockout
		}
		return true, err
	}
	return true, nil
}

// send makes one request with body b and returns the session it carried and
// whether it authenticated with SPNEGO instead.
func (c *Client) send(ctx context.Context, b []byte) (*Response, string, bool, error) {
	spnego := false
	c.krbMu.RLock()
	c.mu.Lock()
	sessionID, krbClient := c.sessionID, c.krbClient
	c.mu.Unlock()

	ipaURL := fmt.Sprintf("https://%s/ipa/json", c.host)
	if len(sessionID) > 0 {
		ipaURL = fmt.Sprintf("https://%s/ipa/session/json", c.host)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", ipaURL, bytes.NewReader(b))
	if err != nil {
		c.krbMu.RUnlock()
		return nil, sessionID, spnego, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/xml", c.host))

	if len(sessionID) > 0 {
		// If session is set, use the session id
		req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", sessionID))
	} else if krbClient != nil {
		// use Kerberos auth (SPNEGO)
		if err := setSPNEGOHeader(krbClient, req, ""); err != nil {
			c.krbMu.RUnlock()
			return nil, sessionID, true, err
		}
		spnego = true
	}
	c.krbMu.RUnlock()

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, sessionID, spnego, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, sessionID, spnego, &HTTPError{StatusCode: res.StatusCode, Status: res.Status}
	}

	if err = c.setSessionID(res); err != nil {
		return nil, sessionID, spnego, err
	}

	rawJSON, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil {
		return nil, sessionID, spnego, err
	}
	if len(rawJSON) > maxResponseSize {
		return nil, sessionID, spnego, fmt.Errorf("ipa: response larger than %d bytes", maxResponseSize)
	}

	var ipaRes Response
	err = json.Unmarshal(rawJSON, &ipaRes)
	if err != nil {
		return nil, sessionID, spnego, err
	}

	if ipaRes.Error != nil {
		return nil, sessionID, spnego, ipaRes.Error
	}

	if ipaRes.Result == nil {
		return nil, sessionID, spnego, errors.New("ipa: response has neither result nor error")
	}

	// Only successful responses count: an error envelope may come from a proxy.
	if ipaRes.Version != "" {
		c.mu.Lock()
		c.serverVersion = ipaRes.Version
		c.mu.Unlock()
	}

	return &ipaRes, sessionID, spnego, nil
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
	return c.PingContext(context.Background())
}

// PingContext is like Ping but bounds the request with ctx.
func (c *Client) PingContext(ctx context.Context) (*Response, error) {
	res, err := c.rpc(ctx, "ping", []string{}, nil)

	if err != nil {
		return nil, err
	}

	return res, nil
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
