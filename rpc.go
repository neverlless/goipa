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

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.krbMu.RLock()
	c.mu.Lock()
	sessionID, krbClient := c.sessionID, c.krbClient
	c.mu.Unlock()

	ipaURL := fmt.Sprintf("https://%s/ipa/json", c.host)
	if len(sessionID) > 0 {
		ipaURL = fmt.Sprintf("https://%s/ipa/session/json", c.host)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", ipaURL, bytes.NewBuffer(b))
	if err != nil {
		c.krbMu.RUnlock()
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
			c.krbMu.RUnlock()
			return nil, err
		}
	}
	c.krbMu.RUnlock()

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: res.StatusCode, Status: res.Status}
	}

	if err = c.setSessionID(res); err != nil {
		return nil, err
	}

	rawJSON, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(rawJSON) > maxResponseSize {
		return nil, fmt.Errorf("ipa: response larger than %d bytes", maxResponseSize)
	}

	var ipaRes Response
	err = json.Unmarshal(rawJSON, &ipaRes)
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
