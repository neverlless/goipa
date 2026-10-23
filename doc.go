// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client for the FreeIPA JSON-RPC API. It is a maintained
// continuation of github.com/ubccr/goipa.
//
// A Client logs in with a password (Login for Kerberos, RemoteLogin for the
// web API), a keytab (LoginWithKeytab), a credentials cache (LoginFromCCache),
// or an existing session (NewDefaultClientWithSession, SetSessionID). A
// *Client is safe for concurrent use.
//
// A FreeIPA error is returned as a bare *IpaError: match it with errors.Is
// against ErrNotFound and the other sentinels, or with a type assertion.
//
// Every method that talks to the server has a ...Context twin that bounds the
// request with a context, except Login, LoginWithKeytab and LoginFromCCache
// (gokrb5 is not cancellable). RPC calls any command goipa does not wrap.
package ipa
