// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"encoding/base64"
	"errors"
	"time"
)

// Certificate is a certificate issued by the FreeIPA CA. Certificates have no
// attributes to modify; Modify does not apply.
type Certificate struct {
	SerialNumber        string    // serial_number (decimal)
	Subject, Issuer     string    // subject, issuer
	NotBefore, NotAfter time.Time // valid_not_before, valid_not_after
	DER                 []byte    // certificate (base64)
	Revoked             bool      // revoked
	RevocationReason    int       // revocation_reason, RFC 5280 code; meaningful only when Revoked
}

// certTimeFormat is ipalib.x509.format_datetime's layout.
const certTimeFormat = "Mon Jan 02 15:04:05 2006 MST"

func certTime(e Entry, attr string) time.Time {
	if t, err := time.Parse(certTimeFormat, e.Str(attr)); err == nil {
		return t.UTC()
	}
	return e.Time(attr)
}

func certFromEntry(e Entry) *Certificate {
	c := &Certificate{
		SerialNumber: e.Str("serial_number"),
		Subject:      e.Str("subject"),
		Issuer:       e.Str("issuer"),
		NotBefore:    certTime(e, "valid_not_before"),
		NotAfter:     certTime(e, "valid_not_after"),
		DER:          e.Bytes("certificate"),
		Revoked:      e.Bool("revoked"),
	}
	if c.DER == nil {
		c.DER, _ = base64.StdEncoding.DecodeString(e.Str("certificate"))
	}
	if n, ok := e.Int("revocation_reason"); ok {
		c.RevocationReason = int(n)
	}
	return c
}

// CertRequest submits a PEM certificate signing request for principal (e.g.
// host/<fqdn>) with `cert_request` under the default profile and returns the
// issued certificate. It requires the Certificate Administrators privilege
// (Request Certificate), or the right to request for that host or service
// itself.
func (c *Client) CertRequest(principal, csrPEM string) (*Certificate, error) {
	return c.CertRequestContext(context.Background(), principal, csrPEM)
}

// CertRequestContext is like CertRequest but bounds the request with ctx.
func (c *Client) CertRequestContext(ctx context.Context, principal, csrPEM string) (*Certificate, error) {
	if principal == "" {
		return nil, errors.New("ipa: certificate principal is required")
	}
	if csrPEM == "" {
		return nil, errors.New("ipa: certificate signing request is required")
	}
	e, _, err := Call[Entry](ctx, c, "cert_request", []string{csrPEM}, Options{"principal": principal, "all": true})
	if err != nil {
		return nil, err
	}
	return certFromEntry(e), nil
}

// CertShow fetches the certificate with decimal serial number serial with
// `cert_show`. It requires the Certificate Administrators or Host
// Administrators privilege (Retrieve Certificates from the CA), or a host
// principal named in the certificate's subject CN; anyone else gets ErrACI.
func (c *Client) CertShow(serial string) (*Certificate, error) {
	return c.CertShowContext(context.Background(), serial)
}

// CertShowContext is like CertShow but bounds the request with ctx.
func (c *Client) CertShowContext(ctx context.Context, serial string) (*Certificate, error) {
	if serial == "" {
		return nil, errors.New("ipa: certificate serial number is required")
	}
	return showEntry(ctx, c, "cert_show", []string{serial}, certFromEntry)
}

// CertRevoke revokes the certificate with decimal serial number serial with
// `cert_revoke`; reason is the RFC 5280 code (0 unspecified, 4 superseded, …).
// It requires the Certificate Administrators privilege (Revoke Certificate).
func (c *Client) CertRevoke(serial string, reason int) error {
	return c.CertRevokeContext(context.Background(), serial, reason)
}

// CertRevokeContext is like CertRevoke but bounds the request with ctx.
func (c *Client) CertRevokeContext(ctx context.Context, serial string, reason int) error {
	if serial == "" {
		return errors.New("ipa: certificate serial number is required")
	}
	_, err := c.rpc(ctx, "cert_revoke", []string{serial}, Options{"revocation_reason": reason})
	return err
}
