// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- a fingerprint FreeIPA reports, not a signature
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
)

// certTimeFormat is ipalib.x509.format_datetime's layout.
const certTimeFormat = "Mon Jan 02 15:04:05 2006 MST"

type fakeCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	next int64 // last serial issued
}

type certRec struct {
	cert    *x509.Certificate
	revoked bool
	reason  int
}

// caLocked returns the server's CA, creating it on first use.
func (s *Server) caLocked() (*fakeCA, error) {
	if s.ca != nil {
		return s.ca, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Certificate Authority", Organization: []string{realm}},
		NotBefore:             now,
		NotAfter:              now.AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s.ca = &fakeCA{key: key, cert: cert, next: 1}
	return s.ca, nil
}

func parseCSR(in string) (*x509.CertificateRequest, error) {
	der := []byte(nil)
	if b, _ := pem.Decode([]byte(in)); b != nil {
		der = b.Bytes
	} else if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in)); err == nil {
		der = d
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	return csr, csr.CheckSignature()
}

func certRequest(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("csr")
	}
	principal, _ := c.Options["principal"].(string)
	if principal == "" {
		return nil, required("principal")
	}
	csr, err := parseCSR(c.Args[0])
	if err != nil {
		return nil, invalid("invalid 'csr': Failure decoding Certificate Signing Request: " + err.Error())
	}
	name, _, _ := strings.Cut(principal, "@")
	fqdn, ok := strings.CutPrefix(name, "host/")
	if _, exists := s.hosts[fqdn]; !ok || !exists {
		return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Message: "The service principal for this request doesn't exist."}
	}
	if !strings.EqualFold(csr.Subject.CommonName, fqdn) {
		return nil, invalid(fmt.Sprintf("invalid 'csr': hostname in subject of request '%s' does not match name or aliases of principal '%s'", csr.Subject.CommonName, principal))
	}
	if csr.PublicKeyAlgorithm != x509.RSA {
		return nil, certOpError("Key Type RSA Not Matched")
	}
	ca, err := s.caLocked()
	if err != nil {
		return nil, certOpError(err.Error())
	}
	ca.next++
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.next),
		Subject:      pkix.Name{CommonName: fqdn, Organization: []string{realm}},
		NotBefore:    now,
		NotAfter:     now.AddDate(2, 0, 0),
		DNSNames:     []string{fqdn},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, invalid("invalid 'csr': " + err.Error())
	}
	cert, _ := x509.ParseCertificate(der)
	rec := &certRec{cert: cert}
	s.certs[cert.SerialNumber.String()] = rec
	return entry("", renderCert(rec), ""), nil
}

func renderCert(r *certRec) map[string]any {
	sha1sum := sha1.Sum(r.cert.Raw) // #nosec G401 -- fingerprint only
	sha256sum := sha256.Sum256(r.cert.Raw)
	out := map[string]any{
		"certificate":        base64.StdEncoding.EncodeToString(r.cert.Raw),
		"serial_number":      json.Number(r.cert.SerialNumber.String()),
		"serial_number_hex":  fmt.Sprintf("0x%X", r.cert.SerialNumber),
		"subject":            r.cert.Subject.String(),
		"issuer":             r.cert.Issuer.String(),
		"valid_not_before":   r.cert.NotBefore.UTC().Format(certTimeFormat),
		"valid_not_after":    r.cert.NotAfter.UTC().Format(certTimeFormat),
		"sha1_fingerprint":   fingerprint(sha1sum[:]),
		"sha256_fingerprint": fingerprint(sha256sum[:]),
		"san_dnsname":        r.cert.DNSNames,
		"cacn":               "ipa",
		"revoked":            r.revoked,
	}
	if r.revoked {
		out["revocation_reason"] = r.reason
	}
	return out
}

func fingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func certOpError(msg string) *ipa.IpaError {
	return &ipa.IpaError{Code: 4301, Name: "CertificateOperationError", Message: "Certificate operation cannot be completed: " + msg}
}

// certLookup finds the certificate a serial_number argument names, decimal or
// 0x-prefixed hex as FreeIPA accepts.
func certLookup(s *Server, c Call) (*certRec, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("serial_number")
	}
	n, ok := new(big.Int).SetString(c.Args[0], 0)
	if !ok {
		return nil, invalid("invalid 'serial_number': must be an integer")
	}
	r := s.certs[n.String()]
	if r == nil {
		var x, y int
		if _, err := fmt.Sscanf(s.version, "%d.%d", &x, &y); err == nil && (x < 4 || x == 4 && y < 12) {
			return nil, certOpError(fmt.Sprintf("Request failed with status 404: Non-2xx response from CA REST API: 404. Certificate ID 0x%x not found (404)", n))
		}
		return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Message: fmt.Sprintf("Certificate ID 0x%x not found", n)}
	}
	return r, nil
}

func certShow(s *Server, c Call) (any, *ipa.IpaError) {
	r, err := certLookup(s, c)
	if err != nil {
		return nil, err
	}
	// shortcut: only host certificates exist here and no plain user manages a host, so every non-admin is refused (Q95); check the subject once user certificates are modelled.
	if !s.isAdmin(c.User) {
		return nil, &ipa.IpaError{Code: ipa.CodeACI, Message: "Insufficient access: not allowed to perform operation: retrieve certificate"}
	}
	return entry("", renderCert(r), ""), nil
}

func certRevoke(s *Server, c Call) (any, *ipa.IpaError) {
	r, err := certLookup(s, c)
	if err != nil {
		return nil, err
	}
	reason := 0
	if v, ok := c.Options["revocation_reason"].(float64); ok {
		reason = int(v)
	}
	r.revoked, r.reason = true, reason
	return map[string]any{"result": map[string]any{"revoked": true}, "value": "", "summary": nil}, nil
}

func init() {
	builtins["cert_request"] = certRequest
	builtins["cert_show"] = certShow
	builtins["cert_revoke"] = certRevoke
}
