// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func csrPEM(t *testing.T, cn string, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestCert_RequestShowRevoke(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHost("web.test.local", ipatest.Host{})
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr := csrPEM(t, "WEB.test.local", rsaKey)

	cert, err := c.CertRequest("host/web.test.local@TEST.LOCAL", csr)
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber != "2" || x.Subject.CommonName != "WEB.test.local" || cert.Issuer != "CN=Certificate Authority,O=TEST.LOCAL" {
		t.Errorf("cert = %+v", cert) // the CA holds serial 1; the CN is spelled as in the CSR (Q144)
	}
	// The base64 DER of the CSR, without PEM armour, is accepted too.
	block, _ := pem.Decode([]byte(csr))
	if cert, err := c.CertRequest("host/web.test.local", base64.StdEncoding.EncodeToString(block.Bytes)); err != nil || cert.SerialNumber != "3" {
		t.Errorf("base64 request = %+v, %v", cert, err)
	}

	got, err := c.CertShow("0x2")
	if err != nil || got.SerialNumber != "2" || got.Revoked {
		t.Errorf("show by hex = %+v, %v", got, err)
	}
	_, err = s.ClientAs("bob").CertShow("2")
	wantIpaCode(t, "non-admin show", err, ipa.CodeACI)

	if err := c.CertRevoke("2", 4); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.CertShow("2"); !got.Revoked || got.RevocationReason != 4 {
		t.Errorf("after revoke = %+v", got)
	}
	for v, want := range map[string]string{
		"4.9.13": "ipa: error 4301 - Certificate operation cannot be completed: ERROR (Attempt to revoke non-existent certificate(s).)",
		"4.12.2": "ipa: error 4035 - Request failed with status 400: Non-2xx response from CA REST API: 400. certificate #2 has already been revoked",
		"4.13.4": "ipa: error 4301 - Certificate operation cannot be completed: Unable to communicate with CMS (certificate 0x2 has already been revoked)",
	} {
		s.SetVersion(v)
		if err := c.CertRevoke("2", 1); err == nil || err.Error() != want {
			t.Errorf("%s revoke again: %v", v, err)
		}
	}
	if got, _ := c.CertShow("2"); got.RevocationReason != 4 {
		t.Errorf("reason after second revoke = %d, want the first one kept (Q145)", got.RevocationReason)
	}

	s.SetVersion("4.9.13")
	if _, err := c.CertShow("99"); err == nil || !strings.Contains(err.Error(), "4301 - ") || !strings.Contains(err.Error(), "Certificate ID 0x63 not found (404)") {
		t.Errorf("4.9 missing: %v", err)
	}
	s.SetVersion("4.13.4")
	if _, err := c.CertShow("99"); err == nil || err.Error() != "ipa: error 4001 - Certificate ID 0x63 not found" {
		t.Errorf("4.13 missing: %v", err)
	}
	_, err = c.RPC("cert_show", []string{"zz"}, nil)
	wantIpaCode(t, "non-numeric serial", err, ipa.CodeValidation)
	_, err = c.RPC("cert_show", nil, nil)
	wantIpaCode(t, "no serial", err, ipa.CodeRequirement)
}

func TestCert_RequestErrors(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHost("web.test.local", ipatest.Host{})
	c := s.ClientAs("admin")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := csrPEM(t, "web.test.local", rsaKey)

	_, err = c.RPC("cert_request", nil, ipa.Options{"principal": "host/web.test.local"})
	wantIpaCode(t, "no csr", err, ipa.CodeRequirement)
	_, err = c.RPC("cert_request", []string{good}, nil)
	wantIpaCode(t, "no principal", err, ipa.CodeRequirement)
	for _, tc := range []struct{ principal, csr, want string }{
		{"host/web.test.local", "not a csr", "ipa: error 3009 - invalid 'csr': Failure decoding Certificate Signing Request: "},
		{"HTTP/web.test.local", good, "ipa: error 4001 - The service principal for this request doesn't exist."},
		{"host/WEB.test.local", good, "ipa: error 4001 - The principal for this request doesn't exist."},
		{"host/web.test.local", csrPEM(t, "other.test.local", rsaKey), "ipa: error 3009 - invalid 'csr': hostname in subject of request 'other.test.local' does not match name or aliases of principal 'host/web.test.local'"},
		{"host/web.test.local", csrPEM(t, "web.test.local", ecKey), "ipa: error 4301 - Certificate operation cannot be completed: Key Type RSA Not Matched"},
	} {
		if _, err := c.CertRequest(tc.principal, tc.csr); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: %v\nwant %s", tc.principal, err, tc.want)
		}
	}
}
