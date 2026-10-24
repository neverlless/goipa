// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

// newCertHost adds a host in the server's domain and deletes it when the
// test ends.
func newCertHost(t *testing.T, b backend) string {
	t.Helper()
	_, domain, _ := strings.Cut(serverHost(t, b), ".")
	fqdn := "goipa" + randHex(t, 4) + "." + domain
	mustRPC(t, b.admin, "host_add", []string{fqdn}, ipa.Options{"force": true})
	t.Cleanup(func() { _, _ = b.admin.RPC("host_del", []string{fqdn}, nil) })
	return fqdn
}

// csrFor makes an RSA CSR: FreeIPA's default profile rejects other keys (Q94).
func csrFor(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func wantCertCode(t *testing.T, err error, code int) {
	t.Helper()
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != code {
		t.Fatalf("got %v, want error %d", err, code)
	}
}

// TestContractCert pins Q90 and Q91.
func TestContractCert(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newCertHost(t, b)
		cert, err := b.admin.CertRequest("host/"+fqdn, csrFor(t, fqdn))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.CertRevoke(cert.SerialNumber, 4) })
		shown, err := b.admin.CertShow(cert.SerialNumber)
		if err != nil {
			t.Fatal(err)
		}
		x, err := x509.ParseCertificate(shown.DER)
		if err != nil {
			t.Fatalf("DER: %v", err)
		}
		if x.SerialNumber.String() != cert.SerialNumber || shown.SerialNumber != cert.SerialNumber {
			t.Errorf("serial %s, shown %s, requested %s", x.SerialNumber, shown.SerialNumber, cert.SerialNumber)
		}
		if !x.NotAfter.Equal(shown.NotAfter) || !x.NotBefore.Equal(shown.NotBefore) || !shown.NotAfter.After(time.Now()) {
			t.Errorf("validity %v..%v, certificate %v..%v", shown.NotBefore, shown.NotAfter, x.NotBefore, x.NotAfter)
		}
		if !x.NotAfter.Equal(cert.NotAfter) || len(cert.DER) == 0 {
			t.Errorf("cert_request: NotAfter %v, %d DER bytes", cert.NotAfter, len(cert.DER))
		}
		if !strings.Contains(shown.Subject, "CN="+fqdn) || shown.Issuer == "" || shown.Revoked {
			t.Errorf("shown %+v", shown)
		}
		if err := b.admin.CertRevoke(cert.SerialNumber, 4); err != nil {
			t.Fatal(err)
		}
		shown, err = b.admin.CertShow(cert.SerialNumber)
		if err != nil {
			t.Fatal(err)
		}
		if !shown.Revoked || shown.RevocationReason != 4 {
			t.Errorf("after revoke: revoked %v, reason %d", shown.Revoked, shown.RevocationReason)
		}
	})
}

// TestContractCertShowMissing pins Q92.
func TestContractCertShowMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		_, err := b.admin.CertShow("987654321")
		if certNotFoundIs4301(t, b) {
			wantCertCode(t, err, 4301)
		} else {
			wantIs(t, err, ipa.ErrNotFound)
		}
	})
}

// certNotFoundIs4301 reports whether b predates 4.12, where Dogtag's 404 came
// back as 4301 CertificateOperationError.
func certNotFoundIs4301(t *testing.T, b backend) bool {
	t.Helper()
	res, err := b.admin.Ping()
	if err != nil {
		t.Fatal(err)
	}
	var x, y int
	if _, err := fmt.Sscanf(res.Version, "%d.%d", &x, &y); err != nil {
		t.Fatalf("server version %q: %v", res.Version, err)
	}
	return x < 4 || x == 4 && y < 12
}

// TestContractCertRequestECDSA pins Q94.
func TestContractCertRequestECDSA(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newCertHost(t, b)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: fqdn}}, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.CertRequest("host/"+fqdn, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
		wantCertCode(t, err, 4301)
	})
}

// TestContractCertRequestWrongCN pins Q93.
func TestContractCertRequestWrongCN(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newCertHost(t, b)
		_, err := b.admin.CertRequest("host/"+fqdn, csrFor(t, "other"+fqdn))
		wantCertCode(t, err, ipa.CodeValidation)
	})
}
