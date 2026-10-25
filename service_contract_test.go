// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

// newService adds goipa<rand>/<server host>@REALM and deletes it afterwards.
func newService(t *testing.T, b backend) (principal, host string) {
	t.Helper()
	host = serverHost(t, b)
	principal = "goipa" + randHex(t, 4) + "/" + host + "@" + b.realm
	if _, err := b.admin.ServiceAdd(principal, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.ServiceDelete(principal) })
	return principal, host
}

func newServiceUser(t *testing.T, b backend) string {
	t.Helper()
	uid := newUID(t, b)
	if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
		t.Fatal(err)
	}
	return uid
}

// serviceTestCert is a throwaway DER certificate FreeIPA's CA did not issue.
// FreeIPA 4.13.4 fails cert_find, and so service_del, with 903 on a
// certificate without subjectAltName.
func serviceTestCert(t *testing.T, host string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "goipa contract test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestContractServiceLifecycle pins Q60.
func TestContractServiceLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		principal, host := newService(t, b)
		shown, err := b.admin.ServiceShow(principal)
		if err != nil {
			t.Fatal(err)
		}
		if shown.Principal != principal || !slices.Contains(shown.Aliases, principal) {
			t.Errorf("principal %q aliases %v, want %q", shown.Principal, shown.Aliases, principal)
		}
		if !slices.Equal(shown.ManagedBy, []string{host}) {
			t.Errorf("managedby %v, want [%s]", shown.ManagedBy, host)
		}
		if shown.HasKeytab || shown.OKAsDelegate || shown.OKToAuthAsDelegate || !shown.RequiresPreAuth {
			t.Errorf("flags %+v", shown)
		}
		// Without the realm the server adds it.
		short := principal[:len(principal)-len("@"+b.realm)]
		if s, err := b.admin.ServiceShow(short); err != nil || s.Principal != principal {
			t.Fatalf("show %q: %v, %+v", short, err, s)
		}
		found, err := b.admin.ServiceFind(ipa.Options{"krbcanonicalname": principal})
		if err != nil || len(found) != 1 || found[0].Principal != principal {
			t.Fatalf("find: %v, %d results", err, len(found))
		}
		var ie *ipa.IpaError
		if _, err := b.admin.ServiceAdd(principal, true); !errors.As(err, &ie) || ie.Code != ipa.CodeDuplicateEntry {
			t.Errorf("second add: %v, want 4002", err)
		}
		if err := b.admin.ServiceDelete(principal); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.ServiceShow(principal)
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractServiceKeytabAccess pins Q61.
func TestContractServiceKeytabAccess(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		principal, _ := newService(t, b)
		uid, cn := newServiceUser(t, b), newGroup(t, b)
		a := ipa.KeytabAccess{Users: []string{uid}, Groups: []string{cn}}
		svc, err := b.admin.ServiceAllowRetrieveKeytab(principal, a)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(svc.KeytabRetrieve.Users, a.Users) || !slices.Equal(svc.KeytabRetrieve.Groups, a.Groups) {
			t.Errorf("retrieve %+v, want %+v", svc.KeytabRetrieve, a)
		}
		if len(svc.KeytabCreate.Users) != 0 {
			t.Errorf("create %+v", svc.KeytabCreate)
		}
		shown, err := b.admin.ServiceShow(principal)
		if err != nil || !slices.Equal(shown.KeytabRetrieve.Users, a.Users) {
			t.Fatalf("show: %v, %+v", err, shown)
		}
		if svc, err = b.admin.ServiceDisallowRetrieveKeytab(principal, a); err != nil {
			t.Fatal(err)
		}
		if len(svc.KeytabRetrieve.Users)+len(svc.KeytabRetrieve.Groups) != 0 {
			t.Errorf("retrieve after disallow %+v", svc.KeytabRetrieve)
		}

		c := ipa.KeytabAccess{Users: []string{uid}}
		if svc, err = b.admin.ServiceAllowCreateKeytab(principal, c); err != nil || !slices.Equal(svc.KeytabCreate.Users, c.Users) {
			t.Fatalf("allow create: %v, %+v", err, svc)
		}
		if svc, err = b.admin.ServiceDisallowCreateKeytab(principal, c); err != nil || len(svc.KeytabCreate.Users) != 0 {
			t.Fatalf("disallow create: %v, %+v", err, svc)
		}
	})
}

// TestContractServiceMemberMissing pins Q62.
func TestContractServiceMemberMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		principal, _ := newService(t, b)
		missing := newUID(t, b)
		svc, err := b.admin.ServiceAllowRetrieveKeytab(principal, ipa.KeytabAccess{Users: []string{missing}})
		var me *ipa.MemberError
		if !errors.As(err, &me) || svc == nil {
			t.Fatalf("svc %v, err %v; want the service and *MemberError", svc, err)
		}
		if len(me.Failures) != 1 || me.Failures[0].Name != missing || me.Failures[0].Type != "user" ||
			me.Failures[0].Kind != "ipaallowedtoperform_read_keys" {
			t.Errorf("failures %+v", me.Failures)
		}
		if svc.Principal != principal || len(svc.KeytabRetrieve.Users) != 0 {
			t.Errorf("svc %+v", svc)
		}
	})
}

// TestContractServiceManagedBy pins Q63.
func TestContractServiceManagedBy(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		principal, host := newService(t, b)
		svc, err := b.admin.ServiceAddHost(principal, []string{host})
		var me *ipa.MemberError
		if !errors.As(err, &me) || svc == nil || me.Failures[0].Kind != "managedby" || me.Failures[0].Type != "host" {
			t.Fatalf("add own host: %v, %+v", err, svc)
		}
		if svc, err = b.admin.ServiceRemoveHost(principal, []string{host}); err != nil || len(svc.ManagedBy) != 0 {
			t.Fatalf("remove: %v, %+v", err, svc)
		}
		if svc, err = b.admin.ServiceAddHost(principal, []string{host}); err != nil || !slices.Equal(svc.ManagedBy, []string{host}) {
			t.Fatalf("add: %v, %+v", err, svc)
		}
	})
}

// TestContractServiceDisable pins Q64.
func TestContractServiceDisable(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		principal, host := newService(t, b)
		var ie *ipa.IpaError
		if err := b.admin.ServiceDisable(principal); !errors.As(err, &ie) || ie.Code != ipa.CodeAlreadyInactive {
			t.Fatalf("disable without keys: %v, want 4010", err)
		}
		der := serviceTestCert(t, host)
		mustRPC(t, b.admin, "service_add_cert", []string{principal}, ipa.Options{"usercertificate": []string{base64.StdEncoding.EncodeToString(der)}})
		svc, err := b.admin.ServiceShow(principal)
		if err != nil || len(svc.Certificates) != 1 || !bytes.Equal(svc.Certificates[0], der) {
			t.Fatalf("show: %v, %d certificates", err, len(svc.Certificates))
		}
		// Before 4.13 a certificate the IPA CA did not issue neither counts
		// nor goes; 4.13 removes it.
		err = b.admin.ServiceDisable(principal)
		left := 1
		if serverAtLeast(b.admin.ServerVersion(), 4, 13) {
			left = 0
			if err != nil {
				t.Fatalf("disable with a foreign certificate: %v", err)
			}
		} else if !errors.As(err, &ie) || ie.Code != ipa.CodeAlreadyInactive {
			t.Fatalf("disable with a foreign certificate: %v, want 4010", err)
		}
		if svc, err = b.admin.ServiceShow(principal); err != nil || svc.HasKeytab || len(svc.Certificates) != left {
			t.Fatalf("after disable: %v, %d certificates, want %d", err, len(svc.Certificates), left)
		}
	})
}
