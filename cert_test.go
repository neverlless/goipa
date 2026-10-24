// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestCert_EmptyKeys(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.CertRequest("", "csr"); err == nil {
		t.Error("CertRequest without principal")
	}
	if _, err := c.CertRequest("host/h", ""); err == nil {
		t.Error("CertRequest without csr")
	}
	if _, err := c.CertShow(""); err == nil {
		t.Error("CertShow without serial")
	}
	if err := c.CertRevoke("", 0); err == nil {
		t.Error("CertRevoke without serial")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls reached the server", n)
	}
}

func TestCertShow_Fields(t *testing.T) {
	s, c := newFake(t)
	s.Handle("cert_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{
			"serial_number":     float64(12),
			"certificate":       "AQID",
			"valid_not_before":  "Sat Oct 24 18:49:36 2026 UTC",
			"valid_not_after":   "Tue Oct 25 18:49:36 2028 UTC",
			"revoked":           true,
			"revocation_reason": float64(1),
		}}, nil
	})
	got, err := c.CertShow("12")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 24, 18, 49, 36, 0, time.UTC)
	if got.SerialNumber != "12" || len(got.DER) != 3 || !got.NotBefore.Equal(want) || got.NotAfter.Year() != 2028 ||
		!got.Revoked || got.RevocationReason != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestCertRevoke_SendsReason(t *testing.T) {
	s, c := newFake(t)
	s.Handle("cert_revoke", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"revoked": true}}, nil
	})
	if err := c.CertRevoke("7", 0); err != nil {
		t.Fatal(err)
	}
	call := s.Calls()[0]
	if call.Args[0] != "7" || call.Options["revocation_reason"] != float64(0) {
		t.Errorf("call %+v", call)
	}
}
