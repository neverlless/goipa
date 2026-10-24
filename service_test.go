// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

const testSvc = "HTTP/ipa.test.local@TEST.LOCAL"

func TestService_NothingToDo(t *testing.T) {
	s, c := newFake(t)
	if err := c.ServiceDelete(); err == nil {
		t.Error("ServiceDelete(): want error")
	}
	if _, err := c.ServiceShow(""); err == nil {
		t.Error("ServiceShow(\"\"): want error")
	}
	if _, err := c.ServiceAllowRetrieveKeytab(testSvc, ipa.KeytabAccess{}); err == nil {
		t.Error("empty KeytabAccess: want error")
	}
	if _, err := c.ServiceAddHost("", []string{"h"}); err == nil {
		t.Error("empty principal: want error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls reached the server", n)
	}
}

func TestService_SeededAndDisable(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	s.AddService("HTTP/ipa.test.local", ipatest.Service{
		ManagedBy: []string{"ipa.test.local"}, HasKeytab: true,
		KeytabRetrieve: ipa.KeytabAccess{Users: []string{"u1"}},
	})
	svc, err := c.ServiceShow(testSvc)
	if err != nil || !svc.HasKeytab || !slices.Equal(svc.KeytabRetrieve.Users, []string{"u1"}) {
		t.Fatalf("show: %v, %+v", err, svc)
	}
	if err := c.ServiceDisable(testSvc); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Service(testSvc); !ok || got.HasKeytab {
		t.Errorf("after disable: %+v, %v", got, ok)
	}
	var ie *ipa.IpaError
	if err := c.ServiceDisable(testSvc); !errors.As(err, &ie) || ie.Code != ipa.CodeAlreadyInactive {
		t.Errorf("second disable: %v", err)
	}
}

func TestService_AddChecksHost(t *testing.T) {
	_, c := newFake(t)
	_, err := c.ServiceAdd("HTTP/nohost.test.local", true)
	wantIs(t, err, ipa.ErrNotFound)
	svc, err := c.ServiceAdd("HTTP/ipa.test.local", false)
	if err != nil || svc.Principal != testSvc {
		t.Fatalf("add: %v, %+v", err, svc)
	}
}

func TestService_FindAndDeleteMany(t *testing.T) {
	s, c := newFake(t)
	for _, p := range []string{"a/ipa.test.local", "b/ipa.test.local", "c/ipa.test.local"} {
		s.AddService(p, ipatest.Service{})
	}
	got, err := c.ServiceFind(ipa.Options{"sizelimit": 2})
	if !errors.Is(err, ipa.ErrTruncated) || len(got) != 2 {
		t.Fatalf("find: %v, %d", err, len(got))
	}
	if err := c.ServiceDelete("a/ipa.test.local", "b/ipa.test.local@TEST.LOCAL"); err != nil {
		t.Fatal(err)
	}
	if got, err = c.ServiceFind(nil); err != nil || len(got) != 1 || got[0].Principal != "c/ipa.test.local@TEST.LOCAL" {
		t.Fatalf("find after delete: %v, %+v", err, got)
	}
	wantIs(t, c.ServiceDelete("a/ipa.test.local"), ipa.ErrNotFound)
}
