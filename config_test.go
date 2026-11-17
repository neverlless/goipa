// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	"github.com/neverlless/goipa/ipatest"
)

func TestConfigShow_Fields(t *testing.T) {
	s, c := newFake(t)
	cfg, err := c.ConfigShow()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserAuthTypes != nil || cfg.DefaultPrimaryGroup != "ipausers" || cfg.HomesRootDir != "/home" ||
		cfg.DefaultLoginShell != "/bin/sh" || cfg.DefaultEmailDomain == "" ||
		cfg.MaxUsernameLength != 32 || cfg.PwdExpAdvNotify != 4 ||
		len(cfg.UserObjectClasses) == 0 || !reflect.DeepEqual(cfg.ConfigString, []string{"AllowNThash", "KDC:Disable Last Success"}) {
		t.Errorf("config = %+v", cfg)
	}
	if got := s.Calls(); len(got) != 1 || got[0].Method != "config_show" || got[0].Options["all"] != true {
		t.Errorf("calls = %+v", got)
	}
}

func TestConfigShow_SetConfigAuthTypes(t *testing.T) {
	s, c := newFake(t)
	s.SetConfig(ipatest.Config{UserAuthTypes: []string{"password", "otp"}, MaxUsernameLength: 8})
	cfg, err := c.ConfigShow()
	if err != nil || !reflect.DeepEqual(cfg.UserAuthTypes, []string{"password", "otp"}) || cfg.MaxUsernameLength != 8 || cfg.HomesRootDir != "" {
		t.Errorf("config = %+v, %v", cfg, err)
	}
}
