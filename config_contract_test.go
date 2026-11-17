// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import "testing"

// V12
func TestContractConfigShow(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cfg, err := b.admin.ConfigShow()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DefaultPrimaryGroup == "" || cfg.HomesRootDir == "" || cfg.DefaultLoginShell == "" || cfg.DefaultEmailDomain == "" ||
			cfg.MaxUsernameLength == 0 || cfg.PwdExpAdvNotify == 0 || len(cfg.UserObjectClasses) == 0 || len(cfg.ConfigString) == 0 {
			t.Errorf("config has empty fields: %+v", cfg)
		}
		if cfg.UserAuthTypes != nil {
			t.Errorf("UserAuthTypes = %v, want nil by default", cfg.UserAuthTypes)
		}
		// Any authenticated user may read it (System: Read Global Configuration).
		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		if c2, err := plain.ConfigShow(); err != nil || c2.HomesRootDir != cfg.HomesRootDir {
			t.Errorf("plain user: %+v, %v", c2, err)
		}
	})
}
