// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
)

func writeKrb5File(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func realmKDCs(t *testing.T, cfg *config.Config, realm string) []string {
	t.Helper()
	_, kdcs, err := cfg.GetKDCs(realm, true)
	if err != nil {
		t.Fatalf("GetKDCs(%s): %v", realm, err)
	}
	var out []string
	for _, k := range kdcs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Layout written by ipa-client-install 4.13 (ipa-client-4.13.4-1.el9).
func TestLoadKrb5ConfigIPAClient413(t *testing.T) {
	dir := t.TempDir()
	confd := filepath.Join(dir, "krb5.conf.d")
	if err := os.Mkdir(confd, 0o750); err != nil {
		t.Fatal(err)
	}

	main := filepath.Join(dir, "krb5.conf")
	writeKrb5File(t, main, `#File modified by ipa-client-install

includedir `+confd+`/
[libdefaults]
  default_realm = MOKEY.TEST
  dns_lookup_realm = false
  dns_lookup_kdc = true
  forwardable = true
`)
	writeKrb5File(t, filepath.Join(confd, "freeipa-realm"), `[libdefaults]
    spake_preauth_groups = edwards25519

[realms]
  MOKEY.TEST = {
    kdc = ipa.mokey.test:88
    admin_server = ipa.mokey.test:749
    default_domain = mokey.test
  }

[domain_realm]
  .mokey.test = MOKEY.TEST
`)
	writeKrb5File(t, filepath.Join(confd, "sssd_enable_idp"), "[plugins]\n  clpreauth = {\n    module = idp:/usr/lib64/sssd/modules/sssd_krb5_idp_plugin.so\n  }\n")
	// Skipped by MIT krb5, so it must not override the realm
	writeKrb5File(t, filepath.Join(confd, "freeipa-realm.rpmsave"), "[realms]\n  MOKEY.TEST = {\n    kdc = stale.mokey.test:88\n  }\n")

	cfg, err := loadKrb5Config(main)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.DefaultRealm != "MOKEY.TEST" {
		t.Errorf("default realm = %q", cfg.LibDefaults.DefaultRealm)
	}
	_, kdcs, err := cfg.GetKDCs("MOKEY.TEST", true)
	if err != nil {
		t.Fatalf("no KDC for the realm: %v", err)
	}
	if len(kdcs) != 1 || kdcs[1] != "ipa.mokey.test:88" {
		t.Errorf("KDCs = %v, want ipa.mokey.test:88", kdcs)
	}
	if got := cfg.ResolveRealm("host.mokey.test"); got != "MOKEY.TEST" {
		t.Errorf("ResolveRealm = %q", got)
	}
}

func TestLoadKrb5ConfigNoIncludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5.conf")
	writeKrb5File(t, path, `[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false
  default_realm = OTHER.COM

[realms]
  EXAMPLE.COM = {
    kdc = kdc1.example.com
    kdc = kdc2.example.com:88
  }
  EXAMPLE.COM = {
    kdc = kdc3.example.com
  }
  V4.COM = {
    v4_instance_convert = {
      kerberos = kerberos
    }
  }

[domain_realm]
  .example.com = EXAMPLE.COM
`)

	want, wantErr := config.Load(path)
	got, err := loadKrb5Config(path)
	if (err == nil) != (wantErr == nil) || (err != nil && err.Error() != wantErr.Error()) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config differs from config.Load:\n got %+v\nwant %+v", got, want)
	}

	missing := filepath.Join(t.TempDir(), "nope.conf")
	_, wantErr = config.Load(missing)
	if _, err := loadKrb5Config(missing); err == nil || err.Error() != wantErr.Error() {
		t.Errorf("missing file: err = %v, want %v", err, wantErr)
	}
}

// MIT krb5 takes the first single value it meets (includes expanded in
// place) and merges a realm defined twice, keeping every kdc.
func TestLoadKrb5ConfigFirstValueWins(t *testing.T) {
	for _, tc := range []struct {
		name, main string
		realm      string
		kdcs       []string
	}{
		{
			name: "include before libdefaults",
			main: "include @INC@\n[libdefaults]\n  default_realm = MAIN.TEST\n  dns_lookup_kdc = true\n[realms]\n  INC.TEST = {\n    kdc = main.inc.test:88\n  }\n",
			// included file comes first
			realm: "INC.TEST",
			kdcs:  []string{"inc.inc.test:88", "main.inc.test:88"},
		},
		{
			name:  "include after libdefaults",
			main:  "[libdefaults]\n  default_realm = MAIN.TEST\n  dns_lookup_kdc = true\n[realms]\n  INC.TEST = {\n    kdc = main.inc.test:88\n  }\ninclude @INC@\n",
			realm: "MAIN.TEST",
			kdcs:  []string{"inc.inc.test:88", "main.inc.test:88"},
		},
		{
			name: "include inside libdefaults",
			// the lines after the include still belong to krb5.conf's [libdefaults]
			main:  "[libdefaults]\n  default_realm = MAIN.TEST\ninclude @INC@\n  dns_lookup_kdc = true\n",
			realm: "MAIN.TEST",
			kdcs:  []string{"inc.inc.test:88"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			inc := filepath.Join(dir, "inc.conf")
			writeKrb5File(t, inc, "[libdefaults]\n  default_realm = INC.TEST\n[realms]\n  INC.TEST = {\n    kdc = inc.inc.test:88\n  }\n[domain_realm]\n  .inc.test = INC.TEST\n")
			main := filepath.Join(dir, "krb5.conf")
			writeKrb5File(t, main, strings.ReplaceAll(tc.main, "@INC@", inc))

			cfg, err := loadKrb5Config(main)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LibDefaults.DefaultRealm != tc.realm {
				t.Errorf("default realm = %q, want %q", cfg.LibDefaults.DefaultRealm, tc.realm)
			}
			if !cfg.LibDefaults.DNSLookupKDC {
				t.Error("dns_lookup_kdc from krb5.conf lost")
			}
			if got := realmKDCs(t, cfg, "INC.TEST"); !reflect.DeepEqual(got, tc.kdcs) {
				t.Errorf("KDCs = %v, want %v", got, tc.kdcs)
			}
		})
	}

	t.Run("domain_realm", func(t *testing.T) {
		dir := t.TempDir()
		inc := filepath.Join(dir, "inc")
		writeKrb5File(t, inc, "[domain_realm]\n  .example.test = INC.TEST\n")
		main := filepath.Join(dir, "krb5.conf")
		writeKrb5File(t, main, "[domain_realm]\n  .example.test = MAIN.TEST\ninclude "+inc+"\n")

		cfg, err := loadKrb5Config(main)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.ResolveRealm("host.example.test"); got != "MAIN.TEST" {
			t.Errorf("ResolveRealm = %q, want MAIN.TEST", got)
		}
	})
}

func TestLoadKrb5ConfigNestedInclude(t *testing.T) {
	dir := t.TempDir()
	confd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confd, 0o750); err != nil {
		t.Fatal(err)
	}
	writeKrb5File(t, filepath.Join(confd, "realm.conf"), "[realms]\n  NEST.TEST = {\n    kdc = kdc.nest.test:88\n  }\n")
	mid := filepath.Join(dir, "mid")
	writeKrb5File(t, mid, "[libdefaults]\n  default_realm = NEST.TEST\nincludedir "+confd+"\n")
	main := filepath.Join(dir, "krb5.conf")
	writeKrb5File(t, main, "include "+mid+"\n")

	cfg, err := loadKrb5Config(main)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.DefaultRealm != "NEST.TEST" {
		t.Errorf("default realm = %q", cfg.LibDefaults.DefaultRealm)
	}
	if got := realmKDCs(t, cfg, "NEST.TEST"); !reflect.DeepEqual(got, []string{"kdc.nest.test:88"}) {
		t.Errorf("KDCs = %v", got)
	}
}

func TestLoadKrb5ConfigMissingIncludedir(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "krb5.conf.d")
	main := filepath.Join(dir, "krb5.conf")
	writeKrb5File(t, main, "includedir "+missing+"/\n[libdefaults]\n  default_realm = X.TEST\n")

	_, err := loadKrb5Config(main)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("err = %v, want an error naming %s", err, missing)
	}

	writeKrb5File(t, main, "include "+filepath.Join(dir, "gone")+"\n")
	if _, err := loadKrb5Config(main); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("missing include: err = %v", err)
	}
}

func TestLoadKrb5ConfigIncludeLoop(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	writeKrb5File(t, a, "include "+b+"\n")
	writeKrb5File(t, b, "include "+a+"\n")

	if _, err := loadKrb5Config(a); err == nil {
		t.Error("include loop: no error")
	}
}
