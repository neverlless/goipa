// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"fmt"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func ExampleNewServer() {
	s := ipatest.New() // in a test: ipatest.NewServer(t)
	defer s.Close()

	res, err := s.ClientAs("admin").Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println(res.Principal)
	// Output: admin@TEST.LOCAL
}

func ExampleServer_Handle() {
	s := ipatest.New()
	defer s.Close()
	s.Handle("user_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4001, Message: "jesse: user not found"}
	})
	_, err := s.ClientAs("admin").UserShow("jesse")
	fmt.Println(errors.Is(err, ipa.ErrNotFound))
	// Output: true
}
