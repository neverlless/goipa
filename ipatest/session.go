// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import ipa "github.com/neverlless/goipa"

func init() {
	builtins["session_logout"] = func(s *Server, c Call) (any, *ipa.IpaError) { // Q39
		delete(s.sessions, c.session)
		s.expired[c.session] = true
		return map[string]any{"result": nil}, nil
	}
}
