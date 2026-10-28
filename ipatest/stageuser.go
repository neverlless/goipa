// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"

	ipa "github.com/neverlless/goipa"
)

// AddStageUser creates or replaces stage user uid, with the defaults of
// AddUser. A stage user is always locked.
func (s *Server) AddStageUser(uid string, u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putUser(true, uid, u)
}

// StageUser returns a copy of stage user uid.
func (s *Server) StageUser(uid string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.stage[uid]
	if !ok {
		return User{}, false
	}
	return r.User.clone(), true
}

// stageUserActivate implements Q30.
func stageUserActivate(s *Server, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArgIn(true, c)
	if err != nil {
		return nil, err
	}
	if s.users[uid] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("active user with name %q already exists", uid)}
	}
	u := r.User.clone()
	u.Locked = false
	if u.Password != "" { // Q160: the copied password is expired
		u.PasswdExpire = expiredNow()
	}
	delete(s.stage, uid)
	rec := s.putUser(false, uid, u)
	rec.uuid = r.uuid
	s.applyAutomember(uid)
	return entry(uid, rec.render(s, uid, false, true), fmt.Sprintf("Stage user %s activated", uid)), nil
}

func init() {
	builtins["stageuser_show"] = userShow(true)
	builtins["stageuser_find"] = userFind(true)
	builtins["stageuser_add"] = userAdd(true)
	builtins["stageuser_mod"] = userMod(true)
	builtins["stageuser_del"] = userDel(true)
	builtins["stageuser_activate"] = stageUserActivate
}
