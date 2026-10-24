// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
)

const (
	firstID     = 1000000 // first uidnumber, as FreeIPA's default ID range
	baseDN      = "cn=users,cn=accounts,dc=test,dc=local"
	stageBaseDN = "cn=staged users,cn=accounts,cn=provisioning,dc=test,dc=local"
)

// User is a user account of the fake server.
type User struct {
	Password          string   // "" = no password: login always invalid-password, has_password false
	Locked            bool     // nsaccountlock (user_disable)
	Preserved         bool     // set by user_del preserve=true
	Groups            []string // memberof_group
	AuthTypes         []string // ipauserauthtype
	Email             string   // first mail value
	Emails            []string // all mail values; when set it is rendered instead of Email
	First             string
	Last              string
	DisplayName       string
	Category          string
	Telephone         string
	Mobile            string
	Shell             string
	HomeDir           string
	SSHPubKeys        []string // ipasshpubkey, authorized_keys lines
	Passkeys          []string // ipapasskey
	Street            string   // street, l, st, postalcode and preferredlanguage need all: true
	City              string
	State             string
	PostalCode        string
	PreferredLanguage string
	Title             string
	OrgUnit           string
	FailedLogins      int
	LastFailedLogin   time.Time // krblastfailedauth, set by a wrong password
	PasswdExpire      time.Time // krbpasswordexpiration; non-zero and not after now = expired
}

// userRec is a stored user plus the attributes the server assigns.
type userRec struct {
	User
	id    int // 0 = none yet: a stage user has no uidnumber until activated
	uuid  string
	stage bool
}

// clone also turns empty slices into nil, so Q11's DeepEqual sees
// []string{} and nil as the same unchanged attribute.
func (u User) clone() User {
	u.Groups = cloneStrs(u.Groups)
	u.AuthTypes = cloneStrs(u.AuthTypes)
	u.SSHPubKeys = cloneStrs(u.SSHPubKeys)
	u.Emails = cloneStrs(u.Emails)
	u.Passkeys = cloneStrs(u.Passkeys)
	return u
}

func cloneStrs(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Clone(s)
}

// AddUser creates or replaces user uid. Empty fields get defaults: Email
// uid@example.com, First "Test", Last "User", HomeDir /home/uid, Shell /bin/sh.
func (s *Server) AddUser(uid string, u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putUser(false, uid, u)
}

// store is the active or the stage user map.
func (s *Server) store(stage bool) map[string]*userRec {
	if stage {
		return s.stage
	}
	return s.users
}

// putUser needs s.mu held. A replaced user keeps its ids.
func (s *Server) putUser(stage bool, uid string, u User) *userRec {
	u = u.clone()
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	if u.Email == "" && len(u.Emails) > 0 {
		u.Email = u.Emails[0]
	}
	def(&u.Email, uid+"@example.com")
	def(&u.First, "Test")
	def(&u.Last, "User")
	def(&u.HomeDir, "/home/"+uid)
	def(&u.Shell, "/bin/sh")
	r := s.store(stage)[uid]
	if r == nil {
		r = &userRec{uuid: newUUID(), stage: stage}
		if !stage {
			s.nextID++
			r.id = s.nextID
		}
		s.store(stage)[uid] = r
	}
	if stage {
		u.Locked = true
	}
	r.User = u
	return r
}

// User returns a copy of user uid.
func (s *Server) User(uid string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.users[uid]
	if !ok {
		return User{}, false
	}
	return r.User.clone(), true
}

// UpdateUser runs fn on a copy of user uid and stores the result. It reports
// whether the user exists. fn runs without the server lock held.
func (s *Server) UpdateUser(uid string, fn func(*User)) bool {
	u, ok := s.User(uid)
	if !ok {
		return false
	}
	fn(&u)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.users[uid]
	if ok {
		r.User = u.clone()
	}
	return ok
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// render is the user record as FreeIPA's JSON API returns it (Q16): LDAP
// attributes are lists, nsaccountlock, has_password, has_keytab, preserved
// and randompassword are scalars, datetimes are {"__datetime__": ...}.
func (r *userRec) render(s *Server, uid string, find, all bool) map[string]any {
	dn := "uid=" + uid + "," + baseDN
	if r.stage {
		dn = "uid=" + uid + "," + stageBaseDN
	}
	out := map[string]any{
		"dn":               dn,
		"uid":              []string{uid},
		"krbprincipalname": []string{uid + "@" + realm},
		"ipauniqueid":      []string{r.uuid},
		"nsaccountlock":    r.Locked,
		"has_password":     r.Password != "",
		"has_keytab":       false,
		"preserved":        r.Preserved,
	}
	if r.id != 0 {
		out["uidnumber"], out["gidnumber"] = []string{strconv.Itoa(r.id)}, []string{strconv.Itoa(r.id)}
	}
	if r.stage { // DNA magic value, set by stageuser_add.pre_callback; the DNA plugin skips staged users
		out["uidnumber"], out["gidnumber"] = []string{"-1"}, []string{"-1"}
	}
	for k, v := range map[string][]string{
		"givenname":       {r.First},
		"sn":              {r.Last},
		"displayname":     {r.DisplayName},
		"mail":            r.mails(),
		"homedirectory":   {r.HomeDir},
		"loginshell":      {r.Shell},
		"telephonenumber": {r.Telephone},
		"mobile":          {r.Mobile},
		"userclass":       {r.Category},
		"ipasshpubkey":    r.SSHPubKeys,
		"ipauserauthtype": r.AuthTypes,
		"ipapasskey":      r.Passkeys,
		"title":           {r.Title},
		"ou":              {r.OrgUnit},
	} {
		v = slices.DeleteFunc(slices.Clone(v), func(s string) bool { return s == "" })
		if len(v) > 0 {
			out[k] = v
		}
	}
	if all { // U4
		for k, v := range map[string]string{"street": r.Street, "l": r.City, "st": r.State,
			"postalcode": r.PostalCode, "preferredlanguage": r.PreferredLanguage} {
			if v != "" {
				out[k] = []string{v}
			}
		}
	}
	if r.stage {
		return out
	}
	direct := s.userGroups(uid, r)
	indirect := s.ancestors(direct)
	if find { // U2
		if all {
			direct, indirect = append(direct, indirect...), nil
		} else {
			indirect = nil
		}
	}
	if len(direct) > 0 {
		out["memberof_group"] = direct
	}
	if len(indirect) > 0 {
		out["memberofindirect_group"] = indirect
	}
	if !r.PasswdExpire.IsZero() {
		out["krbpasswordexpiration"] = []map[string]string{{"__datetime__": r.PasswdExpire.UTC().Format(ipa.IpaDatetimeFormat)}}
	}
	return out
}

// mails is the mail attribute: Emails, else the single Email.
func (u User) mails() []string {
	if len(u.Emails) > 0 {
		return u.Emails
	}
	return []string{u.Email}
}

// strs reads an option that is a string or a list of strings; "" is no value.
func strs(v any) []string {
	var out []string
	switch v := v.(type) {
	case string:
		out = []string{v}
	case []any:
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
	}
	return cloneStrs(slices.DeleteFunc(out, func(s string) bool { return s == "" }))
}

func str(v any) string {
	if s := strs(v); len(s) > 0 {
		return s[0]
	}
	return ""
}

func flag(c Call, name string) bool {
	b, _ := c.Options[name].(bool)
	return b
}

// apply sets the user attributes present in opts, the ones ToOptions sends
// plus ipauserauthtype. An empty value clears the attribute.
func (u *User) apply(opts map[string]any) {
	for k, v := range opts {
		switch k {
		case "mail": // replaces the whole set (U5)
			u.Email, u.Emails = str(v), strs(v)
			if len(u.Emails) < 2 {
				u.Emails = nil
			}
		case "givenname":
			u.First = str(v)
		case "sn":
			u.Last = str(v)
		case "homedirectory":
			u.HomeDir = str(v)
		case "loginshell":
			u.Shell = str(v)
		case "displayname":
			u.DisplayName = str(v)
		case "telephonenumber":
			u.Telephone = str(v)
		case "mobile":
			u.Mobile = str(v)
		case "userclass":
			u.Category = str(v)
		case "street":
			u.Street = str(v)
		case "l":
			u.City = str(v)
		case "st":
			u.State = str(v)
		case "postalcode":
			u.PostalCode = str(v)
		case "preferredlanguage":
			u.PreferredLanguage = str(v)
		case "title":
			u.Title = str(v)
		case "ou":
			u.OrgUnit = str(v)
		case "ipasshpubkey":
			u.SSHPubKeys = strs(v)
		case "ipauserauthtype":
			u.AuthTypes = strs(v)
		}
	}
}

// attrVals is the current values of an attribute apply knows, ok false if it
// does not know it.
func (u *User) attrVals(attr string) (vals []string, ok bool) {
	one := map[string]*string{"givenname": &u.First, "sn": &u.Last, "homedirectory": &u.HomeDir,
		"loginshell": &u.Shell, "displayname": &u.DisplayName, "telephonenumber": &u.Telephone,
		"mobile": &u.Mobile, "userclass": &u.Category, "street": &u.Street, "l": &u.City, "st": &u.State,
		"postalcode": &u.PostalCode, "preferredlanguage": &u.PreferredLanguage, "title": &u.Title, "ou": &u.OrgUnit}
	switch p := one[attr]; {
	case p != nil:
		return strs(*p), true
	case attr == "mail":
		return slices.DeleteFunc(slices.Clone(u.mails()), func(v string) bool { return v == "" }), true
	case attr == "ipasshpubkey":
		return u.SSHPubKeys, true
	case attr == "ipauserauthtype":
		return u.AuthTypes, true
	}
	return nil, false
}

// applyAttrOpts is Q41: setattr, then addattr, then delattr, as FreeIPA's
// process_attr_options does.
func (u *User) applyAttrOpts(opts map[string]any) *ipa.IpaError {
	type kv struct{ attr, val string }
	parse := func(name string) (out []kv) {
		for _, e := range strs(opts[name]) {
			a, v, _ := strings.Cut(e, "=")
			out = append(out, kv{strings.ToLower(strings.TrimSpace(a)), strings.TrimSpace(v)})
		}
		return out
	}
	set, add, del := parse("setattr"), parse("addattr"), parse("delattr")
	for _, l := range [][]kv{set, add, del} {
		for _, e := range l {
			if _, ok := u.attrVals(e.attr); !ok {
				return &ipa.IpaError{Code: ipa.CodeValidation, Name: "ValidationError", Message: fmt.Sprintf("invalid '%s': attribute not allowed", e.attr)}
			}
		}
	}
	vals := map[string][]string{}
	cur := func(attr string) []string {
		if v, ok := vals[attr]; ok {
			return v
		}
		v, _ := u.attrVals(attr)
		return slices.Clone(v)
	}
	for _, e := range set { // values of one attribute accumulate, "" adds none
		if _, ok := vals[e.attr]; !ok {
			vals[e.attr] = nil
		}
		if e.val != "" {
			vals[e.attr] = append(vals[e.attr], e.val)
		}
	}
	for _, e := range add {
		if slices.Contains(cur(e.attr), e.val) {
			return &ipa.IpaError{Code: ipa.CodeAlreadyContainsValue, Name: "AlreadyContainsValue", Message: fmt.Sprintf("'%s' already contains '%s'", e.attr, e.val)}
		}
		vals[e.attr] = append(cur(e.attr), e.val)
	}
	for _, e := range del {
		v := cur(e.attr)
		i := slices.Index(v, e.val)
		if i < 0 {
			return &ipa.IpaError{Code: ipa.CodeAttrValueNotFound, Name: "AttrValueNotFound", Message: fmt.Sprintf("'%s' does not contain '%s'", e.attr, e.val)}
		}
		vals[e.attr] = slices.Delete(v, i, i+1)
	}
	merged := map[string]any{}
	for a, v := range vals {
		if len(v) > 1 && a != "mail" && a != "ipasshpubkey" && a != "ipauserauthtype" {
			return &ipa.IpaError{Code: 4207, Name: "OnlyOneValueAllowed", Message: a + ": Only one value allowed."}
		}
		l := make([]any, len(v))
		for i := range v {
			l[i] = v[i]
		}
		merged[a] = l
	}
	u.apply(merged)
	return nil
}

// uidArg is the primary key every user command takes.
func uidArg(c Call) (string, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", required("uid")
	}
	return c.Args[0], nil
}

// userArg looks up the active user c names.
func (s *Server) userArg(c Call) (string, *userRec, *ipa.IpaError) {
	return s.userArgIn(false, c)
}

func (s *Server) userArgIn(stage bool, c Call) (string, *userRec, *ipa.IpaError) {
	uid, err := uidArg(c)
	if err != nil {
		return "", nil, err
	}
	r := s.store(stage)[uid]
	if r == nil {
		return "", nil, notFound(uid, userObject(stage))
	}
	return uid, r, nil
}

// userObject names the entry type in messages.
func userObject(stage bool) string {
	if stage {
		return "stage user"
	}
	return "user"
}

const pwdMaxLife = 90 * 24 * time.Hour // krbmaxpwdlife

// expiredNow is "now" as FreeIPA stores krbpasswordexpiration: UTC, whole seconds.
func expiredNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// withRandom implements Q3: random=true sets a random password, returned in
// this response only, and expired.
func (r *userRec) withRandom(s *Server, c Call, uid string) map[string]any {
	random := flag(c, "random")
	if random {
		r.Password, r.PasswdExpire = randomPassword(), expiredNow()
	}
	rec := r.render(s, uid, false, flag(c, "all"))
	if random {
		rec["randompassword"] = r.Password
	}
	return rec
}

func userShow(stage bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) { return s.userShow(stage, c) }
}

func (s *Server) userShow(stage bool, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArgIn(stage, c)
	if err != nil {
		return nil, err
	}
	return entry(uid, r.render(s, uid, false, flag(c, "all")), ""), nil
}

func userFind(stage bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) { return s.userFind(stage, c) }
}

func (s *Server) userFind(stage bool, c Call) (any, *ipa.IpaError) {
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	all := flag(c, "all")
	var uids []string
	for uid, r := range s.store(stage) {
		if r.Preserved != flag(c, "preserved") {
			continue
		}
		if needle != "" && !slices.ContainsFunc(append([]string{uid, r.First, r.Last}, r.mails()...), func(v string) bool {
			return strings.Contains(strings.ToLower(v), needle)
		}) {
			continue
		}
		if !matches(c, "uid", uid) || !matchesAny(c, "mail", r.mails()) || !matches(c, "givenname", r.First) || !matches(c, "sn", r.Last) {
			continue
		}
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	recs := make([]map[string]any, 0, len(uids))
	for _, uid := range uids {
		rec := s.store(stage)[uid].render(s, uid, true, all)
		if !all { // Q1, Q28
			delete(rec, "userclass")
		}
		recs = append(recs, rec)
	}
	return listLimited(c, recs), nil
}

func matches(c Call, opt, have string) bool {
	v, ok := c.Options[opt]
	return !ok || str(v) == have
}

func matchesAny(c Call, opt string, have []string) bool {
	v, ok := c.Options[opt]
	return !ok || slices.Contains(have, str(v))
}

func userAdd(stage bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) { return s.userAdd(stage, c) }
}

func (s *Server) userAdd(stage bool, c Call) (any, *ipa.IpaError) {
	uid, err := uidArg(c)
	if err != nil {
		return nil, err
	}
	if s.store(stage)[uid] != nil { // Q10, Q29
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("%s with name %q already exists", userObject(stage), uid)}
	}
	if err := emptyHomeDir(c); err != nil {
		return nil, err
	}
	var u User
	u.apply(c.Options)
	if u.First == "" {
		return nil, required("givenname")
	}
	if u.Last == "" {
		return nil, required("sn")
	}
	rec := s.putUser(stage, uid, u).withRandom(s, c, uid)
	return entry(uid, rec, fmt.Sprintf("Added %s %q", userObject(stage), uid)), nil
}

func userMod(stage bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) { return s.userMod(stage, c) }
}

// emptyHomeDir is Q19: "" means no value and posixAccount requires one.
func emptyHomeDir(c Call) *ipa.IpaError {
	if v, ok := c.Options["homedirectory"]; ok && str(v) == "" {
		return &ipa.IpaError{Code: 4205, Name: "ObjectclassViolation", Message: `missing attribute "homeDirectory" required by object class "posixAccount"`}
	}
	return nil
}

func (s *Server) userMod(stage bool, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArgIn(stage, c)
	if err != nil {
		return nil, err
	}
	if err := emptyHomeDir(c); err != nil {
		return nil, err
	}
	next := r.User.clone()
	next.apply(c.Options) // empty strings clear attributes, as in FreeIPA
	if err := next.applyAttrOpts(c.Options); err != nil {
		return nil, err
	}
	if next.First == "" {
		return nil, required("givenname")
	}
	if next.Last == "" {
		return nil, required("sn")
	}
	random := flag(c, "random")
	if !random && reflect.DeepEqual(next, r.User) { // Q11
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	r.User = next
	rec := r.withRandom(s, c, uid)
	return entry(uid, rec, fmt.Sprintf("Modified %s %q", userObject(stage), uid)), nil
}

func userDel(stage bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) { return s.userDel(stage, c) }
}

func (s *Server) userDel(stage bool, c Call) (any, *ipa.IpaError) {
	users := s.store(stage)
	var deleted, failed []string
	for _, uid := range c.Args {
		if users[uid] == nil {
			if !flag(c, "continue") {
				return nil, notFound(uid, userObject(stage))
			}
			failed = append(failed, uid)
		} else {
			deleted = append(deleted, uid)
		}
	}
	for _, uid := range deleted {
		if !stage {
			for _, g := range s.groups { // referential integrity, also when preserved
				g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == uid })
				g.ManagerUsers = slices.DeleteFunc(g.ManagerUsers, func(m string) bool { return m == uid })
			}
			s.dropFromRules(uid, false)
		}
		if !stage && flag(c, "preserve") {
			users[uid].Preserved, users[uid].Locked = true, true
		} else {
			delete(users, uid)
			if !stage {
				delete(s.subids, uid) // Q33
			}
		}
	}
	if failed == nil {
		failed = []string{}
	}
	if deleted == nil {
		deleted = []string{}
	}
	return map[string]any{
		"result":  map[string]any{"failed": failed},
		"value":   deleted,
		"summary": fmt.Sprintf("Deleted %s %q", userObject(stage), strings.Join(deleted, ",")),
	}, nil
}

// setLocked implements user_disable and user_enable, Q17.
func setLocked(lock bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		uid, r, err := s.userArg(c)
		if err != nil {
			return nil, err
		}
		if r.Locked == lock {
			if lock {
				return nil, &ipa.IpaError{Code: ipa.CodeAlreadyInactive, Message: "This entry is already disabled"}
			}
			return nil, &ipa.IpaError{Code: ipa.CodeAlreadyActive, Message: "This entry is already enabled"}
		}
		r.Locked = lock
		verb := "Enabled"
		if lock {
			verb = "Disabled"
		}
		return map[string]any{"result": true, "value": uid, "summary": fmt.Sprintf("%s user account %q", verb, uid)}, nil
	}
}

func passwd(s *Server, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArg(c)
	if err != nil {
		return nil, err
	}
	if cur, ok := c.Options["current_password"]; ok && (r.Password == "" || str(cur) != r.Password) { // Q9
		return nil, &ipa.IpaError{Code: ipa.CodeACI, Message: "Insufficient access: Invalid credentials"}
	}
	pw := str(c.Options["password"])
	if pw == "" {
		return nil, required("password")
	}
	r.Password = pw
	if c.User == uid { // Q3: a password set by someone else is expired
		r.PasswdExpire = expiredNow().Add(pwdMaxLife)
	} else {
		r.PasswdExpire = expiredNow()
	}
	return map[string]any{"result": true, "value": uid, "summary": fmt.Sprintf("Changed password for %q", uid)}, nil
}

func loginPassword(s *Server, w http.ResponseWriter, r *http.Request) {
	uid, pw := r.FormValue("user"), r.FormValue("password")
	reject := func(reason string) {
		w.Header().Set("X-IPA-Rejection-Reason", reason)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	u := s.users[uid]
	switch {
	case u == nil || u.Password == "":
		reject("invalid-password")
	case u.Locked || u.Preserved || (s.pwpol[globalPolicy].MaxFailures > 0 && u.FailedLogins >= s.pwpol[globalPolicy].MaxFailures): // Q6, Q32
		reject("user-locked")
	case u.Password != pw:
		u.FailedLogins++
		u.LastFailedLogin = time.Now()
		reject("invalid-password")
	case !u.PasswdExpire.IsZero() && !u.PasswdExpire.After(time.Now()): // Q5
		reject("password-expired")
	default:
		u.FailedLogins = 0
		setSessionCookie(w, s.newSession(uid))
	}
}

func changePassword(s *Server, w http.ResponseWriter, r *http.Request) {
	u := s.users[r.FormValue("user")]
	newPw := r.FormValue("new_password")
	result := "ok"
	switch {
	case u == nil || u.Password == "" || u.Password != r.FormValue("old_password"):
		result = "invalid-password"
	case len(newPw) < s.pwpol[globalPolicy].MinLength:
		result = "policy-error"
		w.Header().Set("X-IPA-Pwchange-Policy-Error", "Constraint violation: Password is too short")
	default:
		u.Password, u.PasswdExpire = newPw, expiredNow().Add(pwdMaxLife)
	}
	w.Header().Set("X-IPA-Pwchange-Result", result)
}

func syncToken(s *Server, w http.ResponseWriter, r *http.Request) {
	for _, k := range []string{"user", "password", "first_code", "second_code"} {
		if r.FormValue(k) == "" {
			http.Error(w, "<html><body>Bad Request</body></html>", http.StatusBadRequest)
			return
		}
	}
	uid, c1, c2 := r.FormValue("user"), r.FormValue("first_code"), r.FormValue("second_code")
	u := s.users[uid]
	ok := false
	if u != nil && u.Password != "" && u.Password == r.FormValue("password") {
		for _, t := range s.tokens {
			if t.Owner == uid && !t.Disabled && (r.FormValue("token") == "" || t.UUID == r.FormValue("token")) &&
				len(c1) == t.Digits && len(c2) == t.Digits && isDigits(c1) && isDigits(c2) {
				ok = true
			}
		}
	}
	result := "ok"
	if !ok {
		result = "invalid-credentials"
	}
	w.Header().Set("X-IPA-TokenSync-Result", result)
}

func isDigits(v string) bool {
	return strings.Trim(v, "0123456789") == ""
}

func init() {
	forms["/ipa/session/sync_token"] = syncToken
	builtins["user_show"] = userShow(false)
	builtins["user_find"] = userFind(false)
	builtins["user_add"] = userAdd(false)
	builtins["user_mod"] = userMod(false)
	builtins["user_del"] = userDel(false)
	builtins["user_disable"] = setLocked(true)
	builtins["user_enable"] = setLocked(false)
	builtins["passwd"] = passwd
	forms["/ipa/session/login_password"] = loginPassword
	forms["/ipa/session/change_password"] = changePassword
}
