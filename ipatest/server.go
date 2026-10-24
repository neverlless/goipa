// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	ipa "github.com/neverlless/goipa"
)

const (
	realm         = "TEST.LOCAL"
	serverVersion = "4.13.4"
)

// errorNames fills IpaError.Name when a handler leaves it empty.
var errorNames = map[int]string{
	ipa.CodeVersion:              "VersionError",
	ipa.CodeCommand:              "CommandError",
	ipa.CodeReferer:              "RefererError",
	ipa.CodeACI:                  "ACIError",
	ipa.CodeRequirement:          "RequirementError",
	ipa.CodeValidation:           "ValidationError",
	ipa.CodeNotFound:             "NotFound",
	ipa.CodeDuplicateEntry:       "DuplicateEntry",
	ipa.CodeAlreadyActive:        "AlreadyActive",
	ipa.CodeAlreadyInactive:      "AlreadyInactive",
	ipa.CodeNotGroupMember:       "NotGroupMember",
	ipa.CodeAlreadyGroupMember:   "AlreadyGroupMember",
	ipa.CodeAttrValueNotFound:    "AttrValueNotFound",
	ipa.CodeAlreadyContainsValue: "AlreadyContainsValueError",
	ipa.CodeEmptyModlist:         "EmptyModlist",
	ipa.CodeDatabase:             "DatabaseError",
}

// builtin is a modelled command. It runs with s.mu held.
type builtin func(s *Server, c Call) (any, *ipa.IpaError)

// builtins is filled from init functions, one file per object type.
var builtins = map[string]builtin{
	"ping": func(*Server, Call) (any, *ipa.IpaError) {
		return map[string]any{"summary": "IPA server version " + serverVersion + ". API version 2.257"}, nil
	},
}

// forms holds the non-JSON-RPC endpoints (login_password, change_password)
// by path. They run with s.mu held, after the Referer check.
var forms = map[string]func(s *Server, w http.ResponseWriter, r *http.Request){}

// Call is one JSON-RPC request the server accepted.
type Call struct {
	Method string
	// Args are the positional arguments; non-string ones are flattened with
	// fmt.Sprint.
	Args []string
	// Options are the decoded JSON options: numbers are float64, lists []any,
	// datetimes map[string]any{"__datetime__": ...}.
	Options map[string]any
	// User is the authenticated caller's uid.
	User string
}

func (c Call) clone() Call {
	c.Args = slices.Clone(c.Args)
	c.Options = maps.Clone(c.Options)
	return c
}

// HandlerFunc serves one JSON-RPC method. result is the whole command output
// and is placed verbatim under the envelope's "result"; a non-nil err fails
// the call instead.
type HandlerFunc func(c Call) (result any, err *ipa.IpaError)

// Server is an in-memory fake FreeIPA served over TLS on 127.0.0.1.
// Separate servers share no state.
type Server struct {
	srv *httptest.Server

	mu        sync.Mutex
	sessions  map[string]string // session id -> uid
	expired   map[string]bool   // session ids from ExpireSession
	negotiate string
	calls     []Call
	handlers  map[string]HandlerFunc
	users     map[string]*userRec
	stage     map[string]*userRec
	groups    map[string]*groupRec
	hosts     map[string]Host
	hbac      map[string]*hbacRec
	sudo      map[string]*sudoRec
	tokens    []*OTPToken
	nextID    int // last uidnumber handed out
	nextGID   int // last gidnumber handed out
}

// NewServer starts a server and closes it with tb.Cleanup.
func NewServer(tb testing.TB) *Server {
	tb.Helper()
	s := New()
	tb.Cleanup(s.Close)
	return s
}

// New starts a server for use outside tests (examples, local development).
// Call Close when done.
func New() *Server {
	s := &Server{
		sessions: map[string]string{},
		expired:  map[string]bool{},
		handlers: map[string]HandlerFunc{},
		users:    map[string]*userRec{},
		stage:    map[string]*userRec{},
		groups:   map[string]*groupRec{},
		hosts:    map[string]Host{serverFQDN: {HasKeytab: true}},
		hbac:     seedAllowAll(),
		sudo:     map[string]*sudoRec{},
		nextID:   firstID - 1,
		nextGID:  firstID - 1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ipa/session/json", s.serveSessionJSON)
	mux.HandleFunc("/ipa/json", s.serveNegotiateJSON)
	for path, h := range forms {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !s.refererOK(r) {
				denied(w)
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			h(s, w, r)
		})
	}
	s.srv = httptest.NewTLSServer(mux)
	return s
}

// Close shuts the server down. It is safe to call more than once.
func (s *Server) Close() { s.srv.Close() }

// URL returns the base URL, https://127.0.0.1:PORT.
func (s *Server) URL() string { return s.srv.URL }

// Host returns 127.0.0.1:PORT, the host goipa clients take.
func (s *Server) Host() string { return strings.TrimPrefix(s.srv.URL, "https://") }

// Realm returns the Kerberos realm, TEST.LOCAL.
func (s *Server) Realm() string { return realm }

// HTTPClient returns an HTTP client that trusts only this server.
func (s *Server) HTTPClient() *http.Client { return s.srv.Client() }

// Client returns a goipa client wired to the server, without a session.
func (s *Server) Client() *ipa.Client {
	return ipa.NewClientCustomHttp(s.Host(), realm, s.HTTPClient())
}

// ClientAs returns a client that already holds a session for uid. uid need
// not be a seeded user, e.g. "admin".
func (s *Server) ClientAs(uid string) *ipa.Client {
	c := s.Client()
	c.SetSessionID(s.Session(uid))
	return c
}

// Session issues a new session id for uid, in the form ipa.Client stores it
// ("MagBearerToken=...").
func (s *Server) Session(uid string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newSession(uid)
}

// ExpireSession ends session sid. Calls with it get HTTP 401, FreeIPA's answer
// for an expired session, which mod_session treats as no session.
func (s *Server) ExpireSession(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
	s.expired[sid] = true
}

// newSession needs s.mu held.
func (s *Server) newSession(uid string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails, see crypto/rand.Read
	sid := "MagBearerToken=" + base64.RawURLEncoding.EncodeToString(b)
	s.sessions[sid] = uid
	return sid
}

func setSessionCookie(w http.ResponseWriter, sid string) {
	w.Header().Set("Set-Cookie", "ipa_session="+sid+"; Path=/ipa; Secure; HttpOnly")
}

// SetNegotiateUser makes /ipa/json, the endpoint goipa uses without a
// session (Kerberos), accept every call as uid, standing in for SPNEGO.
// The default "" answers 401 like a server that gets no ticket.
func (s *Server) SetNegotiateUser(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.negotiate = uid
}

// Calls returns a copy of every JSON-RPC call accepted so far, in order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Call, len(s.calls))
	for i, c := range s.calls {
		out[i] = c.clone()
	}
	return out
}

// Handle makes fn serve method in place of the built-in command, or of the
// 905 CommandError an unmodelled method gets. A nil fn removes the override.
// fn runs without the server lock held, so it may call any Server method.
func (s *Server) Handle(method string, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fn == nil {
		delete(s.handlers, method)
		return
	}
	s.handlers[method] = fn
}

// denied is FreeIPA's answer to a missing or foreign Referer (Q12).
func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = io.WriteString(w, "<html>\n<head>\n<title>400 Bad Request</title>\n</head>\n<body>\n<h1>Bad Request</h1>\n<p>\n<strong>denied</strong>\n</p>\n</body>\n</html>")
}

func (s *Server) refererOK(r *http.Request) bool {
	return strings.HasPrefix(r.Referer(), "https://"+r.Host+"/ipa")
}

func (s *Server) serveSessionJSON(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("ipa_session")
	var uid string
	ok, expired := false, false
	if err == nil {
		s.mu.Lock()
		uid, ok = s.sessions[ck.Value]
		expired = s.expired[ck.Value]
		s.mu.Unlock()
	}
	if !ok && !expired && err == nil && strings.HasPrefix(ck.Value, "MagBearerToken=") && ck.Value != "MagBearerToken=" {
		dropConnection(w) // Q13
		return
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.serveRPC(w, r, uid)
}

// dropConnection closes the connection without a response, as the httpd
// child of a real server does when it crashes on a token it cannot decrypt.
func dropConnection(http.ResponseWriter) {
	panic(http.ErrAbortHandler)
}

func (s *Server) serveNegotiateJSON(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	uid := s.negotiate
	sid := ""
	if uid != "" {
		sid = s.newSession(uid)
	}
	s.mu.Unlock()
	if uid == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	setSessionCookie(w, sid)
	s.serveRPC(w, r, uid)
}

func (s *Server) serveRPC(w http.ResponseWriter, r *http.Request, uid string) {
	if !s.refererOK(r) {
		denied(w)
		return
	}

	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	c := Call{User: uid, Options: map[string]any{}}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	if err == nil && len(req.Params) > 0 {
		var args []any
		if err = json.Unmarshal(req.Params[0], &args); err == nil {
			for _, a := range args {
				if str, ok := a.(string); ok {
					c.Args = append(c.Args, str)
				} else {
					c.Args = append(c.Args, fmt.Sprint(a))
				}
			}
		}
	}
	if err == nil && len(req.Params) > 1 {
		err = json.Unmarshal(req.Params[1], &c.Options)
	}
	if c.Options == nil { // params[1] was null
		c.Options = map[string]any{}
	}
	if err != nil {
		http.Error(w, "bad JSON-RPC request: "+err.Error(), http.StatusBadRequest)
		return
	}
	c.Method = req.Method

	s.mu.Lock()
	s.calls = append(s.calls, c.clone())
	h := s.handlers[c.Method]
	s.mu.Unlock()

	var result any
	var ierr *ipa.IpaError
	if h != nil {
		result, ierr = h(c)
	} else if b := builtins[c.Method]; b != nil {
		s.mu.Lock()
		result, ierr = b(s, c)
		s.mu.Unlock()
	} else {
		ierr = &ipa.IpaError{Code: ipa.CodeCommand, Message: fmt.Sprintf("unknown command '%s'", c.Method)}
	}
	if ierr != nil {
		result = nil
	}
	writeEnvelope(w, uid, result, ierr)
}

func writeEnvelope(w http.ResponseWriter, uid string, result any, ierr *ipa.IpaError) {
	if ierr != nil && ierr.Name == "" {
		e := *ierr
		e.Name = errorNames[e.Code]
		ierr = &e
	}
	b, err := json.Marshal(struct {
		Result    any           `json:"result"`
		Error     *ipa.IpaError `json:"error"`
		ID        int           `json:"id"`
		Principal string        `json:"principal"`
		Version   string        `json:"version"`
	}{result, ierr, 0, uid + "@" + realm, serverVersion})
	if err != nil {
		http.Error(w, "cannot encode result: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// entry is the output of *_show, *_add and *_mod.
func entry(pkey string, rec map[string]any, summary string) map[string]any {
	return map[string]any{"result": rec, "value": pkey, "summary": summary}
}

// list is the output of *_find.
func list(recs []map[string]any) map[string]any {
	return map[string]any{
		"result":    recs,
		"count":     len(recs),
		"truncated": false,
		"summary":   fmt.Sprintf("%d entries returned", len(recs)),
	}
}

func notFound(pkey, object string) *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeNotFound, Name: "NotFound", Message: pkey + ": " + object + " not found"}
}

func required(name string) *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeRequirement, Name: "RequirementError", Message: "'" + name + "' is required"}
}
