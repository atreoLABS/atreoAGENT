package smtp

import (
	"context"
	"strings"
	"sync"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime/v2"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
)

// TestInlineCIDs_RewritesKnownCID confirms cid: src attributes get
// replaced with data: URIs only when the cid is present in the inlines
// map. Unknown cids are left alone.
func TestInlineCIDs_RewritesKnownCID(t *testing.T) {
	html := `<p>look: <img src="cid:foo@bar"> <img src="cid:unknown"></p>`
	inlines := []*enmime.Part{
		{
			ContentID:   "<foo@bar>",
			ContentType: "image/png",
			Content:     []byte("PNG-FAKE-BYTES"),
		},
	}
	got := inlineCIDs(html, inlines)
	if !strings.Contains(got, "data:image/png;base64,") {
		t.Errorf("expected cid:foo@bar to be rewritten as data: URI, got %q", got)
	}
	if !strings.Contains(got, "cid:unknown") {
		t.Errorf("expected cid:unknown to be left in place (no inline match), got %q", got)
	}
}

func TestInlineCIDs_NoInlines(t *testing.T) {
	html := `<p><img src="cid:foo"></p>`
	if got := inlineCIDs(html, nil); got != html {
		t.Errorf("expected unchanged html when no inlines, got %q", got)
	}
}

func TestHTMLToPreview_StripsTags(t *testing.T) {
	html := `<p>Hello <b>world</b></p><br><span style="color:red">&nbsp;there</span>`
	got := htmlToPreview(html)
	if got != "Hello world &nbsp;there" {
		t.Errorf("htmlToPreview: got %q", got)
	}
}

// Token-bucket unit tests live with the implementation in internal/ratelimit;
// the gateway's wrapper (newIPLimiter/reap) is exercised via the server tests.

// --- Rcpt routing ----------------------------------------------------------

// fakeNotify satisfies notifySender for tests. APIKey is mutable so the
// rotation test can swap it under a live session; SendToMember records
// the last dispatch so the STARTTLS integration test can assert it.
type fakeNotify struct {
	mu         sync.Mutex
	key        string
	sent       int
	lastMember *atreolink.MemberACLEntry
	lastReq    *notify.NotifyRequest
}

func (f *fakeNotify) APIKey() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key
}

func (f *fakeNotify) setKey(k string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = k
}

func (f *fakeNotify) SendToMember(_ context.Context, m *atreolink.MemberACLEntry, req *notify.NotifyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent++
	f.lastMember = m
	f.lastReq = req
	return nil
}

func (f *fakeNotify) snapshot() (int, *atreolink.MemberACLEntry, *notify.NotifyRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent, f.lastMember, f.lastReq
}

func newSessionFor(t *testing.T, members []atreolink.MemberACLEntry) *session {
	t.Helper()
	store := acl.NewStore("")
	if err := store.ReplaceAll(members); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	return &session{server: &Server{cfg: Config{}, acl: store, notify: &fakeNotify{}}}
}

func newAuthedSessionFor(t *testing.T, members []atreolink.MemberACLEntry) *session {
	t.Helper()
	s := newSessionFor(t, members)
	s.authed = true
	return s
}

func TestRcpt_FullEmailMatch(t *testing.T) {
	s := newSessionFor(t, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com"},
	})
	if err := s.Rcpt("alice@example.com", nil); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if s.recipient == nil || s.recipient.MemberID != "m1" {
		t.Errorf("unexpected recipient: %+v", s.recipient)
	}
}

func TestRcpt_FullEmailMatch_CaseInsensitive(t *testing.T) {
	s := newSessionFor(t, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com"},
	})
	if err := s.Rcpt("ALICE@EXAMPLE.COM", nil); err != nil {
		t.Fatalf("expected accept on case-folded address, got %v", err)
	}
	if s.recipient == nil || s.recipient.MemberID != "m1" {
		t.Errorf("unexpected recipient: %+v", s.recipient)
	}
}

func TestRcpt_UnknownRecipient(t *testing.T) {
	s := newSessionFor(t, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com"},
	})
	err := s.Rcpt("ghost@example.com", nil)
	se, ok := err.(*gosmtp.SMTPError)
	if !ok || se.Code != 550 || se.EnhancedCode != (gosmtp.EnhancedCode{5, 1, 1}) {
		t.Errorf("expected 550 5.1.1 unknown, got %v", err)
	}
}

func TestRcpt_MultipleRcptsRejected(t *testing.T) {
	s := newSessionFor(t, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com"},
	})
	if err := s.Rcpt("alice@example.com", nil); err != nil {
		t.Fatal(err)
	}
	err := s.Rcpt("alice@example.com", nil)
	se, ok := err.(*gosmtp.SMTPError)
	if !ok || se.Code != 452 {
		t.Errorf("expected 452 on second RCPT, got %v", err)
	}
}

// --- AUTH ------------------------------------------------------------------

// authPlain runs the PLAIN SASL exchange (single-shot, initial-response).
func authPlain(t *testing.T, s *session, username, password string) error {
	t.Helper()
	server, err := s.Auth("PLAIN")
	if err != nil {
		t.Fatalf("Auth(PLAIN): %v", err)
	}
	_, _, authErr := server.Next([]byte("\x00" + username + "\x00" + password))
	return authErr
}

func TestAuth_PlainCorrectPassword(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("correct-horse-battery-staple-32b")
	if err := authPlain(t, s, "anything", "correct-horse-battery-staple-32b"); err != nil {
		t.Fatalf("expected AUTH to succeed, got %v", err)
	}
	if !s.authed {
		t.Error("session.authed should be true after successful AUTH")
	}
}

func TestAuth_PlainIgnoresUsername(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("the-key-value")
	for _, name := range []string{"", "user", "alice@example.com", "Sonarr", "x"} {
		s.authed = false
		if err := authPlain(t, s, name, "the-key-value"); err != nil {
			t.Errorf("username %q should be ignored, got %v", name, err)
		}
	}
}

func TestAuth_PlainWrongPasswordSameLength(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("aaaaaaaaaaaaaaaa")
	if err := authPlain(t, s, "x", "bbbbbbbbbbbbbbbb"); err != gosmtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
	if s.authed {
		t.Error("session.authed must remain false after failed AUTH")
	}
}

func TestAuth_PlainWrongLength(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("longer-than-the-candidate")
	if err := authPlain(t, s, "x", "short"); err != gosmtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

func TestAuth_PlainEmptyPassword(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("nonempty")
	if err := authPlain(t, s, "x", ""); err != gosmtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

func TestAuth_PlainEmptyServerKey(t *testing.T) {
	// Belt-and-braces: an unset key must never match, even an empty
	// candidate.
	s := newSessionFor(t, nil)
	if err := authPlain(t, s, "x", ""); err != gosmtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed on empty server key, got %v", err)
	}
}

func TestAuth_Login(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("login-key")
	server, err := s.Auth("LOGIN")
	if err != nil {
		t.Fatalf("Auth(LOGIN): %v", err)
	}
	// Step 1: server asks "Username:".
	chal, done, err := server.Next(nil)
	if err != nil || done || string(chal) != "Username:" {
		t.Fatalf("LOGIN step 1: chal=%q done=%v err=%v", chal, done, err)
	}
	// Step 2: client sends username; server asks "Password:".
	chal, done, err = server.Next([]byte("any-username"))
	if err != nil || done || string(chal) != "Password:" {
		t.Fatalf("LOGIN step 2: chal=%q done=%v err=%v", chal, done, err)
	}
	// Step 3: client sends password.
	if _, _, err := server.Next([]byte("login-key")); err != nil {
		t.Fatalf("LOGIN step 3: %v", err)
	}
	if !s.authed {
		t.Error("session.authed should be true after successful LOGIN")
	}
}

func TestAuth_LoginWrongPassword(t *testing.T) {
	s := newSessionFor(t, nil)
	s.server.notify.(*fakeNotify).setKey("right")
	server, _ := s.Auth("LOGIN")
	if _, _, err := server.Next(nil); err != nil {
		t.Fatalf("LOGIN step 1: %v", err)
	}
	if _, _, err := server.Next([]byte("user")); err != nil {
		t.Fatalf("LOGIN step 2: %v", err)
	}
	if _, _, err := server.Next([]byte("wrong")); err != gosmtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

func TestAuth_UnknownMechanism(t *testing.T) {
	s := newSessionFor(t, nil)
	if _, err := s.Auth("CRAM-MD5"); err != gosmtp.ErrAuthUnknownMechanism {
		t.Errorf("expected ErrAuthUnknownMechanism, got %v", err)
	}
}

func TestAuth_MechanismsAdvertised(t *testing.T) {
	s := newSessionFor(t, nil)
	got := s.AuthMechanisms()
	if len(got) != 2 || got[0] != "PLAIN" || got[1] != "LOGIN" {
		t.Errorf("AuthMechanisms() = %v, want [PLAIN LOGIN]", got)
	}
}

// TestAuth_RotationTakesEffect asserts the SMTP backend re-reads the
// notify API key on every AUTH attempt, so `notify:apikey:rotate`
// invalidates the old password without touching the SMTP server.
func TestAuth_RotationTakesEffect(t *testing.T) {
	s := newSessionFor(t, nil)
	fn := s.server.notify.(*fakeNotify)
	fn.setKey("first-key-value-32b")

	if err := authPlain(t, s, "x", "first-key-value-32b"); err != nil {
		t.Fatalf("pre-rotation AUTH should succeed, got %v", err)
	}

	// Rotate. Mirrors notifyServer.RotateAPIKey() swapping the in-memory key.
	fn.setKey("second-key-value-32")
	s.authed = false

	if err := authPlain(t, s, "x", "first-key-value-32b"); err != gosmtp.ErrAuthFailed {
		t.Errorf("old password must fail after rotation, got %v", err)
	}
	if err := authPlain(t, s, "x", "second-key-value-32"); err != nil {
		t.Errorf("new password must succeed after rotation, got %v", err)
	}
}

func TestMail_RejectsBeforeAuth(t *testing.T) {
	s := newSessionFor(t, nil)
	if err := s.Mail("sender@example.com", nil); err != gosmtp.ErrAuthRequired {
		t.Errorf("expected ErrAuthRequired before AUTH, got %v", err)
	}
}

func TestMail_AllowedAfterAuth(t *testing.T) {
	s := newAuthedSessionFor(t, nil)
	if err := s.Mail("sender@example.com", nil); err != nil {
		t.Errorf("expected MAIL to succeed after AUTH, got %v", err)
	}
	if s.from != "sender@example.com" {
		t.Errorf("envelope sender not recorded: %q", s.from)
	}
}
