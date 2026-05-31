package smtp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	sasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime/v2"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
)

type session struct {
	server    *Server
	remoteIP  string
	authed    bool
	from      string
	recipient *atreolink.MemberACLEntry
}

// Must be advertised in EHLO; otherwise clients skip the AUTH exchange.
var _ gosmtp.AuthSession = (*session)(nil)

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

// Username is ignored — self-hosted apps pick wildly different ones.
// Password is the notify API key, read fresh per attempt for rotation.
func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.validatePassword(password)
		}), nil
	case sasl.Login:
		return newLoginServer(func(username, password string) error {
			return s.validatePassword(password)
		}), nil
	}
	return nil, gosmtp.ErrAuthUnknownMechanism
}

func (s *session) validatePassword(password string) error {
	expected := []byte(s.server.apiKey())
	candidate := []byte(password)
	lenOK := subtle.ConstantTimeEq(int32(len(candidate)), int32(len(expected)))
	bytesOK := subtle.ConstantTimeCompare(candidate, expected)
	if len(expected) == 0 || lenOK != 1 || bytesOK != 1 {
		return gosmtp.ErrAuthFailed
	}
	s.authed = true
	return nil
}

// MAIL FROM is gated on AUTH; go-smtp doesn't do that by default.
func (s *session) Mail(from string, opts *gosmtp.MailOptions) error {
	if !s.authed {
		return gosmtp.ErrAuthRequired
	}
	s.from = from
	return nil
}

// Multi-RCPT rejected up front; gosmtp.MaxRecipients=1 also enforces.
func (s *session) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	if s.recipient != nil {
		return &gosmtp.SMTPError{Code: 452, EnhancedCode: gosmtp.EnhancedCode{4, 5, 3}, Message: "only one recipient per message"}
	}
	if member := s.server.acl.LookupByEmail(to); member != nil {
		s.recipient = member
		return nil
	}
	return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "unknown recipient"}
}

// Refuses standalone attachments; inlines cid: images as data: URIs.
func (s *session) Data(r io.Reader) error {
	if s.recipient == nil {
		return &gosmtp.SMTPError{Code: 503, EnhancedCode: gosmtp.EnhancedCode{5, 5, 1}, Message: "send RCPT TO first"}
	}

	env, err := enmime.ReadEnvelope(r)
	if err != nil {
		return &gosmtp.SMTPError{Code: 554, EnhancedCode: gosmtp.EnhancedCode{5, 6, 0}, Message: fmt.Sprintf("parse mime: %v", err)}
	}

	if len(env.Attachments) > 0 {
		return &gosmtp.SMTPError{Code: 554, EnhancedCode: gosmtp.EnhancedCode{5, 6, 1}, Message: "attachments not supported"}
	}

	htmlBody := env.HTML
	if htmlBody != "" {
		htmlBody = inlineCIDs(htmlBody, env.Inlines)
	}
	plaintextBody := env.Text

	if htmlBody == "" && plaintextBody == "" {
		return &gosmtp.SMTPError{Code: 554, EnhancedCode: gosmtp.EnhancedCode{5, 6, 0}, Message: "empty message body"}
	}

	subject := strings.TrimSpace(env.GetHeader("Subject"))
	if subject == "" {
		subject = "(no subject)"
	}
	emailFrom := strings.TrimSpace(env.GetHeader("From"))
	if emailFrom == "" {
		emailFrom = s.from
	}

	preview := plaintextBody
	if preview == "" {
		preview = htmlToPreview(htmlBody)
	}
	preview = strings.TrimSpace(preview)
	if len(preview) > notify.PreviewBodyChars {
		preview = preview[:notify.PreviewBodyChars]
	}

	req := &notify.NotifyRequest{
		Title:        subject,
		Body:         preview,
		HTML:         htmlBody,
		Plaintext:    plaintextBody,
		Severity:     "info",
		EmailFrom:    emailFrom,
		EmailSubject: subject,
	}
	if htmlBody != "" {
		req.ContentType = "text/html"
	} else {
		req.ContentType = "text/plain"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.server.notify.SendToMember(ctx, s.recipient, req); err != nil {
		// 451 4.7.0 keeps state intact and asks the sender to retry.
		return &gosmtp.SMTPError{Code: 451, EnhancedCode: gosmtp.EnhancedCode{4, 7, 0}, Message: fmt.Sprintf("dispatch failed: %v", err)}
	}
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.recipient = nil
}

func (s *session) Logout() error { return nil }

// Server-side SASL LOGIN — go-sasl only ships the client half. Some
// self-hosted apps emit LOGIN even when PLAIN is offered.
type loginServer struct {
	step     int
	username string
	auth     func(username, password string) error
}

func newLoginServer(auth func(username, password string) error) sasl.Server {
	return &loginServer{auth: auth}
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		l.step = 1
		return []byte("Username:"), false, nil
	case 1:
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		l.step = 3
		err = l.auth(l.username, string(response))
		return nil, true, err
	}
	return nil, true, errors.New("sasl: LOGIN already finished")
}
