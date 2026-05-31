package notify

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// Caps the lockscreen-banner excerpt, keeping the encrypted summary
// inside the push transport's payload limit.
const PreviewBodyChars = 200

type Server struct {
	port      int
	apiKey    string
	dataDir   string
	agentID   string // attached as plaintext so clients can attribute the notification
	atreolink *atreolink.Client
	acl       *acl.Store
}

func NewServer(port int, dataDir, agentID string, link *atreolink.Client, store *acl.Store) (*Server, error) {
	apiKey, err := LoadOrGenerateAPIKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("load api key: %w", err)
	}
	return &Server{
		port:      port,
		apiKey:    apiKey,
		dataDir:   dataDir,
		agentID:   agentID,
		atreolink: link,
		acl:       store,
	}, nil
}

func (s *Server) APIKey() string { return s.apiKey }

func (s *Server) RotateAPIKey() (string, error) {
	key, err := GenerateAPIKey(s.dataDir)
	if err != nil {
		return "", err
	}
	s.apiKey = key
	return key, nil
}

func (s *Server) Port() int { return s.port }

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/notify", s.authMiddleware(s.handleNotify))

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
		// Slowloris defence; the API binds 0.0.0.0 by design.
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          logging.StdLoggerAt(slog.LevelDebug),
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			logging.Error("Notification API shutdown: %v", err)
		}
	}()

	logging.Info("Notification API listening on :%d", s.port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		candidate := []byte(auth[7:])
		expected := []byte(s.apiKey)
		lenOK := subtle.ConstantTimeEq(int32(len(candidate)), int32(len(expected)))
		bytesOK := subtle.ConstantTimeCompare(candidate, expected)
		if lenOK != 1 || bytesOK != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		next(w, r)
	}
}

// Per-user only — UserID and UserEmail are mutually exclusive. Body
// becomes the lockscreen excerpt; HTML / Plaintext carry the full body shown when the notification is opened.
type NotifyRequest struct {
	UserID       string `json:"userId,omitempty"`
	UserEmail    string `json:"userEmail,omitempty"`
	Title        string `json:"title"`
	Body         string `json:"body"`
	HTML         string `json:"html,omitempty"`
	Plaintext    string `json:"plaintext,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
	Severity     string `json:"severity"`
	EmailFrom    string `json:"emailFrom,omitempty"`
	EmailSubject string `json:"emailSubject,omitempty"`
}

type NotifyResponse struct {
	UserID string `json:"userId"`
	Sent   bool   `json:"sent"`
}

const maxNotifyBody = 64 * 1024

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxNotifyBody)
	var req NotifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Title == "" {
		writeErr(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.Severity == "" {
		req.Severity = "info"
	}
	if (req.UserID == "") == (req.UserEmail == "") {
		writeErr(w, http.StatusBadRequest, "exactly one of userId or userEmail is required")
		return
	}

	member, err := s.resolveMember(req.UserID, req.UserEmail)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	if err := s.SendToMember(r.Context(), member, &req); err != nil {
		logging.Error("notify: send to user %s: %v", member.UserID, err)
		writeErr(w, http.StatusInternalServerError, "send failed")
		return
	}

	writeJSON(w, http.StatusOK, NotifyResponse{UserID: member.UserID, Sent: true})
}

func (s *Server) resolveMember(userID, userEmail string) (*atreolink.MemberACLEntry, error) {
	if userID != "" {
		for _, m := range s.acl.AllMembers() {
			if m.UserID == userID {
				return &m, nil
			}
		}
		return nil, fmt.Errorf("no member with that userId")
	}

	if member := s.acl.LookupByEmail(userEmail); member != nil {
		return member, nil
	}
	return nil, fmt.Errorf("no member with that email")
}

// Builds the three-field sealed-box envelope and posts it to atreoLINK.
func (s *Server) SendToMember(ctx context.Context, member *atreolink.MemberACLEntry, req *NotifyRequest) error {
	if member.IdentityKey == "" {
		return fmt.Errorf("member %s has no identity pubkey on the agent yet", member.UserID)
	}

	hasFullBody := req.HTML != "" || req.Plaintext != ""
	summaryBody := req.Body
	if hasFullBody && len(summaryBody) > PreviewBodyChars {
		summaryBody = summaryBody[:PreviewBodyChars]
	}
	contentType := req.ContentType
	if contentType == "" {
		if req.HTML != "" {
			contentType = "text/html"
		} else {
			contentType = "text/plain"
		}
	}
	summary := map[string]any{
		"id":        randomID(),
		"title":     req.Title,
		"body":      summaryBody,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	if hasFullBody {
		summary["hasFullBody"] = true
		summary["contentType"] = contentType
	}
	if req.EmailFrom != "" {
		summary["emailFrom"] = req.EmailFrom
	}
	if req.EmailSubject != "" {
		summary["emailSubject"] = req.EmailSubject
	}

	summaryCT, err := sealField(member.IdentityKey, summary)
	if err != nil {
		return fmt.Errorf("seal summary: %w", err)
	}

	env := atreolink.NotificationEnvelope{
		UserID:   member.UserID,
		AgentID:  s.agentID,
		Summary:  atreolink.SealedField{Ct: summaryCT},
		Severity: req.Severity,
	}

	if req.HTML != "" {
		ct, err := crypto.SealToUser(member.IdentityKey, []byte(req.HTML))
		if err != nil {
			return fmt.Errorf("seal html: %w", err)
		}
		env.HTML = &atreolink.SealedField{Ct: ct}
	}
	if req.Plaintext != "" {
		ct, err := crypto.SealToUser(member.IdentityKey, []byte(req.Plaintext))
		if err != nil {
			return fmt.Errorf("seal plaintext: %w", err)
		}
		env.Plaintext = &atreolink.SealedField{Ct: ct}
	}

	return s.atreolink.SendNotification(ctx, env)
}

func sealField(identityPubB64 string, v any) (string, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return crypto.SealToUser(identityPubB64, plaintext)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Used internally for system alerts (e.g. port-mismatch). `source` is
// unused — kept on the signature for callers that pass it.
func (s *Server) SendToAll(ctx context.Context, title, body, severity, source string) (sent, failed int) {
	_ = source
	members := s.acl.AllMembers()
	if len(members) == 0 {
		return 0, 0
	}
	req := &NotifyRequest{
		Title:    title,
		Body:     body,
		Severity: severity,
	}
	for i := range members {
		if err := s.SendToMember(ctx, &members[i], req); err != nil {
			failed++
			continue
		}
		sent++
	}
	return sent, failed
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read can't fail on a healthy OS entropy source.
		panic(fmt.Sprintf("notify: rand.Read: %v", err))
	}
	return hex.EncodeToString(b)
}
