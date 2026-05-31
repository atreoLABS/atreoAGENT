package atreolink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSlugify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Plex Media Server", "plex-media-server"},
		{"Foo  Bar", "foo-bar"},
		{"  trim me  ", "trim-me"},
		{"unicode-éh!", "unicode-h"},
		{"Already-A-Slug", "already-a-slug"},
		{"???", ""},
		{"a..b..c", "a-b-c"},
		{"trailing-", "trailing"},
		{"123 abc", "123-abc"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := Slugify(tc.in); got != tc.want {
				t.Errorf("Slugify(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEffectiveSlug(t *testing.T) {
	a := App{Name: "Plex Media Server"}
	if got := a.EffectiveSlug(); got != "plex-media-server" {
		t.Errorf("from name: %q", got)
	}
	a = App{Name: "Plex", Slug: "plex-custom"}
	if got := a.EffectiveSlug(); got != "plex-custom" {
		t.Errorf("explicit slug: %q", got)
	}
}

func TestSetDeviceID(t *testing.T) {
	c := NewClient("http://example.invalid", testKeyManager(t), "")
	c.SetDeviceID("dev-new")
	if c.deviceID != "dev-new" {
		t.Errorf("deviceID=%q, want dev-new", c.deviceID)
	}
}

// TestSendNotification: the outer body is the signed auth envelope, not the
// bare NotificationEnvelope. Assert on the inner payload after unwrapping.
func TestSendNotification(t *testing.T) {
	rec := newRecorder(t)
	c := NewClient(rec.server.URL, testKeyManager(t), "11111111-1111-1111-1111-111111111111")
	html := SealedField{Ct: "html-ct"}
	env := NotificationEnvelope{
		UserID:   "user-uuid",
		AgentID:  "agent-uuid",
		Summary:  SealedField{Ct: "summary-ct"},
		HTML:     &html,
		Severity: "warning",
	}
	if err := c.SendNotification(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if rec.lastPath() != "/v1/notifications" {
		t.Errorf("path=%q", rec.lastPath())
	}
	var outer struct {
		SignerID  string          `json:"signerId"`
		Signature string          `json:"signature"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(rec.lastBody(), &outer); err != nil {
		t.Fatalf("decode outer: %v", err)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(outer.Payload, &body)
	if body["userId"] != "user-uuid" || body["agentId"] != "agent-uuid" || body["severity"] != "warning" {
		t.Errorf("body=%v", body)
	}
	summary, _ := body["summary"].(map[string]interface{})
	if summary["ct"] != "summary-ct" {
		t.Errorf("summary.ct=%v", summary["ct"])
	}
	htmlBody, _ := body["html"].(map[string]interface{})
	if htmlBody["ct"] != "html-ct" {
		t.Errorf("html.ct=%v", htmlBody["ct"])
	}
	if _, present := body["plaintext"]; present {
		t.Errorf("plaintext must be omitted when nil: %v", body)
	}
}

func TestPairOptions(t *testing.T) {
	opts := &pairOpts{}
	WithPairTokenHash("hash123")(opts)
	if opts.PairTokenHash != "hash123" {
		t.Errorf("PairTokenHash=%q", opts.PairTokenHash)
	}
	var gotSessionID string
	WithApprovalDecoder(func(_ PairApprovalBlob, sessionID string) ([]byte, []byte, string, error) {
		gotSessionID = sessionID
		return nil, nil, "", nil
	})(opts)
	if opts.Decoder == nil {
		t.Fatal("Decoder not set")
	}
	_, _, _, _ = opts.Decoder(PairApprovalBlob{}, "sess-xyz")
	if gotSessionID != "sess-xyz" {
		t.Errorf("Decoder got sessionID %q, want sess-xyz", gotSessionID)
	}
	WithAuthURLBuilder(func(_, _ string) string { return "x" })(opts)
	if opts.AuthURLBuilder == nil || opts.AuthURLBuilder("", "") != "x" {
		t.Error("AuthURLBuilder not set")
	}
}

// --- recorder helper --------------------------------------------------------

type recorder struct {
	server *httptest.Server
	mu     sync.Mutex
	path   string
	body   []byte
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.path = req.URL.Path
		buf := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(buf)
		r.body = buf
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) lastPath() string { r.mu.Lock(); defer r.mu.Unlock(); return r.path }
func (r *recorder) lastBody() []byte { r.mu.Lock(); defer r.mu.Unlock(); return r.body }
