package proxy

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A realistic browser Accept header, used to exercise the HTML branch.
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

func TestErrorPages_AllKindsRendered(t *testing.T) {
	for kind, c := range errorContents {
		page := errorPages[kind]
		if len(page) == 0 {
			t.Fatalf("kind %d rendered empty", kind)
		}
		body := string(page)
		if !strings.HasPrefix(body, "<!doctype html>") {
			t.Errorf("kind %d: page does not start with doctype", kind)
		}
		// Copy is HTML-escaped in the rendered page (e.g. apostrophes → &#39;).
		for _, want := range []string{"<svg", "atreo", html.EscapeString(c.title), html.EscapeString(c.message), html.EscapeString(c.guidance), http.StatusText(c.status)} {
			if !strings.Contains(body, want) {
				t.Errorf("kind %d: page missing %q", kind, want)
			}
		}
	}
}

func TestWriteErrorPage_HTML(t *testing.T) {
	for kind, c := range errorContents {
		t.Run(c.title, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://x.example/", nil)
			r.Header.Set("Accept", browserAccept)
			w := httptest.NewRecorder()

			writeErrorPage(w, r, kind)

			if w.Code != c.status {
				t.Errorf("status=%d, want %d", w.Code, c.status)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type=%q, want text/html", ct)
			}
			if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control=%q, want no-store", cc)
			}
			if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
				t.Errorf("X-Content-Type-Options=%q, want nosniff", xcto)
			}
			if v := w.Header().Get("Vary"); !strings.Contains(v, "Accept") {
				t.Errorf("Vary=%q, want it to contain Accept", v)
			}
			body := w.Body.String()
			for _, want := range []string{"<svg", "atreo", html.EscapeString(c.title), html.EscapeString(c.guidance), "data:image/svg+xml;base64,"} {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q", want)
				}
			}
			// The plain-text body must not leak into the HTML path.
			if strings.Contains(body, "text/plain") {
				t.Errorf("HTML body unexpectedly mentions text/plain")
			}
		})
	}
}

func TestWriteErrorPage_PlainFallback(t *testing.T) {
	for kind, c := range errorContents {
		for _, accept := range []string{"", "*/*", "application/json"} {
			t.Run(c.title+"/"+accept, func(t *testing.T) {
				r := httptest.NewRequest("GET", "http://x.example/", nil)
				if accept != "" {
					r.Header.Set("Accept", accept)
				}
				w := httptest.NewRecorder()

				writeErrorPage(w, r, kind)

				if w.Code != c.status {
					t.Errorf("status=%d, want %d", w.Code, c.status)
				}
				if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
					t.Errorf("Content-Type=%q, want text/plain; charset=utf-8", ct)
				}
				if got, want := w.Body.String(), c.plainBody+"\n"; got != want {
					t.Errorf("body=%q, want %q", got, want)
				}
			})
		}
	}
}
