package proxy

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
)

// errorKind selects a browser-facing error variant. The proxy is the only
// browser-facing server; auth/notify/probe responses stay terse.
type errorKind int

const (
	errKindBadRequest errorKind = iota
	errKindNotFound
	errKindForbidden
	errKindBadGateway
)

// errorContent is one variant's copy. plainBody is the exact pre-HTML
// http.Error string, so non-browser clients are unaffected; pages never carry
// internal detail (URLs, dial errors stay in the logs).
type errorContent struct {
	status    int
	plainBody string
	title     string
	message   string
	guidance  string
}

var errorContents = map[errorKind]errorContent{
	errKindBadRequest: {
		status:    http.StatusBadRequest,
		plainBody: "Bad request",
		title:     "Something went wrong with that request",
		message:   "Your browser sent a request this server couldn't understand.",
		guidance:  "Try again, and if it keeps happening let the server owner know.",
	},
	errKindNotFound: {
		status:    http.StatusNotFound,
		plainBody: "Not found",
		title:     "App not found",
		message:   "There's no app at this address.",
		guidance:  "Check the address for typos, or ask the server owner if the app has moved.",
	},
	// Untrusted callers get 403 for unknown slugs too, so this copy avoids
	// confirming the app exists — otherwise it would leak the app list.
	errKindForbidden: {
		status:    http.StatusForbidden,
		plainBody: "Forbidden",
		title:     "You don't have access",
		message:   "Your account isn't allowed to open this app.",
		guidance:  "Ask the server owner to grant you access.",
	},
	errKindBadGateway: {
		status:    http.StatusBadGateway,
		plainBody: "Bad gateway",
		title:     "The app isn't responding",
		message:   "The server is up, but the app behind this address didn't answer.",
		guidance:  "The app might be stopped or still starting. Try again in a moment, or let the server owner know.",
	},
}

//go:embed errorpage.html
var errorPageHTML string

// Full wordmark for the header. Its white text is why the card is always dark.
//
//go:embed logo-wordmark.svg
var logoWordmarkSVG string

// Square icon-only mark for the favicon; the wide wordmark makes a poor tab icon.
//
//go:embed logo-icon.svg
var logoIconSVG string

// Rendered once at init: template data is constant, so serving is a cached
// byte-slice write with no runtime error path.
var errorPages = renderErrorPages()

func renderErrorPages() map[errorKind][]byte {
	tmpl := template.Must(template.New("errorpage").Parse(errorPageHTML))
	// The brand assets are attached as nested templates, not injected as
	// template.HTML values: their markup emits verbatim (no request data is ever
	// involved) and, as template text, dodges the URL normalizer that would
	// entity-encode the favicon's base64 '+'/'/'.
	template.Must(tmpl.New("logo").Parse(logoWordmarkSVG))
	favicon := `<link rel="icon" href="data:image/svg+xml;base64,` +
		base64.StdEncoding.EncodeToString([]byte(logoIconSVG)) + `">`
	template.Must(tmpl.New("favicon").Parse(favicon))

	pages := make(map[errorKind][]byte, len(errorContents))
	for kind, c := range errorContents {
		var buf bytes.Buffer
		data := struct {
			Status     int
			StatusText string
			Title      string
			Message    string
			Guidance   string
		}{
			Status:     c.status,
			StatusText: http.StatusText(c.status),
			Title:      c.title,
			Message:    c.message,
			Guidance:   c.guidance,
		}
		// Constant inputs — any failure is a build-time template bug the tests catch.
		if err := tmpl.Execute(&buf, data); err != nil {
			panic("proxy: rendering error page: " + err.Error())
		}
		pages[kind] = buf.Bytes()
	}
	return pages
}

// wantsHTML reports whether the client is a browser. Browsers lead their Accept
// header with text/html; curl and Go clients send */* or nothing.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeErrorPage serves the branded page to browsers, plain text to everything
// else. A failing URL may recover in seconds, so responses are never cached.
func writeErrorPage(w http.ResponseWriter, r *http.Request, kind errorKind) {
	c := errorContents[kind]
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept")
	if !wantsHTML(r) {
		http.Error(w, c.plainBody, c.status) // sets text/plain + nosniff itself
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(c.status)
	_, _ = w.Write(errorPages[kind])
}
