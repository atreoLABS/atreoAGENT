package smtp

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/jhillyerd/enmime/v2"
)

// cidImgPattern matches `<img ... src="cid:..."...>` (single OR double
// quotes, attribute order tolerant). The HTML rendered in the WebView /
// iframe sandbox has a strict CSP that blocks remote `<img>` by default
// only if we leave `cid:` URIs in place. Inlining them as `data:` URIs
// keeps inline email images visible without poking holes in the CSP.
var cidImgPattern = regexp.MustCompile(`(?i)src=["']cid:([^"'<>\s]+)["']`)

// inlineCIDs rewrites every `src="cid:foo"` in html to `src="data:..."`
// for any cid present in the inlines slice. cids not found in inlines
// are left as-is (the renderer will simply fail to load them, which is
// the correct behaviour for unknown references).
func inlineCIDs(html string, inlines []*enmime.Part) string {
	if len(inlines) == 0 {
		return html
	}
	cidMap := make(map[string]*enmime.Part, len(inlines))
	for _, p := range inlines {
		// Content-ID header arrives as <foo@bar>; strip the angles.
		cid := strings.Trim(p.ContentID, "<>")
		if cid != "" {
			cidMap[cid] = p
		}
	}
	if len(cidMap) == 0 {
		return html
	}
	return cidImgPattern.ReplaceAllStringFunc(html, func(match string) string {
		// Extract the cid value from the matched src=...
		sub := cidImgPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		cid := sub[1]
		part, ok := cidMap[cid]
		if !ok {
			return match
		}
		mime := part.ContentType
		if mime == "" {
			mime = "application/octet-stream"
		}
		return fmt.Sprintf(`src="data:%s;base64,%s"`, mime, base64.StdEncoding.EncodeToString(part.Content))
	})
}

// htmlToPreview produces a short plaintext excerpt from HTML for
// fallback summary-body display when the message has no text/plain
// alternative. Strips tags, collapses whitespace.
func htmlToPreview(html string) string {
	if html == "" {
		return ""
	}
	stripped := tagPattern.ReplaceAllString(html, " ")
	return strings.Join(strings.Fields(stripped), " ")
}

var tagPattern = regexp.MustCompile(`<[^>]+>`)
