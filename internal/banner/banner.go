// Package banner renders box-drawn console banners whose borders stay
// aligned regardless of multibyte runes (em-dash, the box characters
// themselves). Hand-counted boxes drift the moment a non-ASCII rune
// sneaks in — this centralises the padding so they can't.
package banner

import (
	"strings"
	"unicode/utf8"
)

// Box draws a box around lines, sized to the widest line with a
// two-space margin each side and a two-space outer indent (matching the
// agent's pairing banner). No trailing newline.
func Box(lines ...string) string {
	maxLen := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > maxLen {
			maxLen = n
		}
	}
	inner := maxLen + 4 // two-space margin each side
	const indent = "  "

	var b strings.Builder
	b.WriteString(indent + "╔" + strings.Repeat("═", inner) + "╗\n")
	for _, l := range lines {
		pad := maxLen - utf8.RuneCountInString(l)
		b.WriteString(indent + "║  " + l + strings.Repeat(" ", pad) + "  ║\n")
	}
	b.WriteString(indent + "╚" + strings.Repeat("═", inner) + "╝")
	return b.String()
}
