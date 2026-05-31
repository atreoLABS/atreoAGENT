package banner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Every rendered line must be the same display width or the right-hand
// border drifts — the exact bug this package exists to prevent. The
// em-dash case is the regression that motivated it.
func TestBoxLinesAlign(t *testing.T) {
	cases := [][]string{
		{"atreoAGENT pairing — operator approval required"},
		{"Automatic port mapping failed. Please manually forward UDP port 51820 to this host."},
		{"first line", "a much longer second line — with an em-dash"},
		{""},
	}
	for _, lines := range cases {
		out := Box(lines...)
		rows := strings.Split(out, "\n")
		want := utf8.RuneCountInString(rows[0])
		for i, r := range rows {
			if got := utf8.RuneCountInString(r); got != want {
				t.Errorf("lines=%q row %d width=%d, want %d\n%s", lines, i, got, want, out)
			}
		}
		if !strings.HasPrefix(rows[0], "  ╔") || !strings.HasSuffix(rows[0], "╗") {
			t.Errorf("top border malformed: %q", rows[0])
		}
		if !strings.HasPrefix(rows[len(rows)-1], "  ╚") || !strings.HasSuffix(rows[len(rows)-1], "╝") {
			t.Errorf("bottom border malformed: %q", rows[len(rows)-1])
		}
	}
}
