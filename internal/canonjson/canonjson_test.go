package canonjson

import (
	"errors"
	"testing"
)

func TestMarshalGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "empty object",
			in:   map[string]any{},
			want: `{}`,
		},
		{
			name: "empty array",
			in:   []any{},
			want: `[]`,
		},
		{
			name: "sorted keys",
			// Provide keys in deliberately reversed order; canonical output must
			// re-sort them. This is the core property the rest of the system
			// depends on.
			in: map[string]any{
				"z": 1,
				"a": 2,
				"m": 3,
			},
			want: `{"a":2,"m":3,"z":1}`,
		},
		{
			name: "nested objects",
			in: map[string]any{
				"outer": map[string]any{
					"b": "two",
					"a": "one",
				},
				"first": true,
			},
			want: `{"first":true,"outer":{"a":"one","b":"two"}}`,
		},
		{
			name: "arrays preserve order",
			in: map[string]any{
				"items": []any{"c", "a", "b"},
			},
			want: `{"items":["c","a","b"]}`,
		},
		{
			name: "basic types",
			in: map[string]any{
				"s": "hi",
				"i": 42,
				"b": false,
			},
			want: `{"b":false,"i":42,"s":"hi"}`,
		},
		{
			name: "string with html-special chars not escaped",
			// RFC 8785 forbids the HTML-safe escape Go does by default. Make
			// sure < > & survive verbatim.
			in:   map[string]any{"s": "a<b>c&d"},
			want: `{"s":"a<b>c&d"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.in)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestMarshalRejectsNull(t *testing.T) {
	cases := []any{
		nil,
		map[string]any{"k": nil},
		[]any{"a", nil, "b"},
	}
	for i, in := range cases {
		_, err := Marshal(in)
		if err == nil {
			t.Errorf("case %d: expected ErrNullForbidden, got nil", i)
			continue
		}
		if !errors.Is(err, ErrNullForbidden) {
			t.Errorf("case %d: error = %v, want ErrNullForbidden", i, err)
		}
	}
}

func TestMarshalIdempotent(t *testing.T) {
	// Canonicalize twice — output must be identical. This is the property
	// that lets the verifier re-canonicalize a payload it received and get
	// the same bytes the signer hashed.
	in := map[string]any{
		"z": 1, "a": []any{3, 2, 1}, "m": map[string]any{"y": "z", "x": "y"},
	}
	first, err := Marshal(in)
	if err != nil {
		t.Fatalf("first Marshal: %v", err)
	}
	second, err := MarshalRaw(first)
	if err != nil {
		t.Fatalf("second MarshalRaw: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("not idempotent:\n1: %s\n2: %s", first, second)
	}
}

func TestMarshalRawRejectsTrailingJunk(t *testing.T) {
	_, err := MarshalRaw([]byte(`{"a":1}garbage`))
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestMarshalStruct(t *testing.T) {
	// Real-world usage: typed struct with json tags. The canonical output
	// must reflect the tag names, sorted.
	type payload struct {
		MemberID string `json:"memberId"`
		LeftAt   string `json:"leftAt"`
	}
	in := payload{MemberID: "m1", LeftAt: "2026-04-19T00:00:00Z"}
	got, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"leftAt":"2026-04-19T00:00:00Z","memberId":"m1"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
