package utils

import "testing"

func TestSanitizeDomainForFilename(t *testing.T) {
	cases := map[string]string{
		"example.com":    "example.com",
		"*.example.com":  "wildcard_.example.com",
		"*":              "wildcard",
		"foo*bar":        "foo_wildcard_bar",
		"..":             "domain",
		"/invalid\\path": "invalid_path",
	}

	for input, expected := range cases {
		if got := SanitizeDomainForFilename(input); got != expected {
			t.Fatalf("expected %q -> %q, got %q", input, expected, got)
		}
	}
}
