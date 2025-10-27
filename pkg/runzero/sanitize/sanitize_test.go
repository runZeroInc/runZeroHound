package sanitize

import (
	"slices"
	"testing"
)

func BenchmarkSanitizeString(b *testing.B) {
	_ = String
	for i := 0; i < b.N; i++ {
		_ = String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		_ = String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00A")
		_ = String("AAAAAAAAAAAAAAAAAAAA\x80\xFFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00A")
	}
}

func TestSanitizeString(t *testing.T) {
	testCases := []struct {
		Input  string
		Result string
	}{
		{"", ""},
		{"\x00", ""},
		{"\x00\x00\x00\x00", ""},
		{"A\x00B\x00C\x00D\x00", "ABCD"},
		{"AAAAAAAAAAAAAAAAAAAA\x80\xFFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00A", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	for _, tc := range testCases {
		got := String(tc.Input)
		if got != tc.Result {
			t.Errorf("expected '%s' for '%s', got '%s'", tc.Result, tc.Input, got)
		}
	}
}

func TestSanitizeStringSlice(t *testing.T) {
	testCases := []struct {
		Input  string
		Result string
	}{
		{"", ""},
		{"\x00", ""},
		{"\x00\x00\x00\x00", ""},
		{"A\x00B\x00C\x00D\x00", "ABCD"},
		{"AAAAAAAAAAAAAAAAAAAA\x80\xFFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00A", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	input := make([]string, len(testCases))
	result := make([]string, len(testCases))
	for _, tc := range testCases {
		input = append(input, tc.Input)
		result = append(result, tc.Result)
	}
	got := StringSlice(input)
	if !slices.Equal(result, got) {
		t.Errorf("expected '%+v', got '%+v'", result, got)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		in     string
		length int
		out    string
	}{
		{"test", 0, ""},
		{"test", 1, "t"},
		{"test", 4, "test"},
		{"test", 99, "test"},
		{"pizza🍕", 7, "pizza"},
		{"pizza🍕", 9, "pizza🍕"},
		{"こんにちは", 9, "こんに"},
		{"こんにちは", 11, "こんに"},
	}

	for _, test := range tests {
		truncated := Truncate(test.in, test.length)
		if truncated != test.out {
			t.Errorf("got %s, expected %s", truncated, test.out)
		}
	}
}
