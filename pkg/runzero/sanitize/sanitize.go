package sanitize

import (
	"bytes"
	"strings"
)

// Name removes null bytes and trims leading and trailing spaces from a string
func Name(name string) string {
	return strings.TrimSpace(strings.ReplaceAll(name, "\x00", ""))
}

// String scrubs a given string of invalid UTF8 and nulls
func String(s string) string {
	// Remove invalid UTF-8 sequences
	s = strings.ToValidUTF8(s, "")
	// Remove null bytes that break PostgreSQL jsonb
	return strings.ReplaceAll(s, "\x00", "")
}

func StringSlice(slice []string) []string {
	for i, s := range slice {
		slice[i] = String(s)
	}
	return slice
}

// SanitizeBytes scrubs a given byte array of invalid UTF8 and nulls
func Bytes(s []byte) []byte {
	// Loop until all invalid bytes are scrubbed (see #11839)
	plen := len(s)
	for {
		// Remove invalid UTF-8 sequences and return a new array
		s = bytes.ToValidUTF8(s, []byte{})
		// Remove null bytes that break PostgreSQL jsonb
		s = bytes.ReplaceAll(s, []byte{0}, []byte{})
		// Remove null bytes unicode sequence
		s = bytes.ReplaceAll(s, []byte{92, 117, 48, 48, 48, 48}, []byte{})
		if len(s) == plen {
			break
		}
		plen = len(s)
	}
	return s
}

// Truncate returns a version of the input string no bigger than l bytes.
// If passed a valid UTF-8 string, it returns a valid UTF-8 string.
func Truncate(s string, l int) string {
	// If we don't need to do any work, return quickly
	if len(s) <= l {
		return s
	}
	// Otherwise we need to perform a rune loop, to avoid truncating in the middle of a rune
	// and ending up with an invalid string.
	var ns strings.Builder
	// Pregrow the string builder for max performance
	ns.Grow(l)
	i := 0
	for _, c := range s {
		scl := len(string(c))
		if scl+i > l {
			break
		}
		ns.WriteRune(c)
		i += scl
	}
	return ns.String()
}
