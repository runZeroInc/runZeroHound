package nextnet

import (
	"fmt"
	"os"
	"strings"
)

// PrintVersion writes the tool version to stderr.
func PrintVersion(app string) {
	var version = "1.0.0"
	fmt.Fprintf(os.Stderr, "%s v%s\n", app, version)
}

// TrimName removes null bytes and surrounding whitespace from a NetBIOS name.
func TrimName(name string) string {
	return strings.TrimSpace(strings.ReplaceAll(name, "\x00", ""))
}
