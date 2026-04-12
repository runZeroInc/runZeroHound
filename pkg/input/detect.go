// Package input provides file type detection and parsing for various network
// scan output formats that runZeroHound can ingest.
package input

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// FileType represents the detected type of an input file.
type FileType int

const (
	FileTypeUnknown      FileType = iota
	FileTypeRunZeroGZIP           // gzip-compressed runZero JSONL export
	FileTypeRunZeroJSONL          // plain runZero JSONL export
	FileTypeNmapXML               // Nmap XML output (-oX)
	FileTypeSNMPWalk              // net-snmp snmpwalk text output
	FileTypeNextnet               // nextnet .nxt JSONL output
)

// String returns a human-readable name for the file type.
func (ft FileType) String() string {
	switch ft {
	case FileTypeRunZeroGZIP:
		return "runzero-gzip"
	case FileTypeRunZeroJSONL:
		return "runzero-jsonl"
	case FileTypeNmapXML:
		return "nmap-xml"
	case FileTypeSNMPWalk:
		return "snmpwalk"
	case FileTypeNextnet:
		return "nextnet"
	default:
		return "unknown"
	}
}

// DetectFileType inspects the path (and its contents) to determine the format.
// Detection order:
//  1. .nxt extension → nextnet
//  2. gzip magic bytes → runZero gzip-compressed JSONL
//  3. XML / nmaprun header → Nmap XML
//  4. snmpwalk OID pattern → snmpwalk
//  5. fallback → runZero JSONL
func DetectFileType(path string) (FileType, error) {
	// 1. Extension-based detection for nextnet
	if strings.HasSuffix(strings.ToLower(path), ".nxt") {
		return FileTypeNextnet, nil
	}

	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return FileTypeUnknown, err
	}
	defer fd.Close()

	header := make([]byte, 512)
	n, err := fd.Read(header)
	if err != nil && err != io.EOF {
		return FileTypeUnknown, err
	}
	header = header[:n]

	// 2. gzip magic bytes → runZero gzip JSONL
	if len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		return FileTypeRunZeroGZIP, nil
	}

	// 3. XML / Nmap header
	trimmed := bytes.TrimSpace(header)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.Contains(trimmed, []byte("<nmaprun")) {
		return FileTypeNmapXML, nil
	}

	// 4. snmpwalk OID pattern
	if looksLikeSNMPWalk(header) {
		return FileTypeSNMPWalk, nil
	}

	// 5. Fallback to runZero JSONL
	return FileTypeRunZeroJSONL, nil
}

// looksLikeSNMPWalk returns true when the first few lines match typical
// snmpwalk output: "OID = TYPE: value" or ".1.3.6... = ...".
func looksLikeSNMPWalk(data []byte) bool {
	s := string(data)
	lines := strings.SplitN(s, "\n", 10)
	matched := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		// Matches "SNMPv2-MIB::sysDescr.0 = STRING: ..." or ".1.3.6.1... = ..."
		if strings.Contains(line, " = ") &&
			(strings.Contains(line, "::") || strings.HasPrefix(line, ".1.")) {
			matched++
			if matched >= 2 {
				return true
			}
		}
	}
	return false
}
