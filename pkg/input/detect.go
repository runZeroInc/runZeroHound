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
	FileTypeNessus                // Nessus .nessus XML report
	FileTypeOpenVAS               // OpenVAS/GVM XML report
	FileTypeNetBox                // NetBox JSON API export
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
	case FileTypeNessus:
		return "nessus"
	case FileTypeOpenVAS:
		return "openvas"
	case FileTypeNetBox:
		return "netbox"
	default:
		return "unknown"
	}
}

// DetectFileType inspects the path (and its contents) to determine the format.
// Detection order:
//  1. .nxt extension → nextnet
//  2. .nessus extension → Nessus
//  3. gzip magic bytes → runZero gzip-compressed JSONL
//  4. XML header dispatch: nmaprun → Nmap, NessusClientData → Nessus, OpenVAS report → OpenVAS
//  5. JSON with count+results → NetBox
//  6. snmpwalk OID pattern → snmpwalk
//  7. fallback → runZero JSONL
func DetectFileType(path string) (FileType, error) {
	lower := strings.ToLower(path)

	// 1. Extension-based detection for nextnet
	if strings.HasSuffix(lower, ".nxt") {
		return FileTypeNextnet, nil
	}

	// 2. Extension-based detection for Nessus
	if strings.HasSuffix(lower, ".nessus") {
		return FileTypeNessus, nil
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

	// 3. gzip magic bytes → runZero gzip JSONL
	if len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		return FileTypeRunZeroGZIP, nil
	}

	// 4. XML dispatch
	trimmed := bytes.TrimSpace(header)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<")) {
		switch {
		case bytes.Contains(trimmed, []byte("NessusClientData")):
			return FileTypeNessus, nil
		case bytes.Contains(trimmed, []byte("<nmaprun")):
			return FileTypeNmapXML, nil
		case bytes.Contains(trimmed, []byte("<report")) &&
			(bytes.Contains(trimmed, []byte("openvas")) ||
				bytes.Contains(trimmed, []byte("gvm")) ||
				bytes.Contains(trimmed, []byte("<results"))):
			return FileTypeOpenVAS, nil
		case bytes.Contains(trimmed, []byte("<nmaprun")):
			return FileTypeNmapXML, nil
		}
	}

	// 5. JSON with NetBox shape: {"count": N, "results": [...]}
	if looksLikeNetBox(header) {
		return FileTypeNetBox, nil
	}

	// 6. snmpwalk OID pattern
	if looksLikeSNMPWalk(header) {
		return FileTypeSNMPWalk, nil
	}

	// 7. Fallback to runZero JSONL
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

// looksLikeNetBox returns true when the header bytes look like a NetBox API
// response: a JSON object with both "count" and "results" keys.
func looksLikeNetBox(data []byte) bool {
	s := string(data)
	return strings.Contains(s, `"count"`) &&
		strings.Contains(s, `"results"`) &&
		strings.HasPrefix(strings.TrimSpace(s), "{")
}
