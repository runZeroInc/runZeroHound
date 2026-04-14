package input

import "strings"

// ParsedHost is the common representation of a network host produced by any
// input parser.  Parsers fill only the fields they have data for.
type ParsedHost struct {
	// Source is the file type that produced this record.
	Source FileType

	// Sources tracks every data source that contributed to this host.
	// Each entry is a short label such as "nmap-xml", "nessus", "runzero-jsonl".
	Sources []string

	// Primary IP addresses observed for this host.
	Addresses []string

	// MAC addresses observed for this host (normalised to aa:bb:cc:dd:ee:ff).
	MACs []string

	// Hostnames / DNS names.
	Names []string

	// OS description (best guess).
	OS string

	// Services observed on the host.
	Services []ParsedService

	// TracerouteHops holds layer-3 path information discovered during scanning.
	// Each hop represents an intermediate router between the scanner and this host.
	TracerouteHops []TracerouteHop

	// SubAssets are related network entities discovered through this host
	// (e.g. SNMP ARP cache entries, MAC table entries, CDP/LLDP neighbours).
	SubAssets []SubAsset

	// Vulns holds vulnerabilities discovered on this host.
	Vulns []ParsedVuln

	// Generic key→value attributes from the source data.
	Attributes map[string]string

	// Unique fingerprints used for cross-source correlation.
	// Keys:   "ssh_hostkey_fp", "tls_cert_fp", "smb_guid", "snmpv3_engine_id"
	UniqueKeys map[string]string
}

// ParsedVuln represents a vulnerability finding on a host.
type ParsedVuln struct {
	// ID is a source-specific identifier (plugin ID, QID, OID, vuln def ID).
	ID string
	// Title is the human-readable name of the vulnerability.
	Title string
	// Severity is the severity level or score from the source.
	Severity string
	// CVEs holds zero or more CVE identifiers associated with this vulnerability.
	CVEs []string
	// Source identifies the scanner that reported this vulnerability.
	Source string
	// Description is a short summary of the vulnerability (e.g. Nessus synopsis).
	Description string
	// CVSSScore is the CVSS base score as a string (e.g. "7.5"), if available.
	CVSSScore string
	// RiskFactor is the qualitative risk rating (e.g. "Critical", "High", "Medium", "Low").
	RiskFactor string
}

// TracerouteHop represents a single router hop in a traceroute path.
type TracerouteHop struct {
	// TTL is the time-to-live / hop number (1-based).
	TTL int
	// Addresses contains one or more IP addresses for this hop.
	// Multi-homed routers may have multiple addresses visible from different probes.
	Addresses []string
	// RTT is the round-trip time in milliseconds (if available, 0 otherwise).
	RTT float64
	// Hostname is the reverse-DNS name of the hop (if available).
	Hostname string
}

// SubAsset represents a network entity discovered indirectly through a host,
// such as ARP cache entries, MAC table entries, or CDP/LLDP neighbours.
type SubAsset struct {
	// Type classifies the sub-asset: "arp", "mac_table", "cdp_neighbor", "lldp_neighbor".
	Type string
	// Addresses holds IP addresses associated with this sub-asset.
	Addresses []string
	// MACs holds MAC addresses associated with this sub-asset.
	MACs []string
	// Interface is the local interface on the parent host (e.g. "Gi0/1", "eth0").
	Interface string
	// VLAN is the VLAN ID if known.
	VLAN string
	// Attributes holds extra key→value metadata.
	Attributes map[string]string
}

// ParsedService represents one observed network service.
type ParsedService struct {
	Address  string
	Port     string
	Protocol string // "tcp" / "udp"
	Product  string
	Version  string
	// Extra key→value information about the service.
	Attributes map[string]string
}

// ParseResult holds the output of a parser run.
type ParseResult struct {
	Hosts []*ParsedHost
}

// trimDesc truncates a description string to maxLen runes after trimming whitespace.
func trimDesc(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
