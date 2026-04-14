package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Nessus XML document structure (.nessus files).
// Reference: https://community.tenable.com/s/article/Nessus-v2-File-Format

type nessusClientData struct {
	XMLName xml.Name     `xml:"NessusClientData_v2"`
	Report  nessusReport `xml:"Report"`
}

type nessusReport struct {
	Name  string             `xml:"name,attr"`
	Hosts []nessusReportHost `xml:"ReportHost"`
}

type nessusReportHost struct {
	Name       string             `xml:"name,attr"`
	Properties nessusHostProps    `xml:"HostProperties"`
	Items      []nessusReportItem `xml:"ReportItem"`
}

type nessusHostProps struct {
	Tags []nessusTag `xml:"tag"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusReportItem struct {
	Port           string   `xml:"port,attr"`
	SvcName        string   `xml:"svc_name,attr"`
	Protocol       string   `xml:"protocol,attr"`
	Severity       string   `xml:"severity,attr"`
	PluginID       string   `xml:"pluginID,attr"`
	PluginName     string   `xml:"pluginName,attr"`
	Output         string   `xml:"plugin_output"`
	Description    string   `xml:"description"`
	CVEs           []string `xml:"cve"`
	RiskFactor     string   `xml:"risk_factor"`
	Synopsis       string   `xml:"synopsis"`
	CVSS3BaseScore string   `xml:"cvss3_base_score"`
	CVSS3Vector    string   `xml:"cvss3_vector"`
	CVSSBaseScore  string   `xml:"cvss_base_score"`
}

// Well-known Nessus plugin IDs that carry fingerprint/identity data.
const (
	nessusPluginSSHHostKey   = "53491" // SSH Host Key Fingerprint
	nessusPluginSSHVersion   = "10267" // SSH Server Type and Version
	nessusPluginTLSCert      = "10863" // SSL Certificate Information
	nessusPluginTLSCert2     = "70544" // SSL Certificate
	nessusPluginSMB2         = "57608" // SMB2 Use Case Supported (has GUID)
	nessusPluginSMBNative    = "10785" // Microsoft Windows SMB NativeLanManager
	nessusPluginSNMPSettings = "40448" // SNMP Supported Protocols Detection
	nessusPluginSNMPEngine   = "161"   // SNMP Request
	nessusPluginSNMPCommName = "41028" // SNMP Agent Default Community Name
	nessusPluginTraceroute   = "10287" // Traceroute Information
)

// reSSHFP matches RSA/ECDSA/ED25519 fingerprint lines like:
// "RSA key fingerprint: aa:bb:cc:..."
// "SHA256:aBcDef..."
// "fingerprint: aa:bb:cc:..."
var reSSHFP = regexp.MustCompile(`(?i)(?:fingerprint|sha256|md5)[\s:]+([0-9a-f]{2}(?::[0-9a-f]{2}){15,})|(?:SHA256:([A-Za-z0-9+/]{43}=?))`)

// reTLSFP matches lines like: "SHA-1 Fingerprint: AA:BB:CC:..." or "SHA-1: AA:BB:CC:..."
var reTLSFP = regexp.MustCompile(`(?i)SHA[-\s]?1\s*(?:fingerprint\s*[:=]\s*|[:=]\s*)([0-9A-Fa-f:]{59})`)

// reSMBGUID matches Windows SMB2 session/server GUID values.
var reSMBGUID = regexp.MustCompile(`(?i)(?:guid|GUID)\s*[=:]\s*(\{?[0-9a-fA-F\-]{36}\}?)`)

// reSNMPEngine matches SNMPv3 engine ID hex strings, optionally prefixed with 0x.
var reSNMPEngine = regexp.MustCompile(`(?i)engine\s*id\s*[=:]\s*(?:0x)?([0-9a-fA-F]{10,})`)

// extractSSHFP extracts the SSH host key fingerprint from text using reSSHFP.
// Returns empty string if no match is found.
func extractSSHFP(text string) string {
	m := reSSHFP.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	// Group 1: colon-hex fingerprint
	if m[1] != "" {
		return normalizeFingerprint(m[1])
	}
	// Group 2: SHA256 base64 fingerprint (without SHA256: prefix)
	if m[2] != "" {
		return "SHA256:" + m[2]
	}
	return ""
}

// reTracerouteHop matches lines like "1  192.168.1.1" or "  2  10.0.0.1  1.234 ms"
var reTracerouteHop = regexp.MustCompile(`^\s*(\d+)\s+([\d.]+(?:\.\d+){3})\b`)

// reBareIPv4 matches a line containing only an IPv4 address (optionally whitespace-padded).
// Used for Nessus traceroute plugin output which lists bare IPs without hop numbers.
var reBareIPv4 = regexp.MustCompile(`^\s*((?:\d{1,3}\.){3}\d{1,3})\s*$`)

// ParseNessus parses a .nessus XML report file into ParsedHosts.
func ParseNessus(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("nessus: open %s: %w", path, err)
	}
	defer fd.Close()

	var doc nessusClientData
	if err = xml.NewDecoder(fd).Decode(&doc); err != nil {
		return nil, fmt.Errorf("nessus: decode %s: %w", path, err)
	}

	result := &ParseResult{}
	for i := range doc.Report.Hosts {
		rh := &doc.Report.Hosts[i]
		ph := parseNessusHost(rh)
		if ph != nil {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	return result, nil
}

func parseNessusHost(rh *nessusReportHost) *ParsedHost {
	ph := &ParsedHost{
		Source:     FileTypeNessus,
		Sources:    []string{"nessus"},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	// Parse HostProperties tags
	props := make(map[string]string)
	for _, tag := range rh.Properties.Tags {
		props[tag.Name] = strings.TrimSpace(tag.Value)
	}

	// IP address — prefer host-ip tag, fallback to ReportHost name attribute
	if ip := props["host-ip"]; ip != "" {
		ph.Addresses = append(ph.Addresses, ip)
	} else if rh.Name != "" {
		ph.Addresses = append(ph.Addresses, rh.Name)
	}

	// Additional IPs
	for _, key := range []string{"host-ip6", "ipv6-address"} {
		if v := props[key]; v != "" {
			ph.Addresses = appendUnique(ph.Addresses, v)
		}
	}

	// Hostnames
	for _, key := range []string{"host-fqdn", "netbios-name", "hostname"} {
		if v := props[key]; v != "" {
			ph.Names = appendUnique(ph.Names, v)
		}
	}

	// OS
	if os := props["operating-system"]; os != "" {
		ph.OS = os
	}

	// MAC
	if mac := props["mac-address"]; mac != "" {
		normalized := normalizeMACAddress(mac)
		ph.MACs = appendUnique(ph.MACs, normalized)
		ph.Attributes["mac_address"] = normalized
	}

	// System type
	if st := props["system-type"]; st != "" {
		ph.Attributes["system_type"] = st
	}

	if len(ph.Addresses) == 0 {
		return nil
	}

	primaryIP := ph.Addresses[0]

	// Track open ports as services; deduplicated by port+proto
	type portKey struct{ port, proto string }
	seenPorts := make(map[portKey]bool)

	for i := range rh.Items {
		item := &rh.Items[i]
		if item.Port == "0" || item.Port == "" {
			// Plugin-level metadata, not a real port
			extractNessusFingerprints(ph, item)
			continue
		}

		pk := portKey{item.Port, item.Protocol}
		if !seenPorts[pk] {
			seenPorts[pk] = true
			svc := ParsedService{
				Address:    primaryIP,
				Port:       item.Port,
				Protocol:   item.Protocol,
				Attributes: make(map[string]string),
			}
			if item.SvcName != "" {
				svc.Attributes["service_name"] = item.SvcName
			}
			ph.Services = append(ph.Services, svc)
		}

		extractNessusFingerprints(ph, item)

		// Extract vulnerabilities (severity > 0).
		if item.Severity != "" && item.Severity != "0" {
			pv := ParsedVuln{
				ID:          item.PluginID,
				Title:       item.PluginName,
				Severity:    item.Severity,
				CVEs:        item.CVEs,
				Source:      "nessus",
				Description: strings.TrimSpace(item.Synopsis),
				RiskFactor:  strings.TrimSpace(item.RiskFactor),
			}
			// Prefer CVSS v3 score; fall back to v2.
			switch {
			case item.CVSS3BaseScore != "":
				pv.CVSSScore = item.CVSS3BaseScore
			case item.CVSSBaseScore != "":
				pv.CVSSScore = item.CVSSBaseScore
			}
			ph.Vulns = append(ph.Vulns, pv)
		}
	}

	return ph
}

// extractNessusFingerprints reads plugin output for known identity data.
func extractNessusFingerprints(ph *ParsedHost, item *nessusReportItem) {
	out := item.Output + "\n" + item.Description

	switch item.PluginID {
	case nessusPluginSSHHostKey:
		fp := extractSSHFP(out)
		if fp != "" {
			ph.UniqueKeys["ssh_hostkey_fp"] = fp
			ph.Attributes["ssh_hostkey_fp"] = fp
		}

	case nessusPluginTLSCert, nessusPluginTLSCert2:
		if m := reTLSFP.FindStringSubmatch(out); len(m) >= 2 {
			fp := normalizeFingerprint(m[1])
			if fp != "" {
				ph.UniqueKeys["tls_cert_fp"] = fp
				ph.Attributes["tls_cert_fp"] = fp
			}
		}
		// Also try generic fingerprint lines
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "sha") && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					fp := normalizeFingerprint(strings.TrimSpace(parts[1]))
					if isFingerprintHex(fp) {
						ph.UniqueKeys["tls_cert_fp"] = fp
						ph.Attributes["tls_cert_fp"] = fp
						break
					}
				}
			}
		}

	case nessusPluginSMB2, nessusPluginSMBNative:
		if m := reSMBGUID.FindStringSubmatch(out); len(m) >= 2 {
			guid := strings.Trim(m[1], "{}")
			if guid != "" {
				ph.UniqueKeys["smb_guid"] = guid
				ph.Attributes["smb_guid"] = guid
			}
		}

	case nessusPluginSNMPSettings, nessusPluginSNMPEngine:
		if m := reSNMPEngine.FindStringSubmatch(out); len(m) >= 2 {
			eid := strings.ReplaceAll(m[1], " ", "")
			if eid != "" {
				ph.UniqueKeys["snmpv3_engine_id"] = eid
				ph.Attributes["snmpv3_engine_id"] = eid
			}
		}

	case nessusPluginSNMPCommName:
		// Plugin 41028 output format:
		//   The remote SNMP server replies to the following default community
		//   string :
		//
		//   public
		extractNessusSNMPCommunity(ph, out)

	case nessusPluginTraceroute:
		// Parse traceroute hops from plugin 10287 output.
		// Two formats are supported:
		//   Numbered:   "1  192.168.1.1\n2  10.0.0.1\n..."
		//   Nessus:     bare IPs in order (scanner, hops..., target)
		lines := strings.Split(out, "\n")

		// Try numbered format first.
		var numbered []TracerouteHop
		for _, line := range lines {
			if m := reTracerouteHop.FindStringSubmatch(line); len(m) >= 3 {
				ttl, _ := strconv.Atoi(m[1])
				ip := strings.TrimSpace(m[2])
				if ttl > 0 && ip != "" {
					numbered = append(numbered, TracerouteHop{
						TTL:       ttl,
						Addresses: []string{ip},
					})
				}
			}
		}

		if len(numbered) > 0 {
			ph.TracerouteHops = append(ph.TracerouteHops, numbered...)
		} else {
			// Fallback: Nessus bare-IP format.
			// Lines are in order: scanner, intermediate hops, target.
			// We emit only intermediate hops (skip first and last).
			var bareIPs []string
			for _, line := range lines {
				if m := reBareIPv4.FindStringSubmatch(line); len(m) >= 2 {
					bareIPs = append(bareIPs, m[1])
				}
			}
			if len(bareIPs) > 2 {
				for i, ip := range bareIPs[1 : len(bareIPs)-1] {
					ph.TracerouteHops = append(ph.TracerouteHops, TracerouteHop{
						TTL:       i + 1,
						Addresses: []string{ip},
					})
				}
			}
		}
	}
}

// normalizeFingerprint strips spaces and normalises a fingerprint string to
// lowercase colon-separated hex when applicable.  SHA256:... base64 fingerprints
// are left as-is.
func normalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if strings.HasPrefix(fp, "SHA256:") {
		return fp
	}
	return normalizeHexFingerprint(fp)
}

// normalizeHexFingerprint converts a hex fingerprint to lowercase colon-separated form.
// Input may be "AA:BB:CC", "AABBCC", "AA BB CC", or "aa:bb:cc".
func normalizeHexFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return ""
	}
	// Already colon-separated → just lowercase
	if strings.Contains(fp, ":") {
		return strings.ToLower(fp)
	}
	// Space-separated → colon-separate and lowercase
	if strings.Contains(fp, " ") {
		parts := strings.Fields(fp)
		return strings.ToLower(strings.Join(parts, ":"))
	}
	// Continuous hex string → insert colons every 2 chars
	fp = strings.ToLower(fp)
	var out strings.Builder
	for i, c := range fp {
		if i > 0 && i%2 == 0 {
			out.WriteByte(':')
		}
		out.WriteRune(c)
	}
	return out.String()
}

// normalizeMACAddress converts a MAC address to the canonical aa:bb:cc:dd:ee:ff form.
func normalizeMACAddress(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	// Handle space-separated hex: "AA BB CC DD EE FF"
	if strings.Contains(mac, " ") {
		parts := strings.Fields(mac)
		if len(parts) == 6 {
			return strings.ToLower(strings.Join(parts, ":"))
		}
	}
	// Handle dash-separated: "AA-BB-CC-DD-EE-FF"
	mac = strings.ReplaceAll(mac, "-", ":")
	// Already colon-separated
	if strings.Contains(mac, ":") {
		return strings.ToLower(mac)
	}
	// Continuous hex: "AABBCCDDEEFF"
	if len(mac) == 12 {
		mac = strings.ToLower(mac)
		return mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
	}
	return strings.ToLower(mac)
}

// isFingerprintHex returns true if s looks like a colon-separated hex fingerprint.
// We require at least 8 colon-separated pairs (64-bit minimum) so that short
// hex strings like SMB GUIDs or serial numbers are not misidentified.
// SHA-1 fingerprints have 20 pairs; MD5 has 16 pairs — both exceed this threshold.
func isFingerprintHex(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) < 8 {
		return false
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) != 2 {
			return false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// isHexString returns true if s is a non-empty string containing only hexadecimal
// characters (0-9, a-f, A-F). Used to validate raw fingerprint values from parsers.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// extractNessusSNMPCommunity extracts SNMP community strings from plugin 41028
// output and appends them to the host's snmp_communities attribute.
func extractNessusSNMPCommunity(ph *ParsedHost, text string) {
	// The output format is free-text with the community name on its own line
	// after the descriptive text. We look for non-empty, non-boilerplate lines.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip known boilerplate lines from plugin 41028
		lower := strings.ToLower(line)
		if strings.Contains(lower, "remote snmp") ||
			strings.Contains(lower, "community") ||
			strings.Contains(lower, "string") ||
			strings.Contains(lower, "default") ||
			strings.Contains(lower, "description") ||
			strings.HasPrefix(lower, "nessus") ||
			strings.HasPrefix(lower, "plugin") ||
			strings.HasPrefix(lower, "the ") ||
			strings.HasPrefix(lower, "this ") {
			continue
		}
		// Whatever remains should be a community name
		community := line
		existing := ph.Attributes["snmp_communities"]
		if existing == "" {
			ph.Attributes["snmp_communities"] = community
		} else if !strings.Contains(existing, community) {
			ph.Attributes["snmp_communities"] = existing + "," + community
		}
	}
}
