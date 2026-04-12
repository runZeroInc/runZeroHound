package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Nessus XML document structure (.nessus files).
// Reference: https://community.tenable.com/s/article/Nessus-v2-File-Format

type nessusClientData struct {
	XMLName xml.Name      `xml:"NessusClientData_v2"`
	Report  nessusReport  `xml:"Report"`
}

type nessusReport struct {
	Name  string            `xml:"name,attr"`
	Hosts []nessusReportHost `xml:"ReportHost"`
}

type nessusReportHost struct {
	Name       string              `xml:"name,attr"`
	Properties nessusHostProps     `xml:"HostProperties"`
	Items      []nessusReportItem  `xml:"ReportItem"`
}

type nessusHostProps struct {
	Tags []nessusTag `xml:"tag"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusReportItem struct {
	Port       string `xml:"port,attr"`
	SvcName    string `xml:"svc_name,attr"`
	Protocol   string `xml:"protocol,attr"`
	Severity   string `xml:"severity,attr"`
	PluginID   string `xml:"pluginID,attr"`
	PluginName string `xml:"pluginName,attr"`
	Output     string `xml:"plugin_output"`
	Description string `xml:"description"`
	CVE        string `xml:"cve"`
	RiskFactor string `xml:"risk_factor"`
	Synopsis   string `xml:"synopsis"`
}

// Well-known Nessus plugin IDs that carry fingerprint/identity data.
const (
	nessusPluginSSHHostKey   = "53491" // SSH Host Key Fingerprint
	nessusPluginSSHVersion   = "10267" // SSH Server Type and Version
	nessusPluginTLSCert      = "10863" // SSL Certificate Information
	nessusPluginTLSCert2     = "70544" // SSL Certificate
	nessusPluginSMB2         = "57608" // SMB2 Use Case Supported (has GUID)
	nessusPluginSMBNative    = "10785" // Microsoft Windows SMB NativeLanManager
	nessusPluginSNMPSettings = "40448" // SNMP Agent Default Community Names
	nessusPluginSNMPEngine   = "161"   // SNMP Request
)

// reSSHFP matches RSA/ECDSA/ED25519 fingerprint lines like:
// "RSA key fingerprint: aa:bb:cc:..."
// "SHA256:aBcDef..."
var reSSHFP = regexp.MustCompile(`(?i)(fingerprint|sha256|md5)[\s:]+([0-9a-f]{2}(?::[0-9a-f]{2}){15,}|SHA256:[A-Za-z0-9+/]{43}=?)`)

// reTLSFP matches lines like: "SHA-1 Fingerprint: AA:BB:CC:..."
var reTLSFP = regexp.MustCompile(`(?i)SHA[-\s]?1\s*(?:fingerprint|:)\s*([0-9A-Fa-f:]{59})`)

// reSMBGUID matches Windows SMB2 session/server GUID values.
var reSMBGUID = regexp.MustCompile(`(?i)(?:guid|GUID)\s*[=:]\s*(\{?[0-9a-fA-F\-]{36}\}?)`)

// reSNMPEngine matches SNMPv3 engine ID hex strings.
var reSNMPEngine = regexp.MustCompile(`(?i)engine\s*id\s*[=:]\s*([0-9a-fA-F]{10,})`)

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
		ph.Attributes["mac_address"] = mac
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
	}

	return ph
}

// extractNessusFingerprints reads plugin output for known identity data.
func extractNessusFingerprints(ph *ParsedHost, item *nessusReportItem) {
	out := item.Output + "\n" + item.Description

	switch item.PluginID {
	case nessusPluginSSHHostKey:
		if m := reSSHFP.FindStringSubmatch(out); len(m) >= 3 {
			fp := normalizeFingerprint(m[2])
			if fp != "" {
				ph.UniqueKeys["ssh_hostkey_fp"] = fp
				ph.Attributes["ssh_hostkey_fp"] = fp
			}
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
	}
}

// normalizeFingerprint strips spaces from a fingerprint string.
func normalizeFingerprint(fp string) string {
	return strings.TrimSpace(fp)
}

// isFingerprintHex returns true if s looks like a colon-separated hex fingerprint.
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
