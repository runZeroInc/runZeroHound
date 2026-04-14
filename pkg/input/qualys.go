package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// Qualys VM scan XML document structure.
// Reference: Qualys VM scan XML export format.

type qualysScan struct {
	XMLName xml.Name   `xml:"SCAN"`
	IPs     []qualysIP `xml:"IP"`
}

type qualysIP struct {
	Value    string         `xml:"value,attr"`
	Name     string         `xml:"name,attr"`
	OS       string         `xml:"OS"`
	Infos    qualysCatGroup `xml:"INFOS"`
	Services qualysCatGroup `xml:"SERVICES"`
	Vulns    qualysCatGroup `xml:"VULNS"`
}

type qualysCatGroup struct {
	Cats []qualysCat `xml:"CAT"`
}

type qualysCat struct {
	Port     string        `xml:"port,attr"`
	Protocol string        `xml:"protocol,attr"`
	Value    string        `xml:"value,attr"`
	Infos    []qualysEntry `xml:"INFO"`
	Services []qualysEntry `xml:"SERVICE"`
	Vulns    []qualysEntry `xml:"VULN"`
}

type qualysEntry struct {
	Number   string        `xml:"number,attr"`
	Severity string        `xml:"severity,attr"`
	Result   string        `xml:"RESULT"`
	Title    string        `xml:"TITLE"`
	CVEIDs   []qualysCVEID `xml:"CVE_ID_LIST>CVE_ID"`
}

type qualysCVEID struct {
	ID string `xml:"ID"`
}

// ParseQualys parses a Qualys VM scan XML report into ParsedHosts.
func ParseQualys(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("qualys: open %s: %w", path, err)
	}
	defer fd.Close()

	var scan qualysScan
	if err = xml.NewDecoder(fd).Decode(&scan); err != nil {
		return nil, fmt.Errorf("qualys: decode %s: %w", path, err)
	}

	result := &ParseResult{}
	for i := range scan.IPs {
		ph := parseQualysIP(&scan.IPs[i])
		if ph != nil && len(ph.Addresses) > 0 {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	return result, nil
}

func parseQualysIP(ip *qualysIP) *ParsedHost {
	if ip.Value == "" {
		return nil
	}

	ph := &ParsedHost{
		Source:     FileTypeQualys,
		Sources:    []string{"qualys"},
		Addresses:  []string{ip.Value},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	if ip.Name != "" {
		ph.Names = appendUnique(ph.Names, ip.Name)
	}

	if ip.OS != "" {
		ph.OS = strings.TrimSpace(ip.OS)
	}

	// Track seen ports to avoid duplicates.
	type portKey struct{ port, proto string }
	seenPorts := make(map[portKey]bool)

	addPort := func(cat *qualysCat) {
		if cat.Port == "" || cat.Port == "0" {
			return
		}
		proto := strings.ToLower(cat.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		pk := portKey{cat.Port, proto}
		if seenPorts[pk] {
			return
		}
		seenPorts[pk] = true
		svc := ParsedService{
			Address:    ip.Value,
			Port:       cat.Port,
			Protocol:   proto,
			Attributes: make(map[string]string),
		}
		if cat.Value != "" {
			svc.Attributes["service_name"] = cat.Value
		}
		ph.Services = append(ph.Services, svc)
	}

	processCats := func(cats []qualysCat, entries func(*qualysCat) []qualysEntry) {
		for i := range cats {
			cat := &cats[i]
			addPort(cat)
			for _, entry := range entries(cat) {
				extractQualysFingerprints(ph, cat, &entry)
			}
		}
	}

	processCats(ip.Infos.Cats, func(c *qualysCat) []qualysEntry { return c.Infos })
	processCats(ip.Services.Cats, func(c *qualysCat) []qualysEntry { return c.Services })
	processCats(ip.Vulns.Cats, func(c *qualysCat) []qualysEntry { return c.Vulns })

	// Extract vulnerabilities from the VULNS section.
	for i := range ip.Vulns.Cats {
		cat := &ip.Vulns.Cats[i]
		for _, entry := range cat.Vulns {
			pv := ParsedVuln{
				ID:       entry.Number,
				Title:    strings.TrimSpace(entry.Title),
				Severity: entry.Severity,
				Source:   "qualys",
			}
			for _, cid := range entry.CVEIDs {
				id := strings.TrimSpace(cid.ID)
				if id != "" {
					pv.CVEs = append(pv.CVEs, id)
				}
			}
			ph.Vulns = append(ph.Vulns, pv)
		}
	}

	return ph
}

// extractQualysFingerprints reads RESULT elements for known identity data.
func extractQualysFingerprints(ph *ParsedHost, cat *qualysCat, entry *qualysEntry) {
	result := strings.TrimSpace(entry.Result)
	if result == "" {
		return
	}

	svcName := strings.ToLower(cat.Value)

	// Extract MAC addresses from results
	if strings.Contains(strings.ToLower(result), "mac") {
		for _, line := range strings.Split(result, "\n") {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			if strings.Contains(lower, "mac") && strings.Contains(lower, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					mac := normalizeMACAddress(strings.TrimSpace(parts[1]))
					if mac != "" && len(strings.Split(mac, ":")) == 6 {
						ph.MACs = appendUnique(ph.MACs, mac)
						ph.Attributes["mac_address"] = mac
					}
				}
			}
		}
	}

	// SSH fingerprint extraction
	if strings.Contains(svcName, "ssh") || strings.Contains(strings.ToLower(result), "ssh") {
		fp := extractSSHFP(result)
		if fp != "" {
			ph.UniqueKeys["ssh_hostkey_fp"] = fp
			ph.Attributes["ssh_hostkey_fp"] = fp
		}
	}

	// TLS/SSL fingerprint extraction
	if strings.Contains(svcName, "ssl") || strings.Contains(svcName, "tls") ||
		strings.Contains(svcName, "https") || strings.Contains(strings.ToLower(result), "sha") {
		if m := reTLSFP.FindStringSubmatch(result); len(m) >= 2 {
			fp := normalizeFingerprint(m[1])
			if fp != "" {
				ph.UniqueKeys["tls_cert_fp"] = fp
				ph.Attributes["tls_cert_fp"] = fp
			}
		}
	}

	// SMB GUID extraction
	if strings.Contains(svcName, "smb") || strings.Contains(svcName, "cifs") ||
		strings.Contains(strings.ToLower(result), "guid") {
		if m := reSMBGUID.FindStringSubmatch(result); len(m) >= 2 {
			guid := strings.Trim(m[1], "{}")
			if guid != "" {
				ph.UniqueKeys["smb_guid"] = guid
				ph.Attributes["smb_guid"] = guid
			}
		}
	}

	// SNMP engine ID extraction
	if strings.Contains(svcName, "snmp") || strings.Contains(strings.ToLower(result), "engine") {
		if m := reSNMPEngine.FindStringSubmatch(result); len(m) >= 2 {
			eid := strings.ReplaceAll(m[1], " ", "")
			if eid != "" {
				ph.UniqueKeys["snmpv3_engine_id"] = eid
				ph.Attributes["snmpv3_engine_id"] = eid
			}
		}
	}
}
