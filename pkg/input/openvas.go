package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// OpenVAS/GVM XML report structure.
// Compatible with GVM 21+ / OpenVAS 21+ report format.
// Reference: https://docs.greenbone.net/API/GMP/gmp-22.4.html

type openvasReport struct {
	XMLName xml.Name         `xml:"report"`
	ID      string           `xml:"id,attr"`
	Results openvasResults   `xml:"results"`
	Hosts   []openvasHostSum `xml:"host"`
}

type openvasResults struct {
	Results []openvasResult `xml:"result"`
}

type openvasResult struct {
	ID          string       `xml:"id,attr"`
	Name        string       `xml:"name"`
	Host        openvasHost  `xml:"host"`
	Port        string       `xml:"port"`
	NVT         openvasNVT   `xml:"nvt"`
	Description string       `xml:"description"`
	Severity    string       `xml:"severity"`
}

type openvasHost struct {
	IP       string `xml:"ip"`
	Hostname string `xml:"hostname"`
}

type openvasNVT struct {
	OID    string        `xml:"oid,attr"`
	Name   string        `xml:"name"`
	Family string        `xml:"family"`
	Tags   string        `xml:"tags"`
	Refs   []openvasRef  `xml:"refs>ref"`
}

type openvasRef struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

// openvasHostSum aggregates per-host detail entries from the <host> sections.
type openvasHostSum struct {
	IP      string             `xml:"ip"`
	Start   string             `xml:"start"`
	End     string             `xml:"end"`
	Details []openvasHostDetail `xml:"detail"`
}

type openvasHostDetail struct {
	Name   string `xml:"name"`
	Value  string `xml:"value"`
	Source openvasDetailSource `xml:"source"`
}

type openvasDetailSource struct {
	Type string `xml:"type"`
	Name string `xml:"name"`
}

// OpenVAS NVT OIDs for interesting identity data.
// OID prefix: 1.3.6.1.4.1.25623.1.0.*
const (
	oidSSHDetection   = "1.3.6.1.4.1.25623.1.0.10267"  // SSH Server Detection
	oidSSHHostKey     = "1.3.6.1.4.1.25623.1.0.103997"  // SSH Host Key Fingerprint
	oidTLSCert        = "1.3.6.1.4.1.25623.1.0.103692"  // SSL/TLS Certificate
	oidTLSCertDetails = "1.3.6.1.4.1.25623.1.0.108453"  // SSL/TLS Certificate Details
	oidSMBDetection   = "1.3.6.1.4.1.25623.1.0.10394"   // SMB Detection
	oidSNMPDetection  = "1.3.6.1.4.1.25623.1.0.10264"   // SNMP Detection
)

// ParseOpenVAS parses an OpenVAS/GVM XML report file into ParsedHosts.
func ParseOpenVAS(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("openvas: open %s: %w", path, err)
	}
	defer fd.Close()

	var report openvasReport
	if err = xml.NewDecoder(fd).Decode(&report); err != nil {
		return nil, fmt.Errorf("openvas: decode %s: %w", path, err)
	}

	return buildOpenVASResult(&report), nil
}

func buildOpenVASResult(report *openvasReport) *ParseResult {
	result := &ParseResult{}

	// First build a map of host → details from the <host> summary sections.
	hostDetails := make(map[string]map[string]string) // ip → key → value
	for _, hs := range report.Hosts {
		if hs.IP == "" {
			continue
		}
		m := make(map[string]string)
		for _, d := range hs.Details {
			if d.Name != "" && d.Value != "" {
				m[d.Name] = strings.TrimSpace(d.Value)
			}
		}
		hostDetails[hs.IP] = m
	}

	// Collect results per host.
	type hostData struct {
		ip       string
		hostname string
		ph       *ParsedHost
	}
	byIP := make(map[string]*hostData)

	getOrCreate := func(ip, hostname string) *hostData {
		hd, ok := byIP[ip]
		if !ok {
			ph := &ParsedHost{
				Source:     FileTypeOpenVAS,
				Sources:    []string{"openvas"},
				Addresses:  []string{ip},
				Attributes: make(map[string]string),
				UniqueKeys: make(map[string]string),
			}
			if hostname != "" {
				ph.Names = append(ph.Names, hostname)
			}
			// Populate from host detail section if available
			if details, ok2 := hostDetails[ip]; ok2 {
				if os := details["OS"]; os != "" {
					ph.OS = os
				}
				if hn := details["hostname"]; hn != "" && hostname == "" {
					ph.Names = appendUnique(ph.Names, hn)
				}
				if mac := details["MAC"]; mac != "" {
					normalized := normalizeMACAddress(mac)
					ph.MACs = appendUnique(ph.MACs, normalized)
					ph.Attributes["mac_address"] = normalized
				}
			}
			hd = &hostData{ip: ip, hostname: hostname, ph: ph}
			byIP[ip] = hd
		} else if hostname != "" {
			hd.ph.Names = appendUnique(hd.ph.Names, hostname)
		}
		return hd
	}

	// Track seen ports to avoid duplicate service nodes.
	type portKey struct{ ip, port, proto string }
	seenPorts := make(map[portKey]bool)

	for _, res := range report.Results.Results {
		ip := strings.TrimSpace(res.Host.IP)
		if ip == "" {
			continue
		}
		hostname := strings.TrimSpace(res.Host.Hostname)
		hd := getOrCreate(ip, hostname)
		ph := hd.ph

		// Parse port entry: "22/tcp", "443/tcp", "general/tcp"
		portStr, protoStr := parseOpenVASPort(res.Port)

		if portStr != "" && portStr != "0" && portStr != "general" {
			pk := portKey{ip, portStr, protoStr}
			if !seenPorts[pk] {
				seenPorts[pk] = true
				svc := ParsedService{
					Address:    ip,
					Port:       portStr,
					Protocol:   protoStr,
					Attributes: make(map[string]string),
				}
				ph.Services = append(ph.Services, svc)
			}
		}

		// Extract fingerprints from NVT results
		extractOpenVASFingerprints(ph, &res)

		// Extract vulnerabilities (severity > 0).
		if sev, err := strconv.ParseFloat(strings.TrimSpace(res.Severity), 64); err == nil && sev > 0 {
			pv := ParsedVuln{
				ID:       res.NVT.OID,
				Title:    res.NVT.Name,
				Severity: res.Severity,
				Source:   "openvas",
			}
			for _, ref := range res.NVT.Refs {
				if strings.EqualFold(ref.Type, "cve") && ref.ID != "" {
					pv.CVEs = append(pv.CVEs, ref.ID)
				}
			}
			ph.Vulns = append(ph.Vulns, pv)
		}
	}

	for _, hd := range byIP {
		result.Hosts = append(result.Hosts, hd.ph)
	}
	return result
}

// parseOpenVASPort splits "22/tcp" into ("22", "tcp").
func parseOpenVASPort(port string) (portStr, proto string) {
	port = strings.TrimSpace(port)
	if port == "" {
		return "", ""
	}
	parts := strings.SplitN(port, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return port, "tcp"
}

// extractOpenVASFingerprints reads known NVT results for identity data.
func extractOpenVASFingerprints(ph *ParsedHost, res *openvasResult) {
	desc := strings.TrimSpace(res.Description)
	oid := res.NVT.OID

	switch oid {
	case oidSSHHostKey:
		fp := extractSSHFP(desc)
		if fp != "" {
			ph.UniqueKeys["ssh_hostkey_fp"] = fp
			ph.Attributes["ssh_hostkey_fp"] = fp
		}

	case oidTLSCert, oidTLSCertDetails:
		if m := reTLSFP.FindStringSubmatch(desc); len(m) >= 2 {
			fp := normalizeFingerprint(m[1])
			if fp != "" {
				ph.UniqueKeys["tls_cert_fp"] = fp
				ph.Attributes["tls_cert_fp"] = fp
			}
		}

	case oidSMBDetection:
		if m := reSMBGUID.FindStringSubmatch(desc); len(m) >= 2 {
			guid := strings.Trim(m[1], "{}")
			if guid != "" {
				ph.UniqueKeys["smb_guid"] = guid
				ph.Attributes["smb_guid"] = guid
			}
		}

	case oidSNMPDetection:
		if m := reSNMPEngine.FindStringSubmatch(desc); len(m) >= 2 {
			eid := strings.ReplaceAll(m[1], " ", "")
			if eid != "" {
				ph.UniqueKeys["snmpv3_engine_id"] = eid
				ph.Attributes["snmpv3_engine_id"] = eid
			}
		}
	}

	// Also do generic fingerprint extraction on all results
	if _, ok := ph.UniqueKeys["ssh_hostkey_fp"]; !ok {
		if strings.Contains(strings.ToLower(res.NVT.Name), "ssh") {
			fp := extractSSHFP(desc)
			if fp != "" {
				ph.UniqueKeys["ssh_hostkey_fp"] = fp
				ph.Attributes["ssh_hostkey_fp"] = fp
			}
		}
	}
}
