package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// reCVEInID matches CVE identifiers embedded in Nexpose vulnerability IDs like "azul-zulu-cve-2023-22006".
var reCVEInID = regexp.MustCompile(`(?i)(cve-\d{4}-\d{4,})`)

// Nexpose XML document structures.
// Three formats are supported:
//   - NeXposeSimpleXML (simple export)
//   - NexposeReport version="1.0" (v1 raw XML export)
//   - NexposeReport version="2.0" (v2 raw XML export with extra attrs)

// --- Simple XML format ---

type nexposeSimpleXML struct {
	XMLName xml.Name              `xml:"NeXposeSimpleXML"`
	Devices []nexposeSimpleDevice `xml:"devices>device"`
}

type nexposeSimpleDevice struct {
	Address  string                       `xml:"address,attr"`
	ID       string                       `xml:"id,attr"`
	FP       *nexposeSimpleFingerprint    `xml:"fingerprint"`
	Services []nexposeSimpleService       `xml:"services>service"`
	Vulns    []nexposeSimpleVulnerability `xml:"vulnerabilities>vulnerability"`
}

type nexposeSimpleFingerprint struct {
	Certainty   string `xml:"certainty,attr"`
	Description string `xml:"description"`
	Vendor      string `xml:"vendor"`
	Family      string `xml:"family"`
	Product     string `xml:"product"`
	Version     string `xml:"version"`
	DeviceClass string `xml:"device-class"`
}

type nexposeSimpleService struct {
	Name     string                       `xml:"name,attr"`
	Port     string                       `xml:"port,attr"`
	Protocol string                       `xml:"protocol,attr"`
	FP       *nexposeSimpleSvcFingerprint `xml:"fingerprint"`
	Vulns    []nexposeSimpleVulnerability `xml:"vulnerabilities>vulnerability"`
}

type nexposeSimpleSvcFingerprint struct {
	Certainty   string `xml:"certainty,attr"`
	Description string `xml:"description"`
	Vendor      string `xml:"vendor"`
	Family      string `xml:"family"`
	Product     string `xml:"product"`
	Version     string `xml:"version"`
}

type nexposeSimpleVulnerability struct {
	ID         string `xml:"id,attr"`
	ResultCode string `xml:"resultCode,attr"`
}

// --- NexposeReport v1/v2 format ---

type nexposeReport struct {
	XMLName xml.Name      `xml:"NexposeReport"`
	Version string        `xml:"version,attr"`
	Scans   []nexposeScan `xml:"scans>scan"`
	Nodes   []nexposeNode `xml:"nodes>node"`
	VulnDef []nexposeVuln `xml:"VulnerabilityDefinitions>vulnerability"`
}

type nexposeScan struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

type nexposeNode struct {
	Address   string              `xml:"address,attr"`
	Status    string              `xml:"status,attr"`
	HWAddress string              `xml:"hardware-address,attr"`
	DeviceID  string              `xml:"device-id,attr"`
	SiteName  string              `xml:"site-name,attr"`
	RiskScore string              `xml:"risk-score,attr"`
	Names     []nexposeNodeName   `xml:"names>name"`
	OSFPs     []nexposeOSFP       `xml:"fingerprints>os"`
	Software  []nexposeSoftwareFP `xml:"software>fingerprint"`
	Endpoints []nexposeEndpoint   `xml:"endpoints>endpoint"`
	Tests     []nexposeTest       `xml:"tests>test"`
}

type nexposeNodeName struct {
	Value string `xml:",chardata"`
}

type nexposeOSFP struct {
	Certainty   string `xml:"certainty,attr"`
	Vendor      string `xml:"vendor,attr"`
	Family      string `xml:"family,attr"`
	Product     string `xml:"product,attr"`
	Version     string `xml:"version,attr"`
	Arch        string `xml:"arch,attr"`
	DeviceClass string `xml:"device-class,attr"`
}

type nexposeSoftwareFP struct {
	Certainty     string `xml:"certainty,attr"`
	SoftwareClass string `xml:"software-class,attr"`
	Vendor        string `xml:"vendor,attr"`
	Family        string `xml:"family,attr"`
	Product       string `xml:"product,attr"`
	Version       string `xml:"version,attr"`
}

type nexposeEndpoint struct {
	Protocol string               `xml:"protocol,attr"`
	Port     string               `xml:"port,attr"`
	Status   string               `xml:"status,attr"`
	Services []nexposeEndpointSvc `xml:"services>service"`
	Tests    []nexposeTest        `xml:"tests>test"`
}

type nexposeEndpointSvc struct {
	Name    string                `xml:"name,attr"`
	FP      *nexposeEndpointSvcFP `xml:"fingerprint"`
	Configs []nexposeConfig       `xml:"configuration>config"`
	Tests   []nexposeTest         `xml:"tests>test"`
}

type nexposeEndpointSvcFP struct {
	Certainty string `xml:"certainty,attr"`
	Vendor    string `xml:"vendor,attr"`
	Family    string `xml:"family,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
}

type nexposeConfig struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nexposeTest struct {
	ID     string `xml:"id,attr"`
	Status string `xml:"status,attr"`
	Key    string `xml:"key,attr"`
}

type nexposeVuln struct {
	ID       string             `xml:"id,attr"`
	Title    string             `xml:"title,attr"`
	Severity string             `xml:"severity,attr"`
	Refs     []nexposeReference `xml:"references>reference"`
}

type nexposeReference struct {
	Source string `xml:"source,attr"`
	Value  string `xml:",chardata"`
}

// ParseNexpose parses a Rapid7 Nexpose/InsightVM XML report.
// Supports NeXposeSimpleXML and NexposeReport (v1/v2) formats.
func ParseNexpose(path string) (*ParseResult, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("nexpose: open %s: %w", path, err)
	}

	// Try NexposeReport first (v1/v2), then simple XML.
	if strings.Contains(string(data[:min(512, len(data))]), "NexposeReport") {
		return parseNexposeReport(data)
	}
	if strings.Contains(string(data[:min(512, len(data))]), "NeXposeSimpleXML") {
		return parseNexposeSimple(data)
	}
	return nil, fmt.Errorf("nexpose: unrecognized format in %s", path)
}

func parseNexposeSimple(data []byte) (*ParseResult, error) {
	var doc nexposeSimpleXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nexpose simple: decode: %w", err)
	}

	result := &ParseResult{}
	for i := range doc.Devices {
		dev := &doc.Devices[i]
		ph := parseSimpleDevice(dev)
		if ph != nil {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	return result, nil
}

func parseSimpleDevice(dev *nexposeSimpleDevice) *ParsedHost {
	if dev.Address == "" {
		return nil
	}

	ph := &ParsedHost{
		Source:     FileTypeNexpose,
		Sources:    []string{"nexpose"},
		Addresses:  []string{dev.Address},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	if dev.FP != nil {
		if dev.FP.Description != "" {
			ph.OS = dev.FP.Description
		} else if dev.FP.Product != "" {
			ph.OS = dev.FP.Product
			if dev.FP.Version != "" {
				ph.OS += " " + dev.FP.Version
			}
		}
		if dev.FP.Vendor != "" {
			ph.Attributes["os_vendor"] = dev.FP.Vendor
		}
		if dev.FP.DeviceClass != "" {
			ph.Attributes["device_class"] = dev.FP.DeviceClass
		}
	}

	// Vulnerability count
	vulnCount := len(dev.Vulns)

	// Extract device-level vulns.
	for _, v := range dev.Vulns {
		pv := ParsedVuln{
			ID:     v.ID,
			Title:  v.ID,
			Source: "nexpose",
		}
		if matches := reCVEInID.FindAllStringSubmatch(v.ID, -1); len(matches) > 0 {
			for _, m := range matches {
				pv.CVEs = append(pv.CVEs, strings.ToUpper(m[1]))
			}
		}
		ph.Vulns = append(ph.Vulns, pv)
	}

	for i := range dev.Services {
		svc := &dev.Services[i]
		ps := ParsedService{
			Address:    dev.Address,
			Port:       svc.Port,
			Protocol:   svc.Protocol,
			Attributes: make(map[string]string),
		}
		if svc.Name != "" {
			ps.Attributes["service_name"] = svc.Name
		}
		if svc.FP != nil {
			if svc.FP.Product != "" {
				ps.Product = svc.FP.Product
			}
			if svc.FP.Version != "" {
				ps.Version = svc.FP.Version
			}
			if svc.FP.Vendor != "" {
				ps.Attributes["vendor"] = svc.FP.Vendor
			}
		}
		// Extract service-level vulns.
		for _, v := range svc.Vulns {
			pv := ParsedVuln{
				ID:     v.ID,
				Title:  v.ID,
				Source: "nexpose",
			}
			if matches := reCVEInID.FindAllStringSubmatch(v.ID, -1); len(matches) > 0 {
				for _, m := range matches {
					pv.CVEs = append(pv.CVEs, strings.ToUpper(m[1]))
				}
			}
			ph.Vulns = append(ph.Vulns, pv)
		}
		vulnCount += len(svc.Vulns)
		ph.Services = append(ph.Services, ps)
	}

	if vulnCount > 0 {
		ph.Attributes["vulnerability_count"] = fmt.Sprintf("%d", vulnCount)
	}

	return ph
}

// nexposeVulnInfo holds pre-parsed vulnerability definition data.
type nexposeVulnInfo struct {
	Title    string
	Severity string
	CVEs     []string
}

func parseNexposeReport(data []byte) (*ParseResult, error) {
	var doc nexposeReport
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nexpose report: decode: %w", err)
	}

	// Build vulnerability definition lookup.
	vulnDefs := make(map[string]*nexposeVulnInfo, len(doc.VulnDef))
	for i := range doc.VulnDef {
		vd := &doc.VulnDef[i]
		info := &nexposeVulnInfo{
			Title:    vd.Title,
			Severity: vd.Severity,
		}
		for _, ref := range vd.Refs {
			if ref.Source == "CVE" && ref.Value != "" {
				info.CVEs = append(info.CVEs, strings.TrimSpace(ref.Value))
			}
		}
		vulnDefs[vd.ID] = info
	}

	result := &ParseResult{}
	for i := range doc.Nodes {
		node := &doc.Nodes[i]
		ph := parseReportNode(node, vulnDefs)
		if ph != nil {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	return result, nil
}

func parseReportNode(node *nexposeNode, vulnDefs map[string]*nexposeVulnInfo) *ParsedHost {
	if node.Address == "" {
		return nil
	}

	// Skip down hosts
	if node.Status != "" && node.Status != "alive" {
		return nil
	}

	ph := &ParsedHost{
		Source:     FileTypeNexpose,
		Sources:    []string{"nexpose"},
		Addresses:  []string{node.Address},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	// MAC address
	if node.HWAddress != "" {
		mac := normalizeNexposeMAC(node.HWAddress)
		ph.MACs = appendUnique(ph.MACs, mac)
		ph.Attributes["mac_address"] = mac
	}

	// Names
	for _, n := range node.Names {
		v := strings.TrimSpace(n.Value)
		if v != "" {
			ph.Names = appendUnique(ph.Names, v)
		}
	}

	// OS fingerprint — pick highest certainty
	if len(node.OSFPs) > 0 {
		best := node.OSFPs[0]
		for _, fp := range node.OSFPs[1:] {
			if fp.Certainty > best.Certainty {
				best = fp
			}
		}
		os := best.Product
		if best.Version != "" {
			os += " " + best.Version
		}
		if best.Arch != "" {
			os += " (" + best.Arch + ")"
		}
		if os != "" {
			ph.OS = strings.TrimSpace(os)
		}
		if best.Vendor != "" {
			ph.Attributes["os_vendor"] = best.Vendor
		}
		if best.Family != "" {
			ph.Attributes["os_family"] = best.Family
		}
		if best.DeviceClass != "" {
			ph.Attributes["device_class"] = best.DeviceClass
		}
	}

	// v2-specific attributes
	if node.SiteName != "" {
		ph.Attributes["site_name"] = node.SiteName
	}
	if node.RiskScore != "" {
		ph.Attributes["risk_score"] = node.RiskScore
	}

	// Software count
	if len(node.Software) > 0 {
		ph.Attributes["software_count"] = fmt.Sprintf("%d", len(node.Software))
	}

	// Vulnerability count from node-level tests
	vulnCount := countVulnerableTests(node.Tests)
	extractNexposeVulns(ph, node.Tests, vulnDefs)

	// Endpoints → services
	for i := range node.Endpoints {
		ep := &node.Endpoints[i]
		if ep.Status != "" && ep.Status != "open" {
			continue
		}
		ps := ParsedService{
			Address:    node.Address,
			Port:       ep.Port,
			Protocol:   ep.Protocol,
			Attributes: make(map[string]string),
		}

		// Extract service name and fingerprint from endpoint services
		for _, svc := range ep.Services {
			if svc.Name != "" && svc.Name != "<unknown>" {
				ps.Attributes["service_name"] = svc.Name
			}
			if svc.FP != nil {
				if svc.FP.Product != "" {
					ps.Product = svc.FP.Product
				}
				if svc.FP.Version != "" {
					ps.Version = svc.FP.Version
				}
				if svc.FP.Vendor != "" {
					ps.Attributes["vendor"] = svc.FP.Vendor
				}
			}

			// Extract interesting config values
			for _, cfg := range svc.Configs {
				extractNexposeConfig(ph, &ps, cfg)
			}

			vulnCount += countVulnerableTests(svc.Tests)
			extractNexposeVulns(ph, svc.Tests, vulnDefs)
		}

		vulnCount += countVulnerableTests(ep.Tests)
		extractNexposeVulns(ph, ep.Tests, vulnDefs)
		ph.Services = append(ph.Services, ps)
	}

	if vulnCount > 0 {
		ph.Attributes["vulnerability_count"] = fmt.Sprintf("%d", vulnCount)
	}

	return ph
}

// extractNexposeConfig extracts identity/fingerprint data from Nexpose service
// configuration entries.
func extractNexposeConfig(ph *ParsedHost, ps *ParsedService, cfg nexposeConfig) {
	switch {
	case strings.HasPrefix(cfg.Name, "ssh.hostkey.") && strings.HasSuffix(cfg.Name, ".fingerprint") && cfg.Value != "":
		fp := normalizeFingerprint(cfg.Value)
		if fp != "" {
			// Use the first SSH host key fingerprint found (prefer RSA, then others)
			if _, exists := ph.UniqueKeys["ssh_hostkey_fp"]; !exists {
				ph.UniqueKeys["ssh_hostkey_fp"] = fp
			}
			ph.Attributes["ssh_hostkey_fp"] = fp
		}
	case cfg.Name == "ssl.cert.sha1.fingerprint" && cfg.Value != "":
		fp := normalizeFingerprint(cfg.Value)
		if fp != "" {
			ph.UniqueKeys["tls_cert_fp"] = fp
			ph.Attributes["tls_cert_fp"] = fp
		}
	case cfg.Name == "ssl.cert.subject.dn":
		ps.Attributes["tls_subject"] = cfg.Value
	case cfg.Name == "ssl.cert.issuer.dn":
		ps.Attributes["tls_issuer"] = cfg.Value
	}
}

// countVulnerableTests counts tests with vulnerable status.
func countVulnerableTests(tests []nexposeTest) int {
	count := 0
	for _, t := range tests {
		if strings.HasPrefix(t.Status, "vulnerable") {
			count++
		}
	}
	return count
}

// extractNexposeVulns creates ParsedVuln entries from Nexpose tests using the
// vulnerability definition lookup.
func extractNexposeVulns(ph *ParsedHost, tests []nexposeTest, vulnDefs map[string]*nexposeVulnInfo) {
	for _, t := range tests {
		if !strings.HasPrefix(t.Status, "vulnerable") {
			continue
		}
		pv := ParsedVuln{
			ID:     t.ID,
			Source: "nexpose",
		}
		if info, ok := vulnDefs[t.ID]; ok {
			pv.Title = info.Title
			pv.Severity = info.Severity
			pv.CVEs = info.CVEs
		} else {
			// Try to extract CVE from the vuln ID itself.
			pv.Title = t.ID
			if matches := reCVEInID.FindAllStringSubmatch(t.ID, -1); len(matches) > 0 {
				for _, m := range matches {
					pv.CVEs = append(pv.CVEs, strings.ToUpper(m[1]))
				}
			}
		}
		ph.Vulns = append(ph.Vulns, pv)
	}
}

// normalizeNexposeMAC converts a bare hex MAC like "000C29D22B02" to "00:0c:29:d2:2b:02".
func normalizeNexposeMAC(raw string) string {
	raw = strings.ReplaceAll(raw, ":", "")
	raw = strings.ReplaceAll(raw, "-", "")
	raw = strings.ToLower(raw)
	if len(raw) != 12 {
		return raw
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		raw[0:2], raw[2:4], raw[4:6],
		raw[6:8], raw[8:10], raw[10:12])
}
