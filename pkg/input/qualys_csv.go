package input

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseQualysCSV parses a Qualys VM scan CSV report into ParsedHosts.
//
// Qualys CSV exports begin with a metadata preamble (company info, scan
// summary), followed by a blank line, then a header row with columns:
//
//	"IP","DNS","NetBIOS","OS","IP Status","QID","Title","Type","Severity",
//	"Port","Protocol","FQDN","SSL","CVE ID",…
//
// Each row is one finding (QID) per host. Hosts are grouped by IP.
func ParseQualysCSV(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("qualys csv: open %s: %w", path, err)
	}
	defer fd.Close()

	reader := csv.NewReader(fd)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable column count

	// Find the data header row that starts with "IP".
	colIdx := make(map[string]int)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			return nil, fmt.Errorf("qualys csv: no data header found in %s", path)
		}
		if err != nil {
			continue // skip unparseable preamble lines
		}
		if len(row) > 0 && row[0] == "IP" {
			for i, col := range row {
				colIdx[col] = i
			}
			break
		}
	}

	// Validate required columns.
	for _, required := range []string{"IP"} {
		if _, ok := colIdx[required]; !ok {
			return nil, fmt.Errorf("qualys csv: missing required column %q in %s", required, path)
		}
	}

	type portKey struct{ port, proto string }
	type hostData struct {
		ph        *ParsedHost
		seenPorts map[portKey]bool
	}
	byIP := make(map[string]*hostData)

	col := func(row []string, name string) string {
		if idx, ok := colIdx[name]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		ip := col(row, "IP")
		if ip == "" {
			continue
		}

		hd, ok := byIP[ip]
		if !ok {
			hd = &hostData{
				ph: &ParsedHost{
					Source:     FileTypeQualysCSV,
					Sources:    []string{"qualys"},
					Addresses:  []string{ip},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				},
				seenPorts: make(map[portKey]bool),
			}
			byIP[ip] = hd
		}
		ph := hd.ph

		// Hostname / DNS
		if dns := col(row, "DNS"); dns != "" && dns != "No registered hostname" {
			ph.Names = appendUnique(ph.Names, dns)
		}
		if fqdn := col(row, "FQDN"); fqdn != "" {
			ph.Names = appendUnique(ph.Names, fqdn)
		}
		if nb := col(row, "NetBIOS"); nb != "" {
			ph.Names = appendUnique(ph.Names, nb)
		}

		// OS
		if osVal := col(row, "OS"); osVal != "" && ph.OS == "" {
			ph.OS = osVal
		}

		// Service / port
		port := col(row, "Port")
		proto := strings.ToLower(col(row, "Protocol"))
		if port != "" && port != "0" {
			if proto == "" {
				proto = "tcp"
			}
			pk := portKey{port, proto}
			if !hd.seenPorts[pk] {
				hd.seenPorts[pk] = true
				svc := ParsedService{
					Address:    ip,
					Port:       port,
					Protocol:   proto,
					Attributes: make(map[string]string),
				}
				if ssl := col(row, "SSL"); strings.Contains(strings.ToLower(ssl), "ssl") {
					svc.Attributes["ssl"] = "true"
				}
				ph.Services = append(ph.Services, svc)
			}
		}

		// Vulnerability / finding metadata
		severity := col(row, "Severity")
		qid := col(row, "QID")
		cve := col(row, "CVE ID")
		result := col(row, "Results")

		if severity != "" {
			// Track highest severity seen.
			if cur := ph.Attributes["max_severity"]; severity > cur {
				ph.Attributes["max_severity"] = severity
			}
		}
		if cve != "" {
			existing := ph.Attributes["cve_ids"]
			for _, c := range strings.Split(cve, ",") {
				c = strings.TrimSpace(c)
				if c != "" && !strings.Contains(existing, c) {
					if existing != "" {
						existing += ","
					}
					existing += c
				}
			}
			ph.Attributes["cve_ids"] = existing
		}

		// Count vulnerabilities.
		if col(row, "Type") == "Vuln" {
			count := ph.Attributes["vuln_count"]
			n := 0
			if count != "" {
				fmt.Sscanf(count, "%d", &n)
			}
			n++
			ph.Attributes["vuln_count"] = fmt.Sprintf("%d", n)

			// Extract vulnerability.
			pv := ParsedVuln{
				ID:       qid,
				Title:    col(row, "Title"),
				Severity: severity,
				Source:   "qualys",
			}
			if cve != "" {
				for _, c := range strings.Split(cve, ",") {
					c = strings.TrimSpace(c)
					if c != "" {
						pv.CVEs = append(pv.CVEs, c)
					}
				}
			}
			ph.Vulns = append(ph.Vulns, pv)
		}

		// Extract fingerprints from Results column using the same logic
		// as the XML parser.
		if result != "" && qid != "" {
			extractQualysCSVFingerprints(ph, qid, result)
		}
	}

	res := &ParseResult{}
	for _, hd := range byIP {
		res.Hosts = append(res.Hosts, hd.ph)
	}
	return res, nil
}

// extractQualysCSVFingerprints extracts identity data from the Results column.
func extractQualysCSVFingerprints(ph *ParsedHost, qid, result string) {
	lower := strings.ToLower(result)

	// SSH fingerprint
	if strings.Contains(lower, "ssh") || strings.Contains(lower, "fingerprint") {
		fp := extractSSHFP(result)
		if fp != "" {
			ph.UniqueKeys["ssh_hostkey_fp"] = fp
			ph.Attributes["ssh_hostkey_fp"] = fp
		}
	}

	// TLS/SSL certificate fingerprint
	if strings.Contains(lower, "sha") || strings.Contains(lower, "ssl") ||
		strings.Contains(lower, "certificate") {
		if m := reTLSFP.FindStringSubmatch(result); len(m) >= 2 {
			fp := normalizeFingerprint(m[1])
			if fp != "" {
				ph.UniqueKeys["tls_cert_fp"] = fp
				ph.Attributes["tls_cert_fp"] = fp
			}
		}
	}

	// SMB GUID
	if strings.Contains(lower, "guid") || strings.Contains(lower, "smb") {
		if m := reSMBGUID.FindStringSubmatch(result); len(m) >= 2 {
			guid := strings.Trim(m[1], "{}")
			if guid != "" {
				ph.UniqueKeys["smb_guid"] = guid
				ph.Attributes["smb_guid"] = guid
			}
		}
	}

	// MAC address
	if strings.Contains(lower, "mac") {
		for _, line := range strings.Split(result, "\n") {
			line = strings.TrimSpace(line)
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "mac") && strings.Contains(lineLower, ":") {
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
}
