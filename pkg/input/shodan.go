package input

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Shodan JSONL record structure.
// Reference: https://developer.shodan.io/api/banner-specification

type shodanRecord struct {
	IPStr     string          `json:"ip_str"`
	Port      int             `json:"port"`
	Transport string          `json:"transport"`
	Data      string          `json:"data"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	OS        string          `json:"os"`
	Hostnames []string        `json:"hostnames"`
	Domains   []string        `json:"domains"`
	Vulns     map[string]json.RawMessage `json:"vulns"`
	SSL       *shodanSSL      `json:"ssl"`
}

type shodanSSL struct {
	Cert *shodanCert `json:"cert"`
}

type shodanCert struct {
	Fingerprint shodanFingerprint `json:"fingerprint"`
}

type shodanFingerprint struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// ParseShodan parses a Shodan JSONL export file into ParsedHosts.
func ParseShodan(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("shodan: open %s: %w", path, err)
	}
	defer fd.Close()

	// Group records by IP to produce one ParsedHost per IP.
	type hostData struct {
		ph *ParsedHost
	}
	byIP := make(map[string]*hostData)

	scanner := bufio.NewScanner(fd)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var rec shodanRecord
		if jerr := json.Unmarshal([]byte(line), &rec); jerr != nil {
			continue
		}
		if rec.IPStr == "" {
			continue
		}

		hd, ok := byIP[rec.IPStr]
		if !ok {
			hd = &hostData{
				ph: &ParsedHost{
					Source:     FileTypeShodan,
					Sources:    []string{"shodan"},
					Addresses:  []string{rec.IPStr},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				},
			}
			byIP[rec.IPStr] = hd
		}
		ph := hd.ph

		// Hostnames
		for _, hn := range rec.Hostnames {
			if hn != "" {
				ph.Names = appendUnique(ph.Names, hn)
			}
		}

		// OS (use first non-empty)
		if ph.OS == "" && rec.OS != "" {
			ph.OS = rec.OS
		}

		// Domains as attributes
		for _, d := range rec.Domains {
			if d != "" {
				ph.Attributes["domain"] = d
			}
		}

		// Service
		proto := rec.Transport
		if proto == "" {
			proto = "tcp"
		}
		svc := ParsedService{
			Address:    rec.IPStr,
			Port:       strconv.Itoa(rec.Port),
			Protocol:   proto,
			Product:    rec.Product,
			Version:    rec.Version,
			Attributes: make(map[string]string),
		}
		if rec.Data != "" {
			// Store a truncated banner to avoid huge attributes
			banner := rec.Data
			if len(banner) > 512 {
				banner = banner[:512]
			}
			svc.Attributes["banner"] = banner
		}
		ph.Services = append(ph.Services, svc)

		// Vulnerabilities as comma-separated attribute
		if len(rec.Vulns) > 0 {
			vulnIDs := make([]string, 0, len(rec.Vulns))
			for vid := range rec.Vulns {
				vulnIDs = append(vulnIDs, vid)
			}
			if existing := ph.Attributes["vulns"]; existing != "" {
				ph.Attributes["vulns"] = existing + "," + strings.Join(vulnIDs, ",")
			} else {
				ph.Attributes["vulns"] = strings.Join(vulnIDs, ",")
			}
		}

		// TLS certificate fingerprint
		if rec.SSL != nil && rec.SSL.Cert != nil {
			fp := rec.SSL.Cert.Fingerprint
			if fp.SHA1 != "" {
				normalized := normalizeHexFingerprint(fp.SHA1)
				if normalized != "" {
					ph.UniqueKeys["tls_cert_fp"] = normalized
					ph.Attributes["tls_cert_fp"] = normalized
				}
			}
		}

		// SSH fingerprint extraction from banner data
		dataLower := strings.ToLower(rec.Data)
		productLower := strings.ToLower(rec.Product)
		if strings.Contains(dataLower, "ssh") ||
			strings.Contains(productLower, "ssh") {
			fp := extractSSHFP(rec.Data)
			if fp != "" {
				ph.UniqueKeys["ssh_hostkey_fp"] = fp
				ph.Attributes["ssh_hostkey_fp"] = fp
			}
		}
	}

	if serr := scanner.Err(); serr != nil {
		return nil, fmt.Errorf("shodan: scan %s: %w", path, serr)
	}

	result := &ParseResult{}
	for _, hd := range byIP {
		result.Hosts = append(result.Hosts, hd.ph)
	}
	return result, nil
}
