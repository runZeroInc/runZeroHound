package input

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// NextnetRecord matches the ScanResult struct written by the nextnet scanner.
type NextnetRecord struct {
	Host  string            `json:"host"`
	Port  string            `json:"port,omitempty"`
	Proto string            `json:"proto,omitempty"`
	Probe string            `json:"probe,omitempty"`
	Name  string            `json:"name,omitempty"`
	Nets  []string          `json:"nets,omitempty"`
	Info  map[string]string `json:"info,omitempty"`
}

// ParseNextnet reads a nextnet .nxt JSONL file and returns parsed hosts.
func ParseNextnet(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("nextnet: open %s: %w", path, err)
	}
	defer fd.Close()

	result := &ParseResult{}
	scanner := bufio.NewScanner(fd)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var rec NextnetRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Skip malformed lines
			continue
		}

		ph := nextnetRecordToHost(&rec)
		if ph != nil {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nextnet: scan %s: %w", path, err)
	}

	return result, nil
}

// nextnetRecordToHost converts a single nextnet ScanResult to a ParsedHost.
func nextnetRecordToHost(rec *NextnetRecord) *ParsedHost {
	if rec.Host == "" {
		return nil
	}

	ph := &ParsedHost{
		Source:     FileTypeNextnet,
		Sources:    []string{"nextnet"},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	ph.Addresses = []string{rec.Host}

	// Secondary IPs (e.g. NetBIOS name reply interfaces)
	for _, net := range rec.Nets {
		if net != "" && net != "0.0.0.0" {
			ph.Addresses = appendUnique(ph.Addresses, net)
		}
	}

	if rec.Name != "" {
		ph.Names = append(ph.Names, rec.Name)
	}

	if rec.Port != "" {
		svc := ParsedService{
			Address:    rec.Host,
			Port:       rec.Port,
			Protocol:   rec.Proto,
			Attributes: make(map[string]string),
		}
		if rec.Probe != "" {
			svc.Attributes["probe"] = rec.Probe
		}
		ph.Services = append(ph.Services, svc)
	}

	// Copy info fields to attributes and check for unique fingerprints
	for k, v := range rec.Info {
		ph.Attributes["nextnet."+k] = v
		extractNextnetFingerprint(ph, k, v)
	}

	if rec.Probe != "" {
		ph.Attributes["nextnet.probe"] = rec.Probe
	}

	return ph
}

// extractNextnetFingerprint recognises known fingerprint keys written by
// nextnet and promotes them to ph.UniqueKeys for correlation.
func extractNextnetFingerprint(ph *ParsedHost, key, value string) {
	if value == "" {
		return
	}
	k := strings.ToLower(key)
	switch {
	case k == "ssh_fp" || k == "ssh_hostkey_fp" || strings.Contains(k, "ssh") && strings.Contains(k, "fp"):
		ph.UniqueKeys["ssh_hostkey_fp"] = value
	case k == "tls_fp" || k == "tls_cert_fp" || strings.Contains(k, "tls") && strings.Contains(k, "fp"):
		ph.UniqueKeys["tls_cert_fp"] = value
	case k == "smb_guid" || k == "guid":
		ph.UniqueKeys["smb_guid"] = value
	case k == "snmpv3_engine_id" || k == "engine_id" || strings.Contains(k, "engineid"):
		ph.UniqueKeys["snmpv3_engine_id"] = value
	case k == "hwaddr" || k == "mac":
		mac := normalizeMACAddress(value)
		if mac != "" {
			ph.MACs = appendUnique(ph.MACs, mac)
			ph.Attributes["mac_address"] = mac
		}
	case k == "domain":
		ph.Attributes["netbios_domain"] = value
	case k == "username":
		ph.Attributes["netbios_user"] = value
	}
}
