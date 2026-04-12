package input

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// ParseSNMPWalk parses the text output of the net-snmp "snmpwalk" tool.
//
// Expected line format:
//
//	OID = TYPE: VALUE
//
// e.g.:
//
//	SNMPv2-MIB::sysDescr.0 = STRING: Linux myrouter 5.15.0
//	SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
//	IF-MIB::ifPhysAddress.1 = Hex-STRING: AA BB CC DD EE FF
//
// The parser tries to extract the agent IP from the file name or falls back
// to "unknown".  Multiple targets can be concatenated by prefixing blocks
// with a comment "# Target: <ip>" (non-standard but convenient).
func ParseSNMPWalk(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("snmpwalk: open %s: %w", path, err)
	}
	defer fd.Close()

	return parseSNMPWalkReader(fd, path)
}

func parseSNMPWalkReader(r io.Reader, hint string) (*ParseResult, error) {
	result := &ParseResult{}

	// current host being populated
	current := &ParsedHost{
		Source:     FileTypeSNMPWalk,
		Sources:    []string{"snmpwalk"},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	// Try to extract an IP from the file-name hint (e.g. "192.168.1.1.txt")
	if ip := extractIPFromName(hint); ip != "" {
		current.Addresses = appendUnique(current.Addresses, ip)
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Support "# Target: <ip>" comments to separate per-host blocks
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "Target:") || strings.Contains(line, "target:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) >= 2 {
					ip := strings.TrimSpace(parts[1])
					if ip != "" {
						// Save current host if it has any data
						if len(current.Attributes) > 0 || len(current.Addresses) > 0 {
							result.Hosts = append(result.Hosts, current)
						}
						current = &ParsedHost{
							Source:     FileTypeSNMPWalk,
							Sources:    []string{"snmpwalk"},
							Attributes: make(map[string]string),
							UniqueKeys: make(map[string]string),
							Addresses:  []string{ip},
						}
					}
				}
			}
			continue
		}

		// Parse "OID = TYPE: VALUE"
		eqIdx := strings.Index(line, " = ")
		if eqIdx < 0 {
			continue
		}
		oid := strings.TrimSpace(line[:eqIdx])
		rest := strings.TrimSpace(line[eqIdx+3:])

		// Split type and value: "STRING: Linux..."
		var typeName, value string
		colonIdx := strings.Index(rest, ": ")
		if colonIdx >= 0 {
			typeName = strings.TrimSpace(rest[:colonIdx])
			value = strings.TrimSpace(rest[colonIdx+2:])
		} else {
			// No type prefix
			value = rest
		}

		// Store the raw attribute keyed by OID
		key := oidToKey(oid)
		current.Attributes[key] = value

		// Process well-known OIDs
		processSNMPOID(current, oid, typeName, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("snmpwalk: scan: %w", err)
	}

	// Add the last (or only) host
	if len(current.Attributes) > 0 || len(current.Addresses) > 0 {
		result.Hosts = append(result.Hosts, current)
	}

	return result, nil
}

// oidToKey converts an SNMP OID string like "SNMPv2-MIB::sysDescr.0" to a
// stable attribute key "snmp.sysDescr.0".
func oidToKey(oid string) string {
	// Remove MIB prefix (e.g. "SNMPv2-MIB::")
	if idx := strings.Index(oid, "::"); idx >= 0 {
		oid = oid[idx+2:]
	}
	// Lowercase and replace characters that aren't safe in property names
	oid = strings.ToLower(oid)
	oid = strings.ReplaceAll(oid, "-", "_")
	return "snmp." + oid
}

// processSNMPOID maps well-known OIDs to structured ParsedHost fields.
func processSNMPOID(ph *ParsedHost, oid, _ /*typeName*/, value string) {
	// Normalise OID: strip MIB prefix
	base := oid
	if idx := strings.Index(oid, "::"); idx >= 0 {
		base = oid[idx+2:]
	}
	base = strings.ToLower(base)

	switch {
	case strings.HasPrefix(base, "sysdescr"):
		if ph.OS == "" {
			ph.OS = value
		}
	case strings.HasPrefix(base, "sysname"):
		if value != "" {
			ph.Names = append(ph.Names, value)
		}
	// Interface physical address → MAC
	case strings.HasPrefix(base, "ifphysaddress"):
		// Hex-STRING: AA BB CC DD EE FF → aa:bb:cc:dd:ee:ff
		mac := normalizeMACFromHexString(value)
		if mac != "" {
			ph.MACs = appendUnique(ph.MACs, mac)
			ph.Attributes["mac_address"] = mac
		}
	// SNMPv3 Engine ID
	case strings.Contains(base, "snmpengineid") || strings.Contains(base, "engineid"):
		if value != "" {
			cleaned := strings.ReplaceAll(value, " ", "")
			ph.UniqueKeys["snmpv3_engine_id"] = cleaned
			ph.Attributes["snmpv3_engine_id"] = cleaned
		}
	// IP address from ipAdEntAddr table
	case strings.HasPrefix(base, "ipadentaddr"):
		// base looks like "ipadentaddr.192.168.1.1" - extract the IP suffix
		parts := strings.SplitN(base, ".", 2)
		if len(parts) == 2 && parts[1] != "" {
			ip := parts[1]
			// Validate using net.ParseIP to ensure correctness
			if net.ParseIP(ip) != nil {
				ph.Addresses = appendUnique(ph.Addresses, ip)
			}
		}

	// ARP cache entries: ipNetToMedia table
	// OID: ipNetToMediaPhysAddress.<ifIndex>.<ip> = MAC
	case strings.HasPrefix(base, "ipnettomediaphysaddress"):
		mac := normalizeMACFromHexString(value)
		if mac != "" && mac != "00:00:00:00:00:00" {
			// Extract IP from OID suffix: ipnettomediaphysaddress.<ifIndex>.<ip>
			parts := strings.SplitN(base, ".", 3)
			if len(parts) >= 3 {
				ip := parts[2]
				if net.ParseIP(ip) != nil {
					ph.SubAssets = append(ph.SubAssets, SubAsset{
						Type:      "arp",
						Addresses: []string{ip},
						MACs:      []string{mac},
						Attributes: map[string]string{
							"interface_index": parts[1],
						},
					})
				}
			}
		}

	// MAC address table: dot1dTpFdbAddress
	case strings.HasPrefix(base, "dot1dtpfdbaddress"):
		mac := normalizeMACFromHexString(value)
		if mac != "" && mac != "00:00:00:00:00:00" {
			ph.SubAssets = append(ph.SubAssets, SubAsset{
				Type: "mac_table",
				MACs: []string{mac},
				Attributes: map[string]string{
					"source_oid": oid,
				},
			})
		}
	}
}

// normalizeMACFromHexString converts "AA BB CC DD EE FF" to "aa:bb:cc:dd:ee:ff".
func normalizeMACFromHexString(s string) string {
	parts := strings.Fields(s)
	if len(parts) != 6 {
		return ""
	}
	return strings.ToLower(strings.Join(parts, ":"))
}

// extractIPFromName tries to find a valid IPv4 address in a file name.
// For example "192.168.1.1.txt" → "192.168.1.1".
func extractIPFromName(name string) string {
	// Strip directory
	base := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		base = name[idx+1:]
	}
	// Try stripping the last extension first ("192.168.1.1.txt" → "192.168.1.1")
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		candidate := base[:idx]
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	// Try the whole base name without extension
	if net.ParseIP(base) != nil {
		return base
	}
	return ""
}

// appendUnique adds s to slice only when not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
