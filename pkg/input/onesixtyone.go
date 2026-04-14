package input

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// ParseOneSixtyOne parses the text output of the "onesixtyone" SNMP scanner.
//
// Expected line format:
//
//	IP [community] sysDescr text
//
// e.g.:
//
//	192.168.0.19 [public] APC Web/SNMP Management Card ...
//	192.168.0.81 [public] Cisco NX-OS(tm) nxos.9.3.7.bin ...
//
// Lines that don't match (status messages like "Scanning N hosts" or
// "Error in sendto") are silently skipped.
//
// Each unique IP becomes a ParsedHost with a UDP/161 service. Each unique
// community string is recorded in the host's Attributes as "snmp_community".
// When the same IP appears with multiple communities, additional community
// values are appended comma-separated.
func ParseOneSixtyOne(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("onesixtyone: open %s: %w", path, err)
	}
	defer fd.Close()

	return parseOneSixtyOneReader(fd)
}

func parseOneSixtyOneReader(r io.Reader) (*ParseResult, error) {
	// hostMap groups entries by IP so multiple community hits merge into one host.
	type hostEntry struct {
		host        *ParsedHost
		communities []string
	}
	hostMap := make(map[string]*hostEntry)
	hostOrder := []string{} // preserve order

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		ip, community, desc := parseOneSixtyOneLine(line)
		if ip == "" {
			continue
		}

		entry, exists := hostMap[ip]
		if !exists {
			entry = &hostEntry{
				host: &ParsedHost{
					Source:     FileTypeOneSixtyOne,
					Sources:    []string{"onesixtyone"},
					Addresses:  []string{ip},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				},
			}
			hostMap[ip] = entry
			hostOrder = append(hostOrder, ip)
		}

		// Record the sysDescr (first one wins if different per community)
		if desc != "" && entry.host.OS == "" {
			entry.host.OS = desc
			entry.host.Attributes["snmp.sysDescr"] = desc
		}

		// Track community strings
		if community != "" && !containsStr(entry.communities, community) {
			entry.communities = append(entry.communities, community)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("onesixtyone: scan: %w", err)
	}

	result := &ParseResult{}
	for _, ip := range hostOrder {
		entry := hostMap[ip]
		h := entry.host

		// Store community strings as comma-separated attribute
		if len(entry.communities) > 0 {
			h.Attributes["snmp_communities"] = strings.Join(entry.communities, ",")
		}

		// Add SNMP service (UDP/161)
		h.Services = append(h.Services, ParsedService{
			Address:  ip,
			Port:     "161",
			Protocol: "udp",
			Product:  "snmp",
			Attributes: map[string]string{
				"snmp.sysDescr": h.Attributes["snmp.sysDescr"],
			},
		})

		result.Hosts = append(result.Hosts, h)
	}

	return result, nil
}

// parseOneSixtyOneLine extracts IP, community and description from a single
// onesixtyone output line. Returns empty strings if the line doesn't match.
//
// Format: "IP [community] description..."
func parseOneSixtyOneLine(line string) (ip, community, desc string) {
	bracketOpen := strings.Index(line, " [")
	if bracketOpen < 0 {
		return "", "", ""
	}
	rest := line[bracketOpen+2:]
	bracketClose := strings.Index(rest, "] ")
	if bracketClose < 0 {
		return "", "", ""
	}

	candidate := strings.TrimSpace(line[:bracketOpen])
	if net.ParseIP(candidate) == nil {
		return "", "", ""
	}

	community = rest[:bracketClose]
	desc = strings.TrimSpace(rest[bracketClose+2:])
	return candidate, community, desc
}

// containsStr checks if a string slice contains a value.
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
