package input

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Masscan XML document structure (subset of Nmap XML format).
// Reference: https://github.com/robertdavidgraham/masscan

type masscanRun struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Scanner string        `xml:"scanner,attr"`
	Hosts   []masscanHost `xml:"host"`
}

type masscanHost struct {
	Address masscanAddress `xml:"address"`
	Ports   masscanPorts   `xml:"ports"`
}

type masscanAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type masscanPorts struct {
	Ports []masscanPort `xml:"port"`
}

type masscanPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   string         `xml:"portid,attr"`
	State    masscanState   `xml:"state"`
	Service  masscanService `xml:"service"`
}

type masscanState struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type masscanService struct {
	Name   string `xml:"name,attr"`
	Banner string `xml:"banner,attr"`
}

// Masscan JSON record structure.
type masscanJSONRecord struct {
	IP        string            `json:"ip"`
	Timestamp string            `json:"timestamp"`
	Ports     []masscanJSONPort `json:"ports"`
}

type masscanJSONPort struct {
	Port    int                `json:"port"`
	Proto   string             `json:"proto"`
	Status  string             `json:"status"`
	Reason  string             `json:"reason"`
	Service masscanJSONService `json:"service"`
	TTL     int                `json:"ttl"`
}

type masscanJSONService struct {
	Name   string `json:"name"`
	Banner string `json:"banner"`
}

// ParseMasscan parses a Masscan output file (XML or JSON) into ParsedHosts.
func ParseMasscan(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("masscan: open %s: %w", path, err)
	}
	defer fd.Close()

	// Peek at the first non-whitespace bytes to determine format.
	peekBuf := make([]byte, 512)
	n, readErr := fd.Read(peekBuf)
	if readErr != nil && readErr != io.EOF {
		return nil, fmt.Errorf("masscan: read header %s: %w", path, readErr)
	}
	if _, err2 := fd.Seek(0, io.SeekStart); err2 != nil {
		return nil, err2
	}

	trimmed := strings.TrimSpace(string(peekBuf[:n]))
	if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "<?xml") {
		return parseMasscanXML(fd, path)
	}
	return parseMasscanJSON(fd, path)
}

func parseMasscanXML(fd *os.File, path string) (*ParseResult, error) {
	var run masscanRun
	if err := xml.NewDecoder(fd).Decode(&run); err != nil {
		return nil, fmt.Errorf("masscan: decode xml %s: %w", path, err)
	}

	// Group ports by IP address.
	type hostData struct {
		ph *ParsedHost
	}
	byIP := make(map[string]*hostData)

	for i := range run.Hosts {
		h := &run.Hosts[i]
		addr := h.Address.Addr
		if addr == "" {
			continue
		}

		hd, ok := byIP[addr]
		if !ok {
			hd = &hostData{
				ph: &ParsedHost{
					Source:     FileTypeMasscan,
					Sources:    []string{"masscan"},
					Addresses:  []string{addr},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				},
			}
			byIP[addr] = hd
		}

		for _, port := range h.Ports.Ports {
			if port.State.State != "" && port.State.State != "open" {
				continue
			}
			svc := ParsedService{
				Address:    addr,
				Port:       port.PortID,
				Protocol:   port.Protocol,
				Attributes: make(map[string]string),
			}
			if port.Service.Name != "" {
				svc.Product = port.Service.Name
				svc.Attributes["service_name"] = port.Service.Name
			}
			if port.Service.Banner != "" {
				svc.Attributes["banner"] = port.Service.Banner
			}
			if port.State.Reason != "" {
				svc.Attributes["reason"] = port.State.Reason
			}
			if port.State.ReasonTTL != "" {
				svc.Attributes["ttl"] = port.State.ReasonTTL
			}
			enrichMasscanService(hd.ph, &svc)
			hd.ph.Services = append(hd.ph.Services, svc)
		}
	}

	result := &ParseResult{}
	for _, hd := range byIP {
		result.Hosts = append(result.Hosts, hd.ph)
	}
	return result, nil
}

func parseMasscanJSON(fd *os.File, path string) (*ParseResult, error) {
	// Masscan JSON can be:
	// 1. A JSON array: [{...}, {...}]
	// 2. JSONL: one record per line (with possible trailing commas from masscan)
	// We handle both by trying array decode first, then falling back to line-by-line.

	var records []masscanJSONRecord
	if err := json.NewDecoder(fd).Decode(&records); err != nil {
		// Fallback to line-by-line parsing for JSONL or malformed array output.
		if _, err2 := fd.Seek(0, io.SeekStart); err2 != nil {
			return nil, err2
		}
		records = nil
		scanner := bufio.NewScanner(fd)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Skip empty lines, array brackets, and trailing commas
			line = strings.TrimRight(line, ",")
			line = strings.TrimSpace(line)
			if line == "" || line == "[" || line == "]" {
				continue
			}
			var rec masscanJSONRecord
			if jerr := json.Unmarshal([]byte(line), &rec); jerr != nil {
				continue
			}
			if rec.IP != "" {
				records = append(records, rec)
			}
		}
		if serr := scanner.Err(); serr != nil {
			return nil, fmt.Errorf("masscan: scan json %s: %w", path, serr)
		}
	}

	// Group by IP.
	type hostData struct {
		ph *ParsedHost
	}
	byIP := make(map[string]*hostData)

	for _, rec := range records {
		if rec.IP == "" {
			continue
		}
		hd, ok := byIP[rec.IP]
		if !ok {
			hd = &hostData{
				ph: &ParsedHost{
					Source:     FileTypeMasscan,
					Sources:    []string{"masscan"},
					Addresses:  []string{rec.IP},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				},
			}
			byIP[rec.IP] = hd
		}

		if rec.Timestamp != "" {
			hd.ph.Attributes["timestamp"] = rec.Timestamp
		}

		for _, port := range rec.Ports {
			if port.Status != "" && port.Status != "open" {
				continue
			}
			proto := port.Proto
			if proto == "" {
				proto = "tcp"
			}
			svc := ParsedService{
				Address:    rec.IP,
				Port:       strconv.Itoa(port.Port),
				Protocol:   proto,
				Attributes: make(map[string]string),
			}
			if port.Service.Name != "" {
				svc.Product = port.Service.Name
				svc.Attributes["service_name"] = port.Service.Name
			}
			if port.Service.Banner != "" {
				svc.Attributes["banner"] = port.Service.Banner
			}
			if port.Reason != "" {
				svc.Attributes["reason"] = port.Reason
			}
			if port.TTL > 0 {
				svc.Attributes["ttl"] = strconv.Itoa(port.TTL)
			}
			enrichMasscanService(hd.ph, &svc)
			hd.ph.Services = append(hd.ph.Services, svc)
		}
	}

	result := &ParseResult{}
	for _, hd := range byIP {
		result.Hosts = append(result.Hosts, hd.ph)
	}
	return result, nil
}

// Regexes for extracting structured data from masscan banners.
var (
	sshVersionRe = regexp.MustCompile(`^SSH-[\d.]+-(\S+)`)
	smbGUIDRe    = regexp.MustCompile(`guid=([0-9a-fA-F-]{36})`)
	smbDomainRe  = regexp.MustCompile(`domain=(\S+)`)
	smbVersionRe = regexp.MustCompile(`version=(\S+)`)
	httpServerRe = regexp.MustCompile(`(?i)Server:\s*(.+)`)
)

// enrichMasscanService extracts structured data from masscan banners and
// populates host/service fields accordingly.
func enrichMasscanService(ph *ParsedHost, svc *ParsedService) {
	banner := svc.Attributes["banner"]
	if banner == "" {
		return
	}

	switch {
	case strings.HasPrefix(banner, "SSH-"):
		if m := sshVersionRe.FindStringSubmatch(banner); m != nil {
			svc.Product = "ssh"
			svc.Version = m[1]
		}

	case strings.HasPrefix(banner, "SMBv"):
		if m := smbGUIDRe.FindStringSubmatch(banner); m != nil {
			svc.Attributes["smb_guid"] = m[1]
			ph.UniqueKeys["smb_guid"] = strings.ToLower(m[1])
		}
		if m := smbDomainRe.FindStringSubmatch(banner); m != nil {
			svc.Attributes["smb_domain"] = m[1]
			if ph.Attributes["smb_domain"] == "" {
				ph.Attributes["smb_domain"] = m[1]
			}
		}
		if m := smbVersionRe.FindStringSubmatch(banner); m != nil {
			svc.Version = m[1]
		}
		svc.Product = "smb"

	case strings.HasPrefix(banner, "HTTP/"):
		if m := httpServerRe.FindStringSubmatch(banner); m != nil {
			svc.Product = strings.TrimSpace(m[1])
		}
	}

	// Masscan uses "http.server" service name to report the Server header value
	// and "title" to report the HTML title; store these as attributes.
	svcName := svc.Attributes["service_name"]
	switch svcName {
	case "http.server":
		svc.Attributes["http_server"] = strings.TrimSpace(banner)
		if svc.Product == "" || svc.Product == "http.server" {
			svc.Product = strings.TrimSpace(banner)
		}
	case "title":
		svc.Attributes["http_title"] = strings.TrimSpace(banner)
	}
}
