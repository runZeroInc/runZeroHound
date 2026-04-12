package input

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// Nmap XML document structure (covers the fields we care about).
// Reference: https://nmap.org/book/nmap-dtd.html

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
	OS        nmapOS        `xml:"os"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	OSType  string `xml:"ostype,attr"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapTable struct {
	Key   string     `xml:"key,attr"`
	Elems []nmapElem `xml:"elem"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// ParseNmapXML opens and parses an Nmap XML file (plain or gzip-compressed).
func ParseNmapXML(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("nmap: open %s: %w", path, err)
	}
	defer fd.Close()

	// Peek for gzip header
	var r io.Reader = fd
	peekBuf := make([]byte, 2)
	n, readErr := fd.Read(peekBuf)
	if readErr != nil && readErr != io.EOF {
		return nil, fmt.Errorf("nmap: read header %s: %w", path, readErr)
	}
	if _, err2 := fd.Seek(0, io.SeekStart); err2 != nil {
		return nil, err2
	}
	if n == 2 && peekBuf[0] == 0x1f && peekBuf[1] == 0x8b {
		gz, gerr := gzip.NewReader(fd)
		if gerr != nil {
			return nil, gerr
		}
		defer gz.Close()
		r = gz
	}

	var run nmapRun
	if err = xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("nmap: decode %s: %w", path, err)
	}

	result := &ParseResult{}
	for i := range run.Hosts {
		h := &run.Hosts[i]
		if h.Status.State != "up" {
			continue
		}
		ph := parseNmapHost(h)
		if len(ph.Addresses) > 0 {
			result.Hosts = append(result.Hosts, ph)
		}
	}
	return result, nil
}

func parseNmapHost(h *nmapHost) *ParsedHost {
	ph := &ParsedHost{
		Source:     FileTypeNmapXML,
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	for _, addr := range h.Addresses {
		switch addr.AddrType {
		case "ipv4", "ipv6":
			ph.Addresses = append(ph.Addresses, addr.Addr)
		case "mac":
			ph.Attributes["mac_address"] = addr.Addr
		}
	}

	for _, hn := range h.Hostnames.Hostnames {
		if hn.Name != "" {
			ph.Names = append(ph.Names, hn.Name)
		}
	}

	if len(h.OS.OSMatches) > 0 {
		ph.OS = h.OS.OSMatches[0].Name
	}

	primaryIP := ""
	if len(ph.Addresses) > 0 {
		primaryIP = ph.Addresses[0]
	}

	for _, port := range h.Ports.Ports {
		if port.State.State != "open" {
			continue
		}
		svc := ParsedService{
			Address:    primaryIP,
			Port:       port.PortID,
			Protocol:   port.Protocol,
			Product:    port.Service.Product,
			Version:    port.Service.Version,
			Attributes: make(map[string]string),
		}
		if port.Service.OSType != "" {
			svc.Attributes["ostype"] = port.Service.OSType
			if ph.OS == "" {
				ph.OS = port.Service.OSType
			}
		}
		if port.Service.Name != "" {
			svc.Attributes["service_name"] = port.Service.Name
		}

		// Extract script output for well-known scripts
		for _, script := range port.Scripts {
			extractNmapScript(ph, &svc, script)
		}

		ph.Services = append(ph.Services, svc)
	}

	return ph
}

// extractNmapScript pulls interesting fields out of nmap NSE script results.
func extractNmapScript(ph *ParsedHost, svc *ParsedService, script nmapScript) {
	id := strings.ToLower(script.ID)

	switch {
	case id == "ssh-hostkey" || strings.HasPrefix(id, "ssh-"):
		// Collect SSH host key fingerprints
		for _, elem := range script.Elems {
			k := strings.ToLower(elem.Key)
			if k == "fingerprint" || strings.Contains(k, "fp") {
				if v := strings.TrimSpace(elem.Value); v != "" {
					ph.UniqueKeys["ssh_hostkey_fp"] = v
					svc.Attributes["ssh_hostkey_fp"] = v
				}
			}
		}
		// Also check tables
		for _, tbl := range script.Tables {
			for _, elem := range tbl.Elems {
				k := strings.ToLower(elem.Key)
				if k == "fingerprint" || strings.Contains(k, "fp") {
					if v := strings.TrimSpace(elem.Value); v != "" {
						ph.UniqueKeys["ssh_hostkey_fp"] = v
						svc.Attributes["ssh_hostkey_fp"] = v
					}
				}
			}
		}

	case id == "ssl-cert" || id == "tls-cert":
		for _, elem := range script.Elems {
			k := strings.ToLower(elem.Key)
			if k == "sha1" || k == "sha-1" || k == "fingerprint" {
				if v := strings.TrimSpace(elem.Value); v != "" {
					ph.UniqueKeys["tls_cert_fp"] = v
					svc.Attributes["tls_cert_fp"] = v
				}
			}
		}
		for _, tbl := range script.Tables {
			for _, elem := range tbl.Elems {
				k := strings.ToLower(elem.Key)
				if k == "sha1" || k == "sha-1" || k == "fingerprint" {
					if v := strings.TrimSpace(elem.Value); v != "" {
						ph.UniqueKeys["tls_cert_fp"] = v
						svc.Attributes["tls_cert_fp"] = v
					}
				}
			}
		}

	case strings.Contains(id, "smb"):
		// SMB GUID from smb-security-mode or smb2-security-mode
		for _, elem := range script.Elems {
			k := strings.ToLower(elem.Key)
			if k == "guid" || k == "server_guid" {
				if v := strings.TrimSpace(elem.Value); v != "" {
					ph.UniqueKeys["smb_guid"] = v
					svc.Attributes["smb_guid"] = v
				}
			}
		}

	case strings.Contains(id, "snmp"):
		// SNMP engine ID
		for _, elem := range script.Elems {
			k := strings.ToLower(elem.Key)
			if strings.Contains(k, "engine") {
				if v := strings.TrimSpace(elem.Value); v != "" {
					ph.UniqueKeys["snmpv3_engine_id"] = v
					svc.Attributes["snmpv3_engine_id"] = v
				}
			}
		}
	}

	// Also store raw script output as a generic attribute
	if script.Output != "" {
		key := "nmap_script_" + strings.ReplaceAll(id, "-", "_")
		svc.Attributes[key] = script.Output
	}
}
