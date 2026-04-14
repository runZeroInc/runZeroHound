package input

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// NetBox JSON API export support.
//
// runZeroHound accepts exports from the following NetBox API endpoints:
//   - /api/dcim/devices/    (devices)
//   - /api/ipam/ip-addresses/ (IP address assignments)
//   - /api/ipam/prefixes/   (subnets / prefixes)
//   - /api/dcim/interfaces/ (device interfaces)
//
// The format is the standard NetBox paginated response:
//
//	{"count": N, "next": "...", "previous": "...", "results": [...]}
//
// Multiple endpoint exports can be passed to the convert command and will be
// merged by the node-deduplication logic in generateOpenGraph.

// netboxResponse is the outer envelope for any NetBox API list response.
type netboxResponse struct {
	Count   int               `json:"count"`
	Results []json.RawMessage `json:"results"`
}

// netboxDevice represents a /api/dcim/devices/ result.
type netboxDevice struct {
	ID         int              `json:"id"`
	Name       string           `json:"name"`
	DeviceType netboxNestedType `json:"device_type"`
	Role       netboxNestedType `json:"device_role"`
	Platform   netboxNestedType `json:"platform"`
	Site       netboxNestedType `json:"site"`
	Rack       netboxNestedType `json:"rack"`
	PrimaryIP4 *netboxIPBrief   `json:"primary_ip4"`
	PrimaryIP6 *netboxIPBrief   `json:"primary_ip6"`
	Status     netboxChoice     `json:"status"`
	Comments   string           `json:"comments"`
	CustomFields map[string]any `json:"custom_fields"`
}

// netboxIPAddress represents a /api/ipam/ip-addresses/ result.
type netboxIPAddress struct {
	ID            int              `json:"id"`
	Address       string           `json:"address"` // "192.168.1.1/24"
	Family        netboxChoice     `json:"family"`
	Status        netboxChoice     `json:"status"`
	DNSName       string           `json:"dns_name"`
	Description   string           `json:"description"`
	AssignedObject *netboxAssigned `json:"assigned_object"`
}

// netboxAssigned is the polymorphic assigned_object on an IP address.
type netboxAssigned struct {
	ID     int              `json:"id"`
	Name   string           `json:"name"`
	Device *netboxDeviceBrief `json:"device"`
	// Virtual machine
	VirtualMachine *netboxNestedType `json:"virtual_machine"`
}

// netboxDeviceBrief is the inline device reference inside an IP assignment.
type netboxDeviceBrief struct {
	ID          int            `json:"id"`
	Name        string         `json:"name"`
	PrimaryIP4  *netboxIPBrief `json:"primary_ip4"`
}

type netboxIPBrief struct {
	Address string `json:"address"` // "192.168.1.1/24"
	// Family value is an integer in the brief form (4 or 6) but an object
	// in the full IP address form. We use json.RawMessage to handle both.
	Family json.RawMessage `json:"family"`
}

type netboxNestedType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type netboxChoice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ParseNetBox parses a NetBox JSON API export file.
// It auto-detects whether the results are devices or IP-addresses based on
// the shape of the first result object.
func ParseNetBox(path string) (*ParseResult, error) {
	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("netbox: open %s: %w", path, err)
	}
	defer fd.Close()

	data, err := io.ReadAll(fd)
	if err != nil {
		return nil, fmt.Errorf("netbox: read %s: %w", path, err)
	}

	var envelope netboxResponse
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("netbox: parse %s: %w", path, err)
	}

	if len(envelope.Results) == 0 {
		return &ParseResult{}, nil
	}

	// Detect result type by inspecting the first object's keys.
	objType := detectNetBoxObjectType(envelope.Results[0])

	switch objType {
	case "device":
		return parseNetBoxDevices(envelope.Results)
	case "ipaddress":
		return parseNetBoxIPAddresses(envelope.Results)
	default:
		// Try devices as the most common export
		return parseNetBoxDevices(envelope.Results)
	}
}

// detectNetBoxObjectType sniffs the first result to determine the export type.
func detectNetBoxObjectType(raw json.RawMessage) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	// Devices have device_type; IP addresses have "address" with CIDR notation
	if _, ok := probe["device_type"]; ok {
		return "device"
	}
	if _, ok := probe["assigned_object"]; ok {
		return "ipaddress"
	}
	if _, ok := probe["address"]; ok {
		return "ipaddress"
	}
	return ""
}

// parseNetBoxDevices converts a slice of device JSON objects to ParsedHosts.
func parseNetBoxDevices(results []json.RawMessage) (*ParseResult, error) {
	out := &ParseResult{}
	for _, raw := range results {
		var dev netboxDevice
		if err := json.Unmarshal(raw, &dev); err != nil {
			continue
		}
		ph := netboxDeviceToHost(&dev)
		if ph != nil {
			out.Hosts = append(out.Hosts, ph)
		}
	}
	return out, nil
}

// netboxDeviceToHost maps a NetBox device to a ParsedHost.
func netboxDeviceToHost(dev *netboxDevice) *ParsedHost {
	ph := &ParsedHost{
		Source:     FileTypeNetBox,
		Sources:    []string{"netbox"},
		Attributes: make(map[string]string),
		UniqueKeys: make(map[string]string),
	}

	if dev.Name != "" {
		ph.Names = append(ph.Names, dev.Name)
	}

	// Primary IPs
	if dev.PrimaryIP4 != nil {
		ip := stripCIDRMask(dev.PrimaryIP4.Address)
		if ip != "" {
			ph.Addresses = append(ph.Addresses, ip)
		}
	}
	if dev.PrimaryIP6 != nil {
		ip := stripCIDRMask(dev.PrimaryIP6.Address)
		if ip != "" {
			ph.Addresses = appendUnique(ph.Addresses, ip)
		}
	}

	if len(ph.Addresses) == 0 {
		return nil
	}

	// Structured attributes
	if dev.DeviceType.Name != "" {
		ph.Attributes["device_type"] = dev.DeviceType.Name
	}
	if dev.Role.Name != "" {
		ph.Attributes["device_role"] = dev.Role.Name
	}
	if dev.Platform.Name != "" {
		ph.OS = dev.Platform.Name
		ph.Attributes["platform"] = dev.Platform.Name
	}
	if dev.Site.Name != "" {
		ph.Attributes["site"] = dev.Site.Name
	}
	if dev.Rack.Name != "" {
		ph.Attributes["rack"] = dev.Rack.Name
	}
	if dev.Status.Label != "" {
		ph.Attributes["status"] = dev.Status.Label
	}
	if dev.Comments != "" {
		ph.Attributes["comments"] = dev.Comments
	}
	ph.Attributes["netbox_id"] = fmt.Sprintf("%d", dev.ID)
	ph.Attributes["source"] = "netbox"

	// Flatten custom fields
	for k, v := range dev.CustomFields {
		if v == nil {
			continue
		}
		ph.Attributes["cf_"+k] = fmt.Sprintf("%v", v)
	}

	return ph
}

// parseNetBoxIPAddresses converts IP-address results to ParsedHosts.
// Each IP address with an assigned device becomes a host entry.
func parseNetBoxIPAddresses(results []json.RawMessage) (*ParseResult, error) {
	out := &ParseResult{}

	// Deduplicate by device ID — multiple IPs can be assigned to same device
	byDevice := make(map[int]*ParsedHost)

	for _, raw := range results {
		var ipAddr netboxIPAddress
		if err := json.Unmarshal(raw, &ipAddr); err != nil {
			continue
		}
		if ipAddr.Status.Value == "deprecated" || ipAddr.Status.Value == "reserved" {
			continue
		}

		ip := stripCIDRMask(ipAddr.Address)
		if ip == "" {
			continue
		}

		// If there's an assigned device, group IPs under that device
		if ipAddr.AssignedObject != nil && ipAddr.AssignedObject.Device != nil {
			dev := ipAddr.AssignedObject.Device
			ph, exists := byDevice[dev.ID]
			if !exists {
				ph = &ParsedHost{
					Source:     FileTypeNetBox,
					Sources:    []string{"netbox"},
					Attributes: make(map[string]string),
					UniqueKeys: make(map[string]string),
				}
				if dev.Name != "" {
					ph.Names = append(ph.Names, dev.Name)
				}
				ph.Attributes["netbox_device_id"] = fmt.Sprintf("%d", dev.ID)
				ph.Attributes["source"] = "netbox"
				byDevice[dev.ID] = ph
			}
			ph.Addresses = appendUnique(ph.Addresses, ip)
			if ipAddr.DNSName != "" {
				ph.Names = appendUnique(ph.Names, ipAddr.DNSName)
			}
		} else {
			// Unassigned IP — create a minimal host
			ph := &ParsedHost{
				Source:     FileTypeNetBox,
				Sources:    []string{"netbox"},
				Addresses:  []string{ip},
				Attributes: map[string]string{"source": "netbox"},
				UniqueKeys: make(map[string]string),
			}
			if ipAddr.DNSName != "" {
				ph.Names = append(ph.Names, ipAddr.DNSName)
			}
			out.Hosts = append(out.Hosts, ph)
		}
	}

	for _, ph := range byDevice {
		if len(ph.Addresses) > 0 {
			out.Hosts = append(out.Hosts, ph)
		}
	}

	return out, nil
}

// stripCIDRMask removes the "/prefix" part from "192.168.1.1/24" → "192.168.1.1".
func stripCIDRMask(cidr string) string {
	if idx := strings.Index(cidr, "/"); idx >= 0 {
		return cidr[:idx]
	}
	return cidr
}
