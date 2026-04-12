package input

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/runZeroInc/runZeroHound/pkg/bloodhound"
	"github.com/runZeroInc/runZeroHound/pkg/runzero"
)

// BuildOpenGraph converts a slice of ParsedHosts (from any source) into
// BloodHound OpenGraph nodes and edges.
//
// Correlation: When a host carries UniqueKeys (ssh_hostkey_fp, tls_cert_fp,
// smb_guid, snmpv3_engine_id) those fingerprints become separate "fingerprint"
// nodes.  Edges from asset → fingerprint node allow BloodHound to link assets
// across different scanners that share the same cryptographic identity.
func BuildOpenGraph(hosts []*ParsedHost) ([]*bloodhound.Node, []*bloodhound.Edge) {
	nodes := []*bloodhound.Node{}
	edges := []*bloodhound.Edge{}

	subnets := make(map[string]uint64)

	// fingerprintNodes tracks already-created fingerprint nodes so we don't
	// duplicate them when multiple hosts carry the same fingerprint.
	fingerprintNodes := make(map[string]bool)

	for _, ph := range hosts {
		if len(ph.Addresses) == 0 {
			continue
		}

		nodeID := hostNodeID(ph)
		label := ph.Addresses[0]
		if len(ph.Names) > 0 {
			label = fmt.Sprintf("%s (%s)", ph.Addresses[0], ph.Names[0])
		}

		props := map[string]any{
			"displayname": label,
			"source":      ph.Source.String(),
			"ip_addresses": ph.Addresses,
		}
		if len(ph.Names) > 0 {
			props["names"] = ph.Names
			props["name"] = ph.Names[0]
		}
		if ph.OS != "" {
			props["os"] = ph.OS
		}
		if len(ph.Services) > 0 {
			props["service_count"] = len(ph.Services)
		}

		// Flatten attributes (sorted for determinism)
		attrKeys := make([]string, 0, len(ph.Attributes))
		for k := range ph.Attributes {
			attrKeys = append(attrKeys, k)
		}
		sort.Strings(attrKeys)
		for _, k := range attrKeys {
			props[k] = ph.Attributes[k]
		}

		// Kind depends on source
		kind := sourceKind(ph.Source)
		assetNode := &bloodhound.Node{
			ID:         nodeID,
			Kinds:      []string{kind},
			Properties: props,
		}
		nodes = append(nodes, assetNode)

		// Service nodes
		for i, svc := range ph.Services {
			svcID := fmt.Sprintf("%s-svc-%d", nodeID, i)
			svcLabel := fmt.Sprintf("%s/%s", svc.Port, svc.Protocol)
			svcProps := map[string]any{
				"displayname": svcLabel,
				"address":     svc.Address,
				"port":        svc.Port,
				"protocol":    svc.Protocol,
			}
			if svc.Product != "" {
				svcProps["product"] = svc.Product
			}
			if svc.Version != "" {
				svcProps["version"] = svc.Version
			}
			for k, v := range svc.Attributes {
				svcProps["attr_"+k] = v
			}
			svcNode := &bloodhound.Node{
				ID:         svcID,
				Kinds:      []string{"RZService"},
				Properties: svcProps,
			}
			nodes = append(nodes, svcNode)
			edges = append(edges,
				edgeBetween(nodeID, "RZHasService", svcID),
				edgeBetween(svcID, "RZRunsOnAsset", nodeID),
			)
		}

		// Subnet nodes and edges
		for _, addr := range ph.Addresses {
			mask := "24"
			if strings.Contains(addr, ":") {
				mask = "56"
			}
			_, ipNet, err := net.ParseCIDR(addr + "/" + mask)
			if err != nil {
				continue
			}
			network := ipNet.String()
			ip := net.ParseIP(addr)
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			subnets[network]++
			subnetID := "rz-network-" + network
			edges = append(edges,
				edgeBetween(nodeID, "RZInsideOfSubnet", subnetID),
				edgeBetween(subnetID, "RZSubnetContains", nodeID),
			)
		}

		// Fingerprint / correlation nodes
		fpKeyOrder := []string{"ssh_hostkey_fp", "tls_cert_fp", "smb_guid", "snmpv3_engine_id"}
		for _, fpKey := range fpKeyOrder {
			fpVal, ok := ph.UniqueKeys[fpKey]
			if !ok || fpVal == "" {
				continue
			}
			fpNodeID := "rz-fp-" + fpKey + "-" + sanitizeFP(fpVal)
			if !fingerprintNodes[fpNodeID] {
				fingerprintNodes[fpNodeID] = true
				fpNode := &bloodhound.Node{
					ID:    fpNodeID,
					Kinds: []string{fingerprintKind(fpKey)},
					Properties: map[string]any{
						"displayname":     fpVal,
						"fingerprint_key": fpKey,
						"fingerprint":     fpVal,
					},
				}
				nodes = append(nodes, fpNode)

				// Subnet link for public fingerprint nodes: link public FPs to internet
				if isPublicFingerprint(fpKey) {
					edges = append(edges,
						edgeBetween(fpNodeID, "RZInsideOfSubnet", "rz-network-public"),
						edgeBetween("rz-network-public", "RZSubnetContains", fpNodeID),
					)
				}
			}
			edgeKind := fingerprintEdgeKind(fpKey)
			edges = append(edges,
				edgeBetween(nodeID, edgeKind, fpNodeID),
				edgeBetween(fpNodeID, edgeKind+"By", nodeID),
			)
		}
	}

	// Build subnet nodes
	for network := range subnets {
		bip := strings.Split(network, "/")
		internal := runzero.IsPrivateIPAddress(bip[0])
		isv6 := strings.Contains(bip[0], ":")
		version := "4"
		if isv6 {
			version = "6"
		}
		if !internal {
			edges = append(edges,
				edgeBetween("rz-network-"+network, "RZInsideOfSubnet", "rz-network-public"),
				edgeBetween("rz-network-public", "RZSubnetContains", "rz-network-"+network),
			)
		}
		nodes = append(nodes, &bloodhound.Node{
			ID:    "rz-network-" + network,
			Kinds: []string{"RZNetwork"},
			Properties: map[string]any{
				"displayname":     network,
				"network_address": bip[0],
				"host_count":      subnets[network],
				"version":         version,
			},
		})
	}

	// Always include the internet node
	nodes = append(nodes, &bloodhound.Node{
		ID:    "rz-network-public",
		Kinds: []string{"RZNetwork"},
		Properties: map[string]any{
			"displayname":     "Global Internet",
			"network_address": "0.0.0.0",
		},
	})

	return nodes, edges
}

// hostNodeID derives a stable node ID from the host's primary address.
func hostNodeID(ph *ParsedHost) string {
	addr := "unknown"
	if len(ph.Addresses) > 0 {
		addr = ph.Addresses[0]
	}
	src := ph.Source.String()
	return fmt.Sprintf("rz-%s-%s", src, strings.ReplaceAll(addr, ":", "-"))
}

// sourceKind maps a FileType to the BloodHound node kind label.
func sourceKind(ft FileType) string {
	switch ft {
	case FileTypeNmapXML:
		return "RZNmapHost"
	case FileTypeSNMPWalk:
		return "RZSNMPHost"
	case FileTypeNextnet:
		return "RZNextnetHost"
	case FileTypeNessus:
		return "RZNessusHost"
	case FileTypeOpenVAS:
		return "RZOpenVASHost"
	case FileTypeNetBox:
		return "RZNetBoxDevice"
	default:
		return "RZAsset"
	}
}

// fingerprintKind returns the BloodHound node kind for a fingerprint type.
func fingerprintKind(fpKey string) string {
	switch fpKey {
	case "ssh_hostkey_fp":
		return "RZSSHHostKey"
	case "tls_cert_fp":
		return "RZTLSCert"
	case "smb_guid":
		return "RZSMBGUID"
	case "snmpv3_engine_id":
		return "RZSNMPv3EngineID"
	default:
		return "RZFingerprint"
	}
}

// fingerprintEdgeKind returns the edge kind for the asset→fingerprint direction.
func fingerprintEdgeKind(fpKey string) string {
	switch fpKey {
	case "ssh_hostkey_fp":
		return "RZHasSSHHostKey"
	case "tls_cert_fp":
		return "RZHasTLSCert"
	case "smb_guid":
		return "RZHasSMBGUID"
	case "snmpv3_engine_id":
		return "RZHasSNMPv3EngineID"
	default:
		return "RZHasFingerprint"
	}
}

// isPublicFingerprint returns true for fingerprint types that may appear on
// internet-facing services.
func isPublicFingerprint(fpKey string) bool {
	switch fpKey {
	case "tls_cert_fp", "ssh_hostkey_fp":
		return true
	}
	return false
}

// sanitizeFP makes a fingerprint value safe for use in a node ID.
func sanitizeFP(fp string) string {
	r := strings.NewReplacer(
		":", "",
		" ", "",
		"/", "_",
		"\\", "_",
	)
	return r.Replace(fp)
}

// edgeBetween creates a directed edge between two node IDs.
func edgeBetween(from, kind, to string) *bloodhound.Edge {
	return &bloodhound.Edge{
		Start: bloodhound.EdgeDesc{Value: from, MatchBy: "id"},
		Kind:  kind,
		End:   bloodhound.EdgeDesc{Value: to, MatchBy: "id"},
	}
}
