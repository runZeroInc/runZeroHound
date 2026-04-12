package input

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/runZeroInc/runZeroHound/pkg/bloodhound"
	"github.com/runZeroInc/runZeroHound/pkg/runzero"
	"github.com/runZeroInc/runZeroHound/pkg/runzero/sanitize"
)

// BuildOpenGraph converts a slice of ParsedHosts (from any source) into
// BloodHound OpenGraph nodes and edges.
//
// Correlation: When a host carries UniqueKeys (ssh_hostkey_fp, tls_cert_fp,
// smb_guid, snmpv3_engine_id) those fingerprints become separate "fingerprint"
// nodes.  Edges from asset → fingerprint node allow BloodHound to link assets
// across different scanners that share the same cryptographic identity.
//
// Traceroute hops are emitted as RZRouter nodes with edges to both the asset
// and the subnet they belong to.
//
// SubAssets (ARP cache, MAC table entries) are emitted as RZSubAsset nodes
// linked to the parent host.
func BuildOpenGraph(hosts []*ParsedHost) ([]*bloodhound.Node, []*bloodhound.Edge) {
	nodes := []*bloodhound.Node{}
	edges := []*bloodhound.Edge{}

	subnets := make(map[string]uint64)

	// fingerprintNodes tracks already-created fingerprint nodes so we don't
	// duplicate them when multiple hosts carry the same fingerprint.
	fingerprintNodes := make(map[string]bool)

	// routerNodes tracks already-created traceroute router nodes.
	routerNodes := make(map[string]bool)

	// communityNodes tracks already-created SNMP community string nodes.
	communityNodes := make(map[string]bool)

	// vulnNodes tracks already-created vulnerability nodes.
	vulnNodes := make(map[string]bool)

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
			"displayname":  label,
			"source":       ph.Source.String(),
			"ip_addresses": strings.Join(ph.Addresses, ","),
		}
		if len(ph.Sources) > 0 {
			props["sources"] = strings.Join(ph.Sources, ",")
		}
		if len(ph.Names) > 0 {
			props["names"] = strings.Join(ph.Names, ",")
			props["name"] = ph.Names[0]
		}
		if ph.OS != "" {
			props["os"] = ph.OS
		}
		if len(ph.Services) > 0 {
			props["service_count"] = len(ph.Services)
		}
		if len(ph.MACs) > 0 {
			props["mac_addresses"] = strings.Join(ph.MACs, ",")
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
				svcProps[strings.ToLower("attr_"+k)] = v
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

		// Subnet nodes and edges.
		// We use /24 for IPv4 and /56 for IPv6 as aggregation boundaries —
		// /24 is the common "class C" that ops teams think in, and /56 is
		// the typical ISP delegation for IPv6. These boundaries are chosen
		// for graph readability; they do not represent actual routing topology.
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
			if shouldSkipIP(ip) {
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

		// Traceroute hop → RZRouter nodes
		for _, hop := range ph.TracerouteHops {
			if len(hop.Addresses) == 0 {
				continue
			}
			routerID := "rz-router-" + strings.ReplaceAll(hop.Addresses[0], ":", "-")
			if !routerNodes[routerID] {
				routerNodes[routerID] = true
				routerProps := map[string]any{
					"displayname":  hop.Addresses[0],
					"ip_addresses": strings.Join(hop.Addresses, ","),
					"ttl":          hop.TTL,
				}
				if hop.RTT > 0 {
					routerProps["rtt_ms"] = hop.RTT
				}
				if hop.Hostname != "" {
					routerProps["hostname"] = hop.Hostname
				}
				routerNode := &bloodhound.Node{
					ID:         routerID,
					Kinds:      []string{"RZRouter"},
					Properties: routerProps,
				}
				nodes = append(nodes, routerNode)

				// Link router to its subnet
				for _, rAddr := range hop.Addresses {
					rMask := "24"
					if strings.Contains(rAddr, ":") {
						rMask = "56"
					}
					_, ipNet, err := net.ParseCIDR(rAddr + "/" + rMask)
					if err != nil {
						continue
					}
					rIP := net.ParseIP(rAddr)
					if shouldSkipIP(rIP) {
						continue
					}
					network := ipNet.String()
					subnets[network]++
					subnetID := "rz-network-" + network
					edges = append(edges,
						edgeBetween(routerID, "RZInsideOfSubnet", subnetID),
						edgeBetween(subnetID, "RZSubnetContains", routerID),
					)
				}
			}
			edges = append(edges,
				edgeBetween(nodeID, "RZTracerouteHop", routerID),
				edgeBetween(routerID, "RZRoutesTo", nodeID),
			)
		}

		// SubAsset nodes (ARP cache, MAC table entries)
		for i, sa := range ph.SubAssets {
			saID := fmt.Sprintf("%s-sub-%d", nodeID, i)
			saLabel := sa.Type
			if len(sa.Addresses) > 0 {
				saLabel = fmt.Sprintf("%s/%s", sa.Type, sa.Addresses[0])
			} else if len(sa.MACs) > 0 {
				saLabel = fmt.Sprintf("%s/%s", sa.Type, sa.MACs[0])
			}
			saProps := map[string]any{
				"displayname": saLabel,
				"type":        sa.Type,
			}
			if len(sa.Addresses) > 0 {
				saProps["ip_addresses"] = strings.Join(sa.Addresses, ",")
			}
			if len(sa.MACs) > 0 {
				saProps["mac_addresses"] = strings.Join(sa.MACs, ",")
			}
			if sa.Interface != "" {
				saProps["interface"] = sa.Interface
			}
			if sa.VLAN != "" {
				saProps["vlan"] = sa.VLAN
			}
			for k, v := range sa.Attributes {
				saProps[strings.ToLower("attr_"+k)] = v
			}
			saNode := &bloodhound.Node{
				ID:         saID,
				Kinds:      []string{"RZSubAsset"},
				Properties: saProps,
			}
			nodes = append(nodes, saNode)
			edges = append(edges,
				edgeBetween(nodeID, "RZHasSubAsset", saID),
				edgeBetween(saID, "RZSubAssetOf", nodeID),
			)
		}

		// SNMP community string nodes
		if commStr, ok := ph.Attributes["snmp_communities"]; ok && commStr != "" {
			for _, community := range strings.Split(commStr, ",") {
				community = strings.TrimSpace(community)
				if community == "" {
					continue
				}
				commID := "rz-snmp-community-" + sanitizeFP(community)
				if !communityNodes[commID] {
					communityNodes[commID] = true
					nodes = append(nodes, &bloodhound.Node{
						ID:    commID,
						Kinds: []string{"RZSNMPCommunity"},
						Properties: map[string]any{
							"displayname": community,
							"community":   community,
						},
					})
				}
				edges = append(edges,
					edgeBetween(nodeID, "RZHasSNMPCommunity", commID),
					edgeBetween(commID, "RZSNMPCommunityUsedBy", nodeID),
				)
			}
		}

		// Vulnerability nodes
		for _, v := range ph.Vulns {
			vulnID := "rz-vuln-" + v.Source + "-" + sanitizeFP(v.ID)
			if !vulnNodes[vulnID] {
				vulnNodes[vulnID] = true
				vulnProps := map[string]any{
					"displayname": vulnDisplayName(v),
					"vuln_id":     v.ID,
					"source":      v.Source,
				}
				if v.Severity != "" {
					vulnProps["severity"] = v.Severity
				}
				if len(v.CVEs) > 0 {
					vulnProps["cve"] = strings.Join(v.CVEs, ",")
				}
				if v.CVSSScore != "" {
					vulnProps["cvss_score"] = v.CVSSScore
				}
				if v.RiskFactor != "" {
					vulnProps["risk_factor"] = v.RiskFactor
				}
				if v.Description != "" {
					vulnProps["description"] = v.Description
				}
				nodes = append(nodes, &bloodhound.Node{
					ID:         vulnID,
					Kinds:      []string{"RZVuln"},
					Properties: vulnProps,
				})
			}
			edges = append(edges,
				edgeBetween(nodeID, "RZHasVuln", vulnID),
				edgeBetween(vulnID, "RZVulnAsset", nodeID),
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
			"displayname":     "Public Internet",
			"network_address": "0.0.0.0",
		},
	})

	// Sanitize all node properties to remove null bytes and invalid UTF-8
	// that would cause PostgreSQL JSONB errors during BHCE ingestion.
	for _, n := range nodes {
		sanitizeProperties(n.Properties)
	}

	return nodes, edges
}

// sanitizeProperties scrubs null bytes and invalid UTF-8 from all string
// values in a property map. This prevents PostgreSQL "unsupported Unicode
// escape sequence" errors when BHCE ingests the data.
func sanitizeProperties(props map[string]any) {
	for k, v := range props {
		if s, ok := v.(string); ok {
			props[k] = sanitize.String(s)
		}
	}
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
	case FileTypeNessus:
		return "RZNessusHost"
	case FileTypeOpenVAS:
		return "RZOpenVASHost"
	case FileTypeNetBox:
		return "RZNetBoxDevice"
	case FileTypeQualys:
		return "RZQualysHost"
	case FileTypeQualysCSV:
		return "RZQualysHost"
	case FileTypeMasscan:
		return "RZMasscanHost"
	case FileTypeShodan:
		return "RZShodanHost"
	case FileTypeOneSixtyOne:
		return "RZOneSixtyOneHost"
	case FileTypeNexpose:
		return "RZNexposeHost"
	case FileTypeNextnet:
		return "RZNextnetHost"
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

// shouldSkipIP returns true if the IP address should be excluded from graph topology
// (link-local, loopback, multicast, or unspecified addresses).
func shouldSkipIP(ip net.IP) bool {
	return ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified()
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

// vulnDisplayName builds a display name for a vulnerability.
// If the vuln has CVEs, the first CVE is used as a prefix: "CVE-2022-3244: Title".
// Duplicate CVE references in the title are stripped (bare or parenthesised).
func vulnDisplayName(v ParsedVuln) string {
	title := v.Title
	if title == "" {
		title = v.ID
	}
	if len(v.CVEs) > 0 {
		cve := v.CVEs[0]
		// Remove the CVE from the title: both "(CVE-XXXX-YYYY)" and bare "CVE-XXXX-YYYY".
		cleaned := strings.ReplaceAll(title, "("+cve+")", "")
		cleaned = strings.ReplaceAll(cleaned, cve, "")
		// Collapse multiple spaces and trim.
		for strings.Contains(cleaned, "  ") {
			cleaned = strings.ReplaceAll(cleaned, "  ", " ")
		}
		cleaned = strings.TrimSpace(cleaned)
		if cleaned == "" {
			cleaned = cve
		}
		return cve + ": " + cleaned
	}
	return title
}
