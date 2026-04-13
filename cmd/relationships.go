package cmd

import (
	"fmt"
	"sort"
	"strings"

	mactracker "github.com/runZeroInc/mac-tracker"
	"github.com/runZeroInc/runZeroHound/pkg/bloodhound"
	"github.com/runZeroInc/runZeroHound/pkg/runzero/models"
)

// relationshipContext collects deduplication state shared across extractors.
type relationshipContext struct {
	nodes []*bloodhound.Node
	edges []*bloodhound.Edge

	// Track created nodes by ID to avoid duplicates.
	created map[string]bool
}

func newRelCtx() *relationshipContext {
	return &relationshipContext{created: make(map[string]bool)}
}

func (rc *relationshipContext) addNode(n *bloodhound.Node) {
	if rc.created[n.ID] {
		return
	}
	rc.created[n.ID] = true
	rc.nodes = append(rc.nodes, n)
}

func (rc *relationshipContext) addEdge(from, kind, to string) {
	rc.edges = append(rc.edges, rzEdge(from, kind, to))
}

func rzEdge(from, kind, to string) *bloodhound.Edge {
	return &bloodhound.Edge{
		Start: bloodhound.EdgeDesc{Value: from, MatchBy: "id"},
		Kind:  kind,
		End:   bloodhound.EdgeDesc{Value: to, MatchBy: "id"},
	}
}

// assetNodeRef holds the precomputed node ID for an asset used by relationship extractors.
type assetNodeRef struct {
	nodeID string
	asset  *models.Asset
}

// extractAllRelationships runs all relationship extractors and returns merged nodes/edges.
func extractAllRelationships(refs []assetNodeRef) ([]*bloodhound.Node, []*bloodhound.Edge) {
	rc := newRelCtx()
	extractGatewayRelationships(rc, refs)
	extractSSHKeyEntities(rc, refs)
	extractTLSCertEntities(rc, refs)
	extractSNMPEngineEntities(rc, refs)
	extractIPMIEntities(rc, refs)
	extractTracerouteEntities(rc, refs)
	extractMACEntities(rc, refs)
	extractSwitchRelationships(rc, refs)
	return rc.nodes, rc.edges
}

// ---------------------------------------------------------------------------
// Gateway relationships: BACnet, CIP, KNXnet, Modbus
// ---------------------------------------------------------------------------

// gatewayKey extracts the gateway identifier from a protocol ID string.
// Returns (gatewayID, protocol) or empty if not applicable.
func gatewayKey(attr map[string]string) (string, string) {
	if bid := firstTabVal(attr["bacnet.id"]); bid != "" {
		// format: IP/port/network:devIdx/instanceNum → gateway = IP/port
		parts := strings.SplitN(bid, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1], "bacnet"
		}
	}
	if cid := firstTabVal(attr["cip.id"]); cid != "" {
		// format: IP:port/slot/.../instanceNum → gateway = IP:port
		parts := strings.SplitN(cid, "/", 2)
		if len(parts) >= 1 {
			return parts[0], "cip"
		}
	}
	if kid := firstTabVal(attr["knxnet.id"]); kid != "" {
		// format: IP/port/addr → gateway = IP/port
		parts := strings.SplitN(kid, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1], "knxnet"
		}
	}
	if mid := firstTabVal(attr["modbus.id"]); mid != "" {
		// format: IP/port/unitID → gateway = IP/port
		parts := strings.SplitN(mid, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1], "modbus"
		}
	}
	return "", ""
}

func extractGatewayRelationships(rc *relationshipContext, refs []assetNodeRef) {
	// Group assets by gateway key.
	type gatewayInfo struct {
		protocol string
		ip       string
		port     string
		assets   []string // node IDs
	}
	gateways := make(map[string]*gatewayInfo)

	for _, ref := range refs {
		gk, proto := gatewayKey(ref.asset.Attributes)
		if gk == "" {
			continue
		}
		gi, ok := gateways[gk]
		if !ok {
			// Parse IP and port from gateway key
			var ip, port string
			if strings.Contains(gk, ":") && !strings.Contains(gk, "/") {
				// CIP format: IP:port
				parts := strings.SplitN(gk, ":", 2)
				ip = parts[0]
				if len(parts) > 1 {
					port = parts[1]
				}
			} else {
				// BACnet/KNXnet/Modbus: IP/port
				parts := strings.SplitN(gk, "/", 2)
				ip = parts[0]
				if len(parts) > 1 {
					port = parts[1]
				}
			}
			gi = &gatewayInfo{protocol: proto, ip: ip, port: port}
			gateways[gk] = gi
		}
		gi.assets = append(gi.assets, ref.nodeID)
	}

	for gk, gi := range gateways {
		gwNodeID := "rz-gateway-" + sanitizeID(gk)
		displayName := fmt.Sprintf("%s %s gateway (%s)", gi.protocol, gi.ip, gi.port)

		rc.addNode(&bloodhound.Node{
			ID:    gwNodeID,
			Kinds: []string{"RZGateway"},
			Properties: map[string]any{
				"displayname": displayName,
				"ip":          gi.ip,
				"port":        gi.port,
				"protocol":    gi.protocol,
				"asset_count": len(gi.assets),
			},
		})

		for _, assetID := range gi.assets {
			rc.addEdge(assetID, "RZHasGateway", gwNodeID)
			rc.addEdge(gwNodeID, "RZHasGatewayAssets", assetID)
		}
	}

	cnt := len(gateways)
	if cnt > 0 {
		rlog("info", "created %d gateway nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// SSH Host Key entities
// ---------------------------------------------------------------------------

func extractSSHKeyEntities(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	for _, ref := range refs {
		for sk, svc := range ref.asset.Services {
			sha256 := svc["ssh.hostKey.sha256"]
			if sha256 == "" {
				continue
			}
			svcNodeID := fmt.Sprintf("rz-service-%s-%s", ref.asset.ID.String(), sk)

			// tab-separated multiple key fingerprints
			for _, fp := range strings.Split(sha256, "\t") {
				fp = strings.TrimSpace(fp)
				if fp == "" {
					continue
				}
				keyNodeID := "rz-sshkey-" + sanitizeID(fp)
				if !rc.created[keyNodeID] {
					cnt++
					keyType := ""
					// Try to find the key type from per-algorithm attributes
					for _, algo := range []string{"RSA", "ED25519", "ECDSASHA2NISTP256", "ECDSASHA2NISTP521", "DSS"} {
						if svc["ssh.hostKey"+algo+".sha256"] == fp {
							keyType = svc["ssh.hostKey"+algo+".type"]
							break
						}
					}
					rc.addNode(&bloodhound.Node{
						ID:    keyNodeID,
						Kinds: []string{"RZSSHKey"},
						Properties: map[string]any{
							"displayname": "SSH:" + fp[:min(16, len(fp))],
							"fingerprint": fp,
							"key_type":    keyType,
						},
					})
				}
				rc.addEdge(ref.nodeID, "RZHasSSHKey", keyNodeID)
				rc.addEdge(keyNodeID, "RZHasSSHService", svcNodeID)
			}
		}
	}
	if cnt > 0 {
		rlog("info", "created %d SSH key nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// TLS Certificate entities
// ---------------------------------------------------------------------------

func extractTLSCertEntities(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	for _, ref := range refs {
		for sk, svc := range ref.asset.Services {
			sha1 := firstTabVal(svc["tls.fp.sha1"])
			if sha1 == "" {
				continue
			}
			svcNodeID := fmt.Sprintf("rz-service-%s-%s", ref.asset.ID.String(), sk)
			certNodeID := "rz-tlscert-" + sanitizeID(sha1)
			if !rc.created[certNodeID] {
				cnt++
				props := map[string]any{
					"displayname": "TLS:" + sha1[:min(16, len(sha1))],
					"sha1":        sha1,
				}
				if cn := firstTabVal(svc["tls.cn"]); cn != "" {
					props["cn"] = cn
					props["displayname"] = fmt.Sprintf("TLS:%s (%s)", sha1[:min(12, len(sha1))], cn)
				}
				if sha256 := firstTabVal(svc["tls.fp.sha256"]); sha256 != "" {
					props["sha256"] = sha256
				}
				if issuer := firstTabVal(svc["tls.issuer"]); issuer != "" {
					props["issuer"] = issuer
				}
				if subject := firstTabVal(svc["tls.subject"]); subject != "" {
					props["subject"] = subject
				}
				if notAfter := firstTabVal(svc["tls.notAfter"]); notAfter != "" {
					props["not_after"] = notAfter
				}
				if selfSigned := firstTabVal(svc["tls.selfSigned"]); selfSigned != "" {
					props["self_signed"] = selfSigned
				}
				rc.addNode(&bloodhound.Node{
					ID:         certNodeID,
					Kinds:      []string{"RZTLSCert"},
					Properties: props,
				})
			}
			rc.addEdge(ref.nodeID, "RZHasTLSCert", certNodeID)
			rc.addEdge(certNodeID, "RZHasTLSService", svcNodeID)
		}
	}
	if cnt > 0 {
		rlog("info", "created %d TLS cert nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// SNMP v3 Engine ID entities
// ---------------------------------------------------------------------------

func extractSNMPEngineEntities(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	for _, ref := range refs {
		for sk, svc := range ref.asset.Services {
			raw := firstTabVal(svc["snmp.engineID.raw"])
			if raw == "" {
				continue
			}
			svcNodeID := fmt.Sprintf("rz-service-%s-%s", ref.asset.ID.String(), sk)
			engineNodeID := "rz-snmpengine-" + sanitizeID(raw)
			if !rc.created[engineNodeID] {
				cnt++
				props := map[string]any{
					"displayname": "SNMPv3:" + raw[:min(16, len(raw))],
					"engine_id":   raw,
				}
				if vendor := firstTabVal(svc["snmp.engineID.vendor"]); vendor != "" {
					props["vendor"] = vendor
				}
				if format := firstTabVal(svc["snmp.engineID.format"]); format != "" {
					props["format"] = format
				}
				if mac := firstTabVal(svc["snmp.engineID.mac"]); mac != "" {
					props["mac"] = mac
				}
				rc.addNode(&bloodhound.Node{
					ID:         engineNodeID,
					Kinds:      []string{"RZSNMPEngineID"},
					Properties: props,
				})
			}
			rc.addEdge(ref.nodeID, "RZHasSNMPEngineID", engineNodeID)
			rc.addEdge(engineNodeID, "RZHasSNMPService", svcNodeID)
		}
	}
	if cnt > 0 {
		rlog("info", "created %d SNMP v3 engine ID nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// IPMI entities
// ---------------------------------------------------------------------------

func extractIPMIEntities(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	for _, ref := range refs {
		for sk, svc := range ref.asset.Services {
			sessionStatus := firstTabVal(svc["ipmi.session.status"])
			if sessionStatus == "" {
				continue
			}
			svcNodeID := fmt.Sprintf("rz-service-%s-%s", ref.asset.ID.String(), sk)

			// Build a credential identity from the IPMI auth configuration
			cipherZero := firstTabVal(svc["ipmi.cipherZero"])
			userAuth := firstTabVal(svc["ipmi.userAuth"])
			passAuth := firstTabVal(svc["ipmi.passAuth"])
			connVersions := firstTabVal(svc["ipmi.connVersions"])

			// The credential key is based on the service endpoint
			credNodeID := fmt.Sprintf("rz-ipmi-%s-%s", ref.asset.ID.String(), sanitizeID(sk))
			if !rc.created[credNodeID] {
				cnt++
				props := map[string]any{
					"displayname":    fmt.Sprintf("IPMI:%s", sk),
					"session_status": sessionStatus,
					"cipher_zero":    cipherZero,
					"user_auth":      userAuth,
					"pass_auth":      passAuth,
					"conn_versions":  connVersions,
				}
				if sessionID := firstTabVal(svc["ipmi.session.id"]); sessionID != "" {
					props["session_id"] = sessionID
				}
				rc.addNode(&bloodhound.Node{
					ID:         credNodeID,
					Kinds:      []string{"RZIPMICredential"},
					Properties: props,
				})
			}
			rc.addEdge(ref.nodeID, "RZHasIPMICredential", credNodeID)
			rc.addEdge(credNodeID, "RZHasIPMIService", svcNodeID)
		}
	}
	if cnt > 0 {
		rlog("info", "created %d IPMI credential nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// Traceroute entities
// ---------------------------------------------------------------------------

func extractTracerouteEntities(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	for _, ref := range refs {
		traceVal := ref.asset.Attributes["ipv4.traceroute"]
		if traceVal == "" {
			continue
		}
		// Format: hop1/hop2/hop3,.../.../target
		// Each hop is an IP, multiple IPs per hop separated by ','
		// Empty entries represent non-responding hops
		hops := strings.Split(traceVal, "/")
		prevRouterID := ""
		for ttl, hop := range hops {
			hop = strings.TrimSpace(hop)
			if hop == "" {
				prevRouterID = ""
				continue
			}
			// Multiple IPs for a single hop (ECMP)
			ips := strings.Split(hop, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					continue
				}
				routerNodeID := "rz-router-" + sanitizeID(ip)
				if !rc.created[routerNodeID] {
					cnt++
					rc.addNode(&bloodhound.Node{
						ID:    routerNodeID,
						Kinds: []string{"RZRouter"},
						Properties: map[string]any{
							"displayname":  ip,
							"ip_addresses": []string{ip},
							"ttl":          ttl + 1,
						},
					})
				}
				// Link asset to router
				rc.addEdge(ref.nodeID, "RZHasRouter", routerNodeID)
				rc.addEdge(routerNodeID, "RZHasRouter", ref.nodeID)

				// Chain routers in order
				if prevRouterID != "" && prevRouterID != routerNodeID {
					rc.addEdge(prevRouterID, "RZHasRouter", routerNodeID)
					rc.addEdge(routerNodeID, "RZHasRouter", prevRouterID)
				}
				prevRouterID = routerNodeID
			}
		}
	}
	if cnt > 0 {
		rlog("info", "created %d traceroute router nodes", cnt)
	}
}

// ---------------------------------------------------------------------------
// MAC address entities with vendor lookup
// ---------------------------------------------------------------------------

func extractMACEntities(rc *relationshipContext, refs []assetNodeRef) {
	macCnt := 0
	vendorCnt := 0

	// Track vendor nodes
	vendors := make(map[string]int) // vendor name → asset count

	for _, ref := range refs {
		allMACs := make(map[string]bool)
		for _, m := range ref.asset.MACs {
			m = strings.ToLower(strings.TrimSpace(m))
			if m != "" && m != "00:00:00:00:00:00" {
				allMACs[m] = true
			}
		}
		if nm := strings.ToLower(strings.TrimSpace(ref.asset.NewestMAC)); nm != "" && nm != "00:00:00:00:00:00" {
			allMACs[nm] = true
		}

		for mac := range allMACs {
			macNodeID := "rz-mac-" + sanitizeID(mac)

			if !rc.created[macNodeID] {
				macCnt++
				props := map[string]any{
					"displayname": mac,
					"mac_address": mac,
				}
				// MAC vendor lookup
				block := mactracker.Lookup(mac)
				if block != nil {
					props["vendor"] = block.Vendor
					props["vendor_country"] = block.Country
					props["vendor_added"] = block.Added
					if block.Virtual != "" {
						props["virtual_platform"] = block.Virtual
					}
					if block.Private {
						props["private"] = true
					}
					vendors[block.Vendor]++
				}
				rc.addNode(&bloodhound.Node{
					ID:         macNodeID,
					Kinds:      []string{"RZMACAddress"},
					Properties: props,
				})
			}
			rc.addEdge(ref.nodeID, "RZHasMAC", macNodeID)
			rc.addEdge(macNodeID, "RZHasMACHost", ref.nodeID)

			// Link MAC to vendor node
			block := mactracker.Lookup(mac)
			if block != nil && block.Vendor != "" {
				vendorNodeID := "rz-macvendor-" + sanitizeID(block.Vendor)
				if !rc.created[vendorNodeID] {
					vendorCnt++
					rc.addNode(&bloodhound.Node{
						ID:    vendorNodeID,
						Kinds: []string{"RZMACVendor"},
						Properties: map[string]any{
							"displayname": block.Vendor,
							"vendor":      block.Vendor,
							"country":     block.Country,
							"added":       block.Added,
						},
					})
				}
				rc.addEdge(macNodeID, "RZHasMACVendor", vendorNodeID)
			}
		}
	}

	if macCnt > 0 {
		rlog("info", "created %d MAC address nodes, %d vendor nodes", macCnt, vendorCnt)
	}
}

// ---------------------------------------------------------------------------
// Switch relationships (SNMP ARP cache / MAC table / switch port)
// ---------------------------------------------------------------------------

func extractSwitchRelationships(rc *relationshipContext, refs []assetNodeRef) {
	cnt := 0
	subAssetCnt := 0

	for _, ref := range refs {
		switchIP := firstTabVal(ref.asset.Attributes["switch.ip"])
		if switchIP == "" {
			continue
		}
		switchName := firstTabVal(ref.asset.Attributes["switch.name"])
		switchPort := firstTabVal(ref.asset.Attributes["switch.port"])

		swNodeID := "rz-switch-" + sanitizeID(switchIP)
		if !rc.created[swNodeID] {
			cnt++
			display := switchIP
			if switchName != "" {
				display = fmt.Sprintf("%s (%s)", switchIP, switchName)
			}
			rc.addNode(&bloodhound.Node{
				ID:    swNodeID,
				Kinds: []string{"RZSwitch"},
				Properties: map[string]any{
					"displayname": display,
					"ip":          switchIP,
					"name":        switchName,
				},
			})
		}

		rc.addEdge(ref.nodeID, "RZHasSwitch", swNodeID)
		rc.addEdge(swNodeID, "RZHasSwitchAssets", ref.nodeID)

		if switchPort != "" {
			portNodeID := "rz-switchport-" + sanitizeID(switchPort)
			if !rc.created[portNodeID] {
				rc.addNode(&bloodhound.Node{
					ID:    portNodeID,
					Kinds: []string{"RZSwitchPort"},
					Properties: map[string]any{
						"displayname": switchPort,
						"port":        switchPort,
					},
				})
			}
			rc.addEdge(swNodeID, "RZHasSwitchPort", portNodeID)
			rc.addEdge(ref.nodeID, "RZConnectedToPort", portNodeID)
		}

		// Create sub-assets for ARP/MAC table entries referenced in _links.ports
		arpMACs := firstTabVal(ref.asset.Attributes["_links.ports.unmapped"])
		if arpMACs != "" {
			for _, mac := range strings.Split(arpMACs, "\t") {
				mac = strings.ToLower(strings.TrimSpace(mac))
				if mac == "" || mac == "00:00:00:00:00:00" {
					continue
				}
				subAssetCnt++
				saNodeID := "rz-switchmac-" + sanitizeID(mac)
				if !rc.created[saNodeID] {
					props := map[string]any{
						"displayname": mac,
						"mac_address": mac,
						"type":        "switch_mac",
					}
					block := mactracker.Lookup(mac)
					if block != nil {
						props["vendor"] = block.Vendor
					}
					rc.addNode(&bloodhound.Node{
						ID:         saNodeID,
						Kinds:      []string{"RZSubAsset"},
						Properties: props,
					})
				}
				rc.addEdge(swNodeID, "RZHasSwitchAssets", saNodeID)
				rc.addEdge(saNodeID, "RZHasSwitch", swNodeID)
			}
		}
	}

	if cnt > 0 {
		rlog("info", "created %d switch nodes, %d switch sub-assets", cnt, subAssetCnt)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// firstTabVal returns the first tab-separated value from a runZero attribute string.
func firstTabVal(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "\t"); idx >= 0 {
		return s[:idx]
	}
	return s
}

// sanitizeID makes a string safe for use in a BloodHound node ID.
func sanitizeID(s string) string {
	r := strings.NewReplacer(
		":", "-",
		" ", "_",
		"/", "-",
		"\\", "-",
		"(", "",
		")", "",
		"{", "",
		"}", "",
		"'", "",
		"\"", "",
		",", "_",
	)
	return strings.ToLower(r.Replace(s))
}

// sortedMapKeys returns sorted keys from a map.
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
