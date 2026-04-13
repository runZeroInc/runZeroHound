package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/runZeroInc/runZeroHound/pkg/bloodhound"
	"github.com/runZeroInc/runZeroHound/pkg/input"
	"github.com/runZeroInc/runZeroHound/pkg/runzero"
	"github.com/runZeroInc/runZeroHound/pkg/runzero/models"
	"github.com/runZeroInc/runZeroHound/pkg/runzero/sanitize"
	"github.com/spf13/cobra"
)

type ConvertSettings struct {
	Prefix     string
	OutputFile string
	OutputFD   *os.File
	Type       string
}

var convertSettings = ConvertSettings{}

func init() {
	convertCmd.Flags().StringVarP(&convertSettings.Type, "type", "t", "opengraph", "Specify the type of graph to generate")
	convertCmd.Flags().StringVarP(&convertSettings.OutputFile, "output", "o", "-", "Output file path ('-' for stdout)")
	rootCmd.AddCommand(convertCmd)
}

var convertCmd = &cobra.Command{
	Use:   "convert <input1> [input2 ...]",
	Short: "Generate graph data from one or more network scan files",
	Long: `Convert one or more input files into BloodHound OpenGraph format.

Supported input types (auto-detected):
  runzero   runZero asset export (.json.gz or .jsonl)
  nmap      Nmap XML output (-oX)
  snmpwalk  net-snmp snmpwalk text output
  nessus    Nessus vulnerability scanner report (.nessus)
  openvas   OpenVAS/GVM XML report
  netbox    NetBox DCIM/IPAM JSON API export
  qualys    Qualys VM scan XML report
  masscan   Masscan XML (-oX) or JSON (-oJ) output
  shodan    Shodan JSONL export

Use -o/--output to specify the output file (default: stdout).
`,
	Run: generateGraph,
}

func generateGraph(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Printf("Usage: %s convert [options] <input1> [input2 ...]\n", ToolName)
		return
	}

	outFile := convertSettings.OutputFile
	outFd := os.Stdout
	if outFile != "-" {
		var err error
		outFd, err = os.Create(outFile) // #nosec G304
		if err != nil {
			fmt.Printf("error creating output file %s: %v\n", outFile, err)
			return
		}
		defer outFd.Close()
	}
	convertSettings.OutputFD = outFd

	switch convertSettings.Type {
	case "opengraph":
		err := generateOpenGraph(args, convertSettings.OutputFD)
		if err != nil {
			fmt.Printf("error generating OpenGraph: %v\n", err)
		}
	default:
		fmt.Printf("unsupported graph type: %s\n", convertSettings.Type)
	}
}

func generateOpenGraph(inputFiles []string, outputFD *os.File) error {
	allNodes := []*bloodhound.Node{}
	allEdges := []*bloodhound.Edge{}

	// Track which subnet / domain / vlan nodes have already been added so we
	// don't duplicate them when merging results across multiple input files.
	addedNodes := make(map[string]bool)

	mergeResult := func(nodes []*bloodhound.Node, edges []*bloodhound.Edge) {
		for _, n := range nodes {
			if !addedNodes[n.ID] {
				addedNodes[n.ID] = true
				allNodes = append(allNodes, n)
			}
		}
		allEdges = append(allEdges, edges...)
	}

	for _, path := range inputFiles {
		ft, err := input.DetectFileType(path)
		if err != nil {
			return fmt.Errorf("cannot detect type of %s: %w", path, err)
		}
		rlog("info", "processing %s as %s", path, ft)

		switch ft {
		case input.FileTypeRunZeroGZIP, input.FileTypeRunZeroJSONL:
			assets, err := loadGraphAssets(path)
			if err != nil {
				return fmt.Errorf("load runzero %s: %w", path, err)
			}
			nodes, edges, err := buildOpenGraph(assets)
			if err != nil {
				return fmt.Errorf("build graph from %s: %w", path, err)
			}
			mergeResult(nodes, edges)

		case input.FileTypeNmapXML:
			result, err := input.ParseNmapXML(path)
			if err != nil {
				return fmt.Errorf("parse nmap %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeSNMPWalk:
			result, err := input.ParseSNMPWalk(path)
			if err != nil {
				return fmt.Errorf("parse snmpwalk %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeNessus:
			result, err := input.ParseNessus(path)
			if err != nil {
				return fmt.Errorf("parse nessus %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeOpenVAS:
			result, err := input.ParseOpenVAS(path)
			if err != nil {
				return fmt.Errorf("parse openvas %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeNetBox:
			result, err := input.ParseNetBox(path)
			if err != nil {
				return fmt.Errorf("parse netbox %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeQualys:
			result, err := input.ParseQualys(path)
			if err != nil {
				return fmt.Errorf("parse qualys %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeMasscan:
			result, err := input.ParseMasscan(path)
			if err != nil {
				return fmt.Errorf("parse masscan %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		case input.FileTypeShodan:
			result, err := input.ParseShodan(path)
			if err != nil {
				return fmt.Errorf("parse shodan %s: %w", path, err)
			}
			nodes, edges := input.BuildOpenGraph(result.Hosts)
			mergeResult(nodes, edges)

		default:
			return fmt.Errorf("unsupported file type for %s", path)
		}
	}

	g := &bloodhound.GraphContainer{
		Metadata: map[string]any{
			"source_kind": "RunZeroHound",
		},
		Graph: &bloodhound.Graph{
			Nodes: allNodes,
			Edges: allEdges,
		},
	}

	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	if _, err = outputFD.Write(data); err != nil {
		return fmt.Errorf("error writing output: %v", err)
	}

	if err = outputFD.Close(); err != nil {
		return fmt.Errorf("error closing output: %v", err)
	}

	rlog("info", "OpenGraph generation complete with %d nodes and %d edges", len(allNodes), len(allEdges))
	return nil
}

func loadGraphAssets(path string) ([]*models.Asset, error) {
	wg := sync.WaitGroup{}
	fdc := make(chan string, 1)
	assets := make([]*models.Asset, 0)

	lock := sync.Mutex{}
	acnt := atomic.Int64{}
	stime := time.Now()

	assetLineWorker := func() {
		defer wg.Done()
		for line := range fdc {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			ima := &models.Asset{}

			err := json.Unmarshal([]byte(line), ima)
			if err != nil {
				rlog("error", "failed to deserialize asset: %s", err)
				continue
			}

			lock.Lock()
			acnt.Add(1)
			if acnt.Load()%1000 == 0 {
				rlog("info", "loaded %d assets in %s", acnt.Load(), time.Since(stime).Truncate(time.Second))
			}
			assets = append(assets, ima)
			lock.Unlock()
		}
	}

	fd, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go assetLineWorker()
	}

	err = runzero.ReadLines(fd, fdc)
	if err != nil {
		return nil, err
	}
	wg.Wait()

	rlog("info", "loaded %d assets in %s", acnt.Load(), time.Since(stime).Truncate(time.Second))

	return assets, nil
}

func buildOpenGraph(assets []*models.Asset) ([]*bloodhound.Node, []*bloodhound.Edge, error) {

	v4Mask := "24"
	v6Mask := "56"

	// Build the nodes

	nodes := []*bloodhound.Node{}
	edges := []*bloodhound.Edge{}

	subnets := make(map[string]uint64)
	domains := make(map[string]uint64)
	vlans := make(map[string]uint64)

	// Collect asset references for the relationship extractors (second pass).
	assetRefs := make([]assetNodeRef, 0, len(assets))

	bCount := 0

	for _, asset := range assets {
		aset := make(map[string]bool)
		for _, addr := range asset.Addresses {
			aset[addr] = true
		}
		for _, addr := range asset.AddressesExtra {
			aset[addr] = true
		}

		nset := make(map[string]string)
		for addr := range aset {
			mask := v4Mask
			if strings.Contains(addr, ":") {
				mask = v6Mask
			}
			ipb, ipn, err := net.ParseCIDR(addr + "/" + mask)
			if err != nil {
				continue
			}
			if ipb.IsLinkLocalUnicast() || ipb.IsLoopback() || ipb.IsMulticast() || ipb.IsUnspecified() {
				continue
			}
			nset[ipn.String()] = addr
			subnets[ipn.String()]++
		}

		src := []string{}
		dst := []string{}

		for k, v := range nset {
			if k == "" || v == "" {
				continue
			}
			dst = append(dst, k)
			src = append(src, v)
		}

		if len(src) == 0 || len(dst) == 0 {
			continue
		}

		hostName := src[0]
		srcName := src[0]
		if len(asset.Names) > 0 {
			nits := strings.Split(asset.Names[0], ".")
			if len(nits[0]) > 0 {
				hostName = nits[0]
				srcName = fmt.Sprintf("%s (%s)", src[0], nits[0])
			}
		}
		bCount++

		label := srcName
		labelSplit := strings.Split(label, "\n")
		if len(labelSplit) >= 2 {
			host := labelSplit[1]
			host = strings.TrimLeft(host, "(")
			host = strings.TrimRight(host, ")")
			host = sanitize.Truncate(host, 22)
			labelSplit[1] = fmt.Sprintf("(%s)", host)
			label = strings.Join(labelSplit, " ")
		}
		deviceType := asset.Type
		if deviceType == "" {
			deviceType = "device"
		}

		nodeID := "rz-asset-" + asset.ID.String()

		// Generate a BloodHound-style hostname based on NTLM responses
		ntlmName := hostName
		for _, v := range strings.Fields(asset.Attributes["ntlmssp.dnsComputer"]) {
			v = strings.ToUpper(v)
			if v != "" {
				ntlmName = v
			}
			break
		}

		// Resolve source IDs to names
		sourceNames := make([]string, len(asset.SourceIDs))
		for i, sid := range asset.SourceIDs {
			sname, ok := runzero.SourceNames[sid]
			if !ok {
				sname = "source-" + strconv.Itoa(i)
			}
			sourceNames[i] = sname
		}

		// Convert functions map to a sorted string array for OpenGraph schema compliance
		funcList := make([]string, 0, len(asset.Functions))
		for k := range asset.Functions {
			funcList = append(funcList, k)
		}
		sort.Strings(funcList)

		assetNode := &bloodhound.Node{
			ID:    nodeID,
			Kinds: []string{"RZAsset"},
			Properties: map[string]any{
				"displayname":            label,
				"name":                   ntlmName,
				"hostname":               hostName,
				"names":                  asset.Names,
				"domains":                asset.Domains,
				"type":                   deviceType,
				"category":               asset.Category,
				"rz_functions":           funcList,
				"os":                     asset.OS,
				"hw":                     asset.HW,
				"ip_addresses":           asset.Addresses,
				"ip_address_count":       len(asset.Addresses),
				"ip_addresses_extra":     asset.AddressesExtra,
				"ip_address_extra_count": len(asset.AddressesExtra),
				"mac_addresses":          asset.MACs,
				"newest_mac":             asset.NewestMAC,
				"newest_mac_vendor":      asset.NewestMACVendor,
				"newest_mac_age":         asset.NewestMACAge,
				"lowest_ttl":             asset.LowestTTL,
				"lowest_rtt":             asset.LowestRTT,
				"alive":                  asset.Alive,
				"scanned":                asset.Scanned,
				"comments":               asset.Comments,
				"services_count":         asset.ServiceCount,
				"services_tcp_count":     asset.ServiceCountTCP,
				"services_udp_count":     asset.ServiceCountUDP,
				"services_icmp_count":    asset.ServiceCountICMP,
				"services_arp_count":     asset.ServiceCountARP,
				"software_count":         asset.SoftwareCount,
				"vulnerability_count":    asset.VulnerabilityCount,
				"risk":                   runzero.RiskRankToName[asset.RiskRank],
				"risk_rank":              asset.RiskRank,
				"outlier_score":          asset.OutlierScore,
				"outlier_raw":            asset.OutlierRaw,
				"first_seen":             asset.FirstSeen,
				"last_seen":              asset.LastSeen,
				"created_at":             asset.CreatedAt,
				"updated_at":             asset.UpdatedAt,
				"sources":                sourceNames,
				"organization_name":      asset.OrganizationName,
				"site_name":              asset.SiteName,
				"agent_name":             asset.AgentName,
				"agent_external_ip":      asset.AgentExternalIP,
				"hosted_zone_name":       asset.HostedZoneName,
				"last_agent_id":          asset.LastAgentID,
				"last_task_id":           asset.LastTaskID,
				"first_task_id":          asset.FirstTaskID,
			},
		}

		if len(asset.ServiceProtocols) > 0 {
			assetNode.Properties["service_protocols"] = asset.ServiceProtocols
		}

		if len(asset.ServiceProducts) > 0 {
			assetNode.Properties["service_products"] = asset.ServiceProducts
		}

		if len(asset.ServicePortsTCP) > 0 {
			assetNode.Properties["service_ports_tcp"] = asset.ServicePortsTCP
		}

		if len(asset.ServicePortsUDP) > 0 {
			assetNode.Properties["service_ports_udp"] = asset.ServicePortsUDP
		}

		// Add Asset tags
		if len(asset.Tags) > 0 {
			tags := make([]string, 0, len(asset.Tags))
			for k, v := range asset.Tags {
				if v == "" {
					tags = append(tags, k)
				} else {
					tags = append(tags, fmt.Sprintf("%s=%s", k, v))
				}
			}
			sort.Strings(tags)
			assetNode.Properties["tags"] = tags
		}

		// Add Asset attributes (flattened, deduplicated, and sorted)
		assetAttr := make(map[string]map[string]struct{})
		for k, sv := range asset.Attributes {
			if strings.HasPrefix(k, "_") {
				continue
			}
			attrKey := "runzero." + k
			if k == "vlan" {
				attrKey = k
			}
			for _, v := range strings.Split(sv, "\t") {
				if _, ok := assetAttr[attrKey]; !ok {
					assetAttr[attrKey] = make(map[string]struct{})
				}
				assetAttr[attrKey][v] = struct{}{}
			}
		}
		// Add Foreign Attributes
		for attrType, attrSet := range asset.ForeignAttributes {
			for _, attrVals := range attrSet {
				for k, tsv := range attrVals {
					attrKey := strings.ReplaceAll(attrType, "@", "") + "." + k
					for _, v := range strings.Split(tsv, "\t") {
						if _, ok := assetAttr[attrKey]; !ok {
							assetAttr[attrKey] = make(map[string]struct{})
						}
						assetAttr[attrKey][v] = struct{}{}
					}
				}
			}
		}
		// Stored unique sorted values
		for ak, av := range assetAttr {
			vals := make([]string, 0, len(av))
			for v := range av {
				vals = append(vals, v)
			}
			sort.Strings(vals)
			assetNode.Properties[ak] = vals
		}

		// Add runZero site subnet mappings
		rzSubnets := make([]string, 0, len(asset.Subnets))
		for k := range asset.Subnets {
			rzSubnets = append(rzSubnets, k)
		}
		assetNode.Properties["subnets"] = rzSubnets

		// TODO: Implement layer-2 switch links
		/*
			"_links.ports.mapped": "<links>",
			"_links.ports.unmapped": "<macs>",
			"switch.ip": "192.168.0.31",
			"switch.name": "M4300-OFFICE",
			"switch.port": "192.168.0.31-1/0/15",
		*/

		// Add the Asset node
		nodes = append(nodes, assetNode)

		// Collect ref for second-pass relationship extraction
		assetRefs = append(assetRefs, assetNodeRef{nodeID: nodeID, asset: asset})

		// Create and link the Service nodes
		for sk, svc := range asset.Services {
			svcNodeID := fmt.Sprintf("rz-service-%s-%s", asset.ID.String(), sk)
			svcNode := &bloodhound.Node{
				ID:    svcNodeID,
				Kinds: []string{"RZService"},
				Properties: map[string]any{
					"displayname": sk,
					"address":     svc["service.address"],
					"port":        svc["service.port"],
					"transport":   svc["service.transport"],
				},
			}

			// Add Service attributes (deduplicated and sorted)
			svcAttr := make(map[string]map[string]struct{})
			for k, sv := range svc {
				if strings.HasPrefix(k, "_") || strings.HasPrefix(k, "service.") {
					continue
				}
				for _, v := range strings.Split(sv, "\t") {
					attrKey := "attr_" + k
					if _, ok := svcAttr[attrKey]; !ok {
						svcAttr[attrKey] = make(map[string]struct{})
					}
					svcAttr[attrKey][v] = struct{}{}
				}
			}
			// Stored unique sorted values
			for ak, av := range svcAttr {
				vals := make([]string, 0, len(av))
				for v := range av {
					vals = append(vals, v)
				}
				sort.Strings(vals)
				svcNode.Properties[ak] = vals
			}

			// Add the Service node
			nodes = append(nodes, svcNode)

			// Edge from Asset to Service
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
				Kind: "RZHasService",
				End: bloodhound.EdgeDesc{
					Value:   svcNodeID,
					MatchBy: "id",
				},
			})

			// Edge from Service to Asset
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   svcNodeID,
					MatchBy: "id",
				},
				Kind: "RZRunsOnAsset",
				End: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
			})
		}

		// Create edges to the subnet nodes
		for _, dstName := range dst {
			// Forward
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
				Kind: "RZInsideOfSubnet",
				End: bloodhound.EdgeDesc{
					Value:   "rz-network-" + dstName,
					MatchBy: "id",
				},
			})
			// Backwards
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   "rz-network-" + dstName,
					MatchBy: "id",
				},
				Kind: "RZSubnetContains",
				End: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
			})
		}

		// Domains
		for _, domain := range asset.Domains {
			domains[domain]++
			// Forward
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
				Kind: "RZPartOfDomain",
				End: bloodhound.EdgeDesc{
					Value:   "rz-domain-" + domain,
					MatchBy: "id",
				},
			})
			// Backwards
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   "rz-domain-" + domain,
					MatchBy: "id",
				},
				Kind: "RZDomainContains",
				End: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
			})
		}

		// VLANs
		for _, vlan := range strings.Split(asset.Attributes["vlan"], "\t") {
			if vlan == "" {
				continue
			}
			vlans[vlan]++
			// Forward
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
				Kind: "RZPartOfVLAN",
				End: bloodhound.EdgeDesc{
					Value:   "rz-vlan-" + vlan,
					MatchBy: "id",
				},
			})
			// Backwards
			edges = append(edges, &bloodhound.Edge{
				Start: bloodhound.EdgeDesc{
					Value:   "rz-vlan-" + vlan,
					MatchBy: "id",
				},
				Kind: "RZVLANContains",
				End: bloodhound.EdgeDesc{
					Value:   nodeID,
					MatchBy: "id",
				},
			})
		}
	}

	// --- Second pass: extract protocol-specific relationships ---
	relNodes, relEdges := extractAllRelationships(assetRefs)
	nodes = append(nodes, relNodes...)
	edges = append(edges, relEdges...)

	// Build the subnet nodes and edges
	for network := range subnets {
		bip := strings.Split(network, "/")

		internal := runzero.IsPrivateIPAddress(bip[0])
		isv6 := strings.Contains(bip[0], ":")

		if !internal {
			// Create an edge to the internet cloud
			edges = append(edges,
				&bloodhound.Edge{
					Start: bloodhound.EdgeDesc{Value: "rz-network-" + network, MatchBy: "id"},
					Kind:  "RZInsideOfSubnet", // All public subnets are inside the internet
					End:   bloodhound.EdgeDesc{Value: "rz-network-public", MatchBy: "id"},
				},
			)
			// Create an edge from the internet cloud
			edges = append(edges,
				&bloodhound.Edge{
					Start: bloodhound.EdgeDesc{Value: "rz-network-public", MatchBy: "id"},
					Kind:  "RZSubnetContains", // The internet contains all public subnets
					End:   bloodhound.EdgeDesc{Value: "rz-network-" + network, MatchBy: "id"},
				},
			)
		}
		version := "4"
		if isv6 {
			version = "6"
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

	// Always create the internet node to represent the public internet
	network := "Public Internet"
	nodes = append(nodes, &bloodhound.Node{
		ID:    "rz-network-public",
		Kinds: []string{"RZNetwork"},
		Properties: map[string]any{
			"displayname":     network,
			"network_address": "0.0.0.0",
		},
	})

	// Build domain nodes
	for domain, cnt := range domains {
		nodes = append(nodes, &bloodhound.Node{
			ID:    "rz-domain-" + domain,
			Kinds: []string{"RZDomain"},
			Properties: map[string]any{
				"displayname": domain,
				"host_count":  cnt,
			},
		})
	}

	// Build the vlan nodes
	for vlan, cnt := range vlans {
		nodes = append(nodes, &bloodhound.Node{
			ID:    "rz-vlan-" + vlan,
			Kinds: []string{"RZVLAN"},
			Properties: map[string]any{
				"displayname": vlan,
				"host_count":  cnt,
			},
		})
	}

	return nodes, edges, nil
}
