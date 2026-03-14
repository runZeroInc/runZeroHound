package cmd

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/runZeroInc/runZeroHound/pkg/bloodhound"
	"github.com/spf13/cobra"
)

//go:embed web
var webFS embed.FS

type ServeSettings struct {
	Port int
	Host string
}

var serveSettings = ServeSettings{}

func init() {
	serveCmd.Flags().IntVarP(&serveSettings.Port, "port", "p", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&serveSettings.Host, "host", "127.0.0.1", "Host to bind to")
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve <graph.json>",
	Short: "Serve an interactive graph visualization in the browser",
	Long:  "Start a local web server that presents an interactive visualization of a runZero OpenGraph JSON file",
	Args:  cobra.ExactArgs(1),
	Run:   runServe,
}

type frontendNode struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Kind        string         `json:"kind"`
	X           float64        `json:"x"`
	Y           float64        `json:"y"`
	MultiSubnet bool           `json:"multiSubnet,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

type frontendEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type frontendGraph struct {
	Nodes []frontendNode `json:"nodes"`
	Edges []frontendEdge `json:"edges"`
}

func runServe(cmd *cobra.Command, args []string) {
	inputFile := args[0]

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", inputFile, err)
		os.Exit(1)
	}

	var container bloodhound.GraphContainer
	if err := json.Unmarshal(data, &container); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	if container.Graph == nil || len(container.Graph.Nodes) == 0 {
		fmt.Fprintln(os.Stderr, "Error: graph contains no nodes")
		os.Exit(1)
	}

	fg := transformGraphForFrontend(container.Graph)

	graphJSON, err := json.Marshal(fg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing graph: %v\n", err)
		os.Exit(1)
	}

	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading web assets: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(webContent)))
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(graphJSON)
	})

	addr := fmt.Sprintf("%s:%d", serveSettings.Host, serveSettings.Port)
	fmt.Printf("runZeroHound graph explorer\n")
	fmt.Printf("  Graph: %d nodes, %d edges\n", len(fg.Nodes), len(fg.Edges))
	fmt.Printf("  URL:   http://%s\n", addr)
	rlog("info", "starting server on http://%s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func transformGraphForFrontend(graph *bloodhound.Graph) *frontendGraph {
	nodeMap := make(map[string]*bloodhound.Node, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if slices.Contains(node.Kinds, "RZService") {
			// Skip services
			continue
		}
		if slices.Contains(node.Kinds, "RZNetwork") && strings.Contains(fmt.Sprint(node.Properties["displayname"]), ":") {
			// Skip IPv6 for now
			continue
		}
		nodeMap[node.ID] = node
	}

	childrenOf := make(map[string][]string)
	primaryParent := make(map[string]string)

	for _, edge := range graph.Edges {
		if _, ok := nodeMap[edge.Start.Value]; !ok {
			continue
		}
		if _, ok := nodeMap[edge.End.Value]; !ok {
			continue
		}
		if edge.Kind == "RZHasService" || edge.Kind == "RunsOnAsset" {
			// Skip services
			continue
		}
		if strings.Contains(fmt.Sprint(edge.End.Value), ":") {
			// Skip IPv6 for now
			continue
		}

		if edge.Kind == "RZSubnetContains" {
			childrenOf[edge.Start.Value] = append(childrenOf[edge.Start.Value], edge.End.Value)
			if _, exists := primaryParent[edge.End.Value]; !exists {
				primaryParent[edge.End.Value] = edge.Start.Value
			}
		}
	}

	// Count subnet parents per asset (for multi-subnet detection)
	subnetParentCount := make(map[string]int)
	for _, edge := range graph.Edges {
		if edge.Kind == "RZSubnetContains" {
			if _, ok := nodeMap[edge.Start.Value]; ok {
				if _, ok := nodeMap[edge.End.Value]; ok {
					subnetParentCount[edge.End.Value]++
				}
			}
		}
	}

	// Group non-service nodes by kind
	byKind := make(map[string][]string)
	for _, node := range graph.Nodes {
		kind := graphNodeKind(node)
		byKind[kind] = append(byKind[kind], node.ID)
	}

	// Identify Global Internet nodes by displayname
	globalInternetIDs := make(map[string]bool)
	for _, node := range graph.Nodes {
		if dn, ok := node.Properties["displayname"]; ok {
			if s, ok := dn.(string); ok && s == "Global Internet" {
				globalInternetIDs[node.ID] = true
			}
		}
	}

	positions := computeHierarchicalLayout(byKind, childrenOf, primaryParent, globalInternetIDs)

	// Build frontend nodes (skip services)
	fg := &frontendGraph{
		Nodes: make([]frontendNode, 0, len(graph.Nodes)),
		Edges: make([]frontendEdge, 0, len(graph.Edges)),
	}

	for _, node := range graph.Nodes {
		if _, ok := nodeMap[node.ID]; !ok {
			continue
		}
		kind := graphNodeKind(node)
		label := node.ID
		if dn, ok := node.Properties["displayname"]; ok {
			if s, ok := dn.(string); ok && s != "" {
				label = s
			}
		}
		pos := positions[node.ID]
		multiSubnet := kind == "RZAsset" && subnetParentCount[node.ID] > 1
		fg.Nodes = append(fg.Nodes, frontendNode{
			ID:          node.ID,
			Label:       label,
			Kind:        kind,
			X:           pos[0],
			Y:           pos[1],
			MultiSubnet: multiSubnet,
			Properties:  node.Properties,
		})
	}

	for _, edge := range graph.Edges {
		if _, ok := nodeMap[edge.Start.Value]; !ok {
			continue
		}
		if _, ok := nodeMap[edge.End.Value]; !ok {
			continue
		}
		fg.Edges = append(fg.Edges, frontendEdge{
			Source: edge.Start.Value,
			Target: edge.End.Value,
			Kind:   edge.Kind,
		})
	}

	return fg
}

func computeHierarchicalLayout(
	byKind map[string][]string,
	childrenOf map[string][]string,
	primaryParent map[string]string,
	globalInternetIDs map[string]bool,
) map[string][2]float64 {
	positions := make(map[string][2]float64)

	// Networks in a circle at the center
	networks := byKind["RZNetwork"]
	networkRadius := math.Max(float64(len(networks))*60, 400)

	// Separate Global Internet nodes from regular networks
	var regularNetworks []string
	var globalNetworks []string
	for _, id := range networks {
		if globalInternetIDs[id] {
			globalNetworks = append(globalNetworks, id)
		} else {
			regularNetworks = append(regularNetworks, id)
		}
	}

	// Position Global Internet nodes at the far left with vertical spacing
	globalX := -networkRadius * 1.3
	for i, id := range globalNetworks {
		offset := float64(i) * 10
		positions[id] = [2]float64{globalX, offset}
	}

	// Regular networks in a circle at the center
	for i, id := range regularNetworks {
		angle := 2 * math.Pi * float64(i) / math.Max(float64(len(regularNetworks)), 1)
		positions[id] = [2]float64{
			networkRadius * math.Cos(angle),
			networkRadius * math.Sin(angle),
		}
	}

	// Assets around their parent network
	netAssetCount := make(map[string]int)
	netAssetIndex := make(map[string]int)
	for _, assetID := range byKind["RZAsset"] {
		parent := primaryParent[assetID]
		if parent != "" {
			netAssetCount[parent]++
		}
	}
	for _, assetID := range byKind["RZAsset"] {
		parent := primaryParent[assetID]
		if parent == "" {
			positions[assetID] = [2]float64{0, 0}
			continue
		}
		parentPos := positions[parent]
		count := netAssetCount[parent]
		idx := netAssetIndex[parent]
		netAssetIndex[parent]++

		assetRadius := math.Max(float64(count)*6, 80)
		angle := 2 * math.Pi * float64(idx) / math.Max(float64(count), 1)
		positions[assetID] = [2]float64{
			parentPos[0] + assetRadius*math.Cos(angle),
			parentPos[1] + assetRadius*math.Sin(angle),
		}
	}

	// Domains in a cluster offset from center
	domains := byKind["RZDomain"]
	domainCX := -networkRadius * 1.3
	domainCY := -networkRadius * 0.5
	for i, id := range domains {
		angle := 2 * math.Pi * float64(i) / math.Max(float64(len(domains)), 1)
		positions[id] = [2]float64{
			domainCX + 60*math.Cos(angle),
			domainCY + 60*math.Sin(angle),
		}
	}

	// VLANs in a cluster on the other side
	vlans := byKind["RZVLAN"]
	vlanCX := networkRadius * 1.3
	vlanCY := -networkRadius * 0.5
	for i, id := range vlans {
		angle := 2 * math.Pi * float64(i) / math.Max(float64(len(vlans)), 1)
		positions[id] = [2]float64{
			vlanCX + 60*math.Cos(angle),
			vlanCY + 60*math.Sin(angle),
		}
	}

	return positions
}

func graphNodeKind(node *bloodhound.Node) string {
	if len(node.Kinds) > 0 {
		return node.Kinds[0]
	}
	return "Unknown"
}
