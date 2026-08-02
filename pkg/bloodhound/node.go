package bloodhound

type GraphContainer struct {
	Metadata map[string]any `json:"metadata,omitempty"`
	Graph    *Graph         `json:"graph,omitempty"`
}

type Graph struct {
	Nodes []*Node `json:"nodes,omitempty"`
	Edges []*Edge `json:"edges,omitempty"`
}

type Node struct {
	ID         string         `json:"id,omitempty"`
	Kinds      []string       `json:"kinds,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type EdgeDesc struct {
	Value   string `json:"value,omitempty"`
	MatchBy string `json:"match_by,omitempty"`
}
type Edge struct {
	Kind  string   `json:"kind,omitempty"`
	Start EdgeDesc `json:"start,omitempty"`
	End   EdgeDesc `json:"end,omitempty"`
	// Properties are optional edge attributes. Open Graph accepts them and
	// they are how an edge records which disclosure produced it.
	Properties map[string]any `json:"properties,omitempty"`
}
