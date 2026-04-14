package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var cypherBH = BHSettings{}

func init() {
	addBHFlags(cypherCmd, &cypherBH)
	rootCmd.AddCommand(cypherCmd)
}

var cypherCmd = &cobra.Command{
	Use:   `cypher <query>`,
	Short: "Run a Cypher query against a BloodHound CE instance",
	Long: `Execute a Cypher query against a BloodHound CE instance and print the raw
JSON response to stdout.

Authentication can use an API token pair or username/password login.

  Flags:
    --url           BloodHound CE base URL         (or BLOODHOUND_URL)
    --token-id      API token ID                   (or BLOODHOUND_TOKEN_ID)
    --token-key     API token key/secret           (or BLOODHOUND_TOKEN_KEY)
    --username      BloodHound CE username         (or BLOODHOUND_USERNAME)
    --password      BloodHound CE password         (or BLOODHOUND_PASSWORD)

  Environment variables are used when flags are not set.

Examples:
  # Using API token
  runZeroHound cypher --url https://bh.example.com \
    --token-id abc123 --token-key secret456 \
    'MATCH (n) RETURN n LIMIT 5'

  # Using username/password
  runZeroHound cypher --url https://bh.example.com \
    --username admin --password secret \
    'MATCH (n:Computer) RETURN n.name LIMIT 10'
`,
	Args: cobra.ExactArgs(1),
	Run:  runCypher,
}

func runCypher(_ *cobra.Command, args []string) {
	query := args[0]

	baseURL, authHeader, err := bhResolveAuth(&cypherBH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Execute the Cypher query.
	rlog("info", "running cypher query against %s", baseURL)
	client := bhBuildHTTPClient(&cypherBH)
	result, err := bhCypherQuery(client, baseURL, authHeader, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cypher query failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}

// bhCypherQuery executes a Cypher query and returns the raw JSON response.
func bhCypherQuery(client *http.Client, baseURL, authHeader, query string) (json.RawMessage, error) {
	reqBody, err := json.Marshal(map[string]string{
		"query": query,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal query body: %w", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/api/v2/graphs/cypher", bytes.NewReader(reqBody)) // #nosec G107
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", ToolName, Version))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cypher request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cypher response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// The BH CE Cypher transpiler returns 404 when a query is valid
		// but produces zero results (e.g. aggregation with WHERE filter).
		// Return an empty data envelope instead of treating as an error.
		return json.RawMessage(`{"data":{"nodes":{},"edges":[],"literals":[]}}`), nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cypher: HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.RawMessage(body), nil
}
