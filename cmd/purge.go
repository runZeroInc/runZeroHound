package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var purgeBH = BHSettings{}

func init() {
	addBHFlags(purgeCmd, &purgeBH)
	rootCmd.AddCommand(purgeCmd)
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Delete all collected data from BloodHound CE",
	Long: `Trigger a full database deletion of collected graph data, file ingest
history, and data quality history in a BloodHound CE instance.

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
  runZeroHound purge --url https://bh.example.com \
    --token-id abc123 --token-key secret456

  # Using username/password
  runZeroHound purge --url https://bh.example.com \
    --username admin --password secret
`,
	Args: cobra.NoArgs,
	Run:  runPurge,
}

func runPurge(_ *cobra.Command, _ []string) {
	baseURL, authHeader, err := bhResolveAuth(&purgeBH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	client := bhBuildHTTPClient(&purgeBH)

	reqBody, err := json.Marshal(map[string]bool{
		"deleteCollectedGraphData": true,
		"deleteFileIngestHistory":  true,
		"deleteDataQualityHistory": true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal request: %v\n", err)
		os.Exit(1)
	}

	rlog("info", "requesting full database purge on %s", baseURL)

	resp, err := bhAuthRequest(client, "POST", baseURL+"/api/v2/clear-database", authHeader, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: purge request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "error: purge: HTTP %d: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	rlog("info", "database purge accepted")
}
