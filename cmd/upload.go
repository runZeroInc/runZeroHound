package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type UploadSettings struct {
	URL      string
	TokenID  string
	TokenKey string
	Insecure bool
	Timeout  int
}

var uploadSettings = UploadSettings{}

func init() {
	uploadCmd.Flags().StringVarP(&uploadSettings.URL, "url", "u", "", "BloodHound CE API URL (e.g. https://bloodhound.example.com)")
	uploadCmd.Flags().StringVar(&uploadSettings.TokenID, "token-id", "", "BloodHound CE API token ID (or set BLOODHOUND_TOKEN_ID)")
	uploadCmd.Flags().StringVar(&uploadSettings.TokenKey, "token-key", "", "BloodHound CE API token key (or set BLOODHOUND_TOKEN_KEY)")
	uploadCmd.Flags().BoolVar(&uploadSettings.Insecure, "insecure", false, "Skip TLS certificate verification")
	uploadCmd.Flags().IntVar(&uploadSettings.Timeout, "timeout", 300, "HTTP request timeout in seconds")
	rootCmd.AddCommand(uploadCmd)
}

var uploadCmd = &cobra.Command{
	Use:   "upload <graph.json>",
	Short: "Upload an OpenGraph JSON file to BloodHound CE",
	Long: `Upload a previously generated OpenGraph JSON file to a BloodHound CE instance.

The command reads the JSON file and sends it to the BloodHound CE ingest API
using the file-upload endpoint.

Authentication requires an API token pair. Provide them via flags or
environment variables:

  Flags:
    --url           BloodHound CE base URL         (or BLOODHOUND_URL)
    --token-id      API token ID                   (or BLOODHOUND_TOKEN_ID)
    --token-key     API token key/secret           (or BLOODHOUND_TOKEN_KEY)

  Environment variables take precedence when flags are not set.

Examples:
  # Using flags
  runZeroHound upload --url https://bh.example.com \
    --token-id abc123 --token-key secret456 graph.json

  # Using environment variables
  export BLOODHOUND_URL=https://bh.example.com
  export BLOODHOUND_TOKEN_ID=abc123
  export BLOODHOUND_TOKEN_KEY=secret456
  runZeroHound upload graph.json
`,
	Args: cobra.ExactArgs(1),
	Run:  runUpload,
}

func runUpload(_ *cobra.Command, args []string) {
	inputPath := args[0]

	// Resolve credentials: flags override env vars.
	url := resolveStr(uploadSettings.URL, "BLOODHOUND_URL")
	tokenID := resolveStr(uploadSettings.TokenID, "BLOODHOUND_TOKEN_ID")
	tokenKey := resolveStr(uploadSettings.TokenKey, "BLOODHOUND_TOKEN_KEY")

	if url == "" {
		fmt.Fprintln(os.Stderr, "error: BloodHound CE URL is required (--url or BLOODHOUND_URL)")
		os.Exit(1)
	}
	if tokenID == "" || tokenKey == "" {
		fmt.Fprintln(os.Stderr, "error: API token ID and key are required (--token-id/--token-key or BLOODHOUND_TOKEN_ID/BLOODHOUND_TOKEN_KEY)")
		os.Exit(1)
	}

	url = strings.TrimRight(url, "/")

	rlog("info", "reading %s", inputPath)
	data, err := os.ReadFile(inputPath) // #nosec G304
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	// Validate that the file is valid JSON.
	if !json.Valid(data) {
		fmt.Fprintf(os.Stderr, "error: %s is not valid JSON\n", inputPath)
		os.Exit(1)
	}

	rlog("info", "uploading %d bytes to %s", len(data), url)

	if err := uploadToBloodHound(url, tokenID, tokenKey, data); err != nil {
		fmt.Fprintf(os.Stderr, "error: upload failed: %v\n", err)
		os.Exit(1)
	}

	rlog("info", "upload complete")
}

// uploadToBloodHound performs the graph upload to BloodHound CE.
//
// BloodHound CE exposes two ingest flows:
//  1. Create an upload job:   POST /api/v2/file-upload/start
//  2. Send file data:         POST /api/v2/file-upload/{id}
//  3. Mark job complete:      POST /api/v2/file-upload/{id}/end
func uploadToBloodHound(baseURL, tokenID, tokenKey string, data []byte) error {
	client := buildHTTPClient()

	// Step 1: Start the upload job.
	startResp, err := bhRequest(client, "POST", baseURL+"/api/v2/file-upload/start", tokenID, tokenKey, nil)
	if err != nil {
		return fmt.Errorf("start upload: %w", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusCreated && startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		return fmt.Errorf("start upload: HTTP %d: %s", startResp.StatusCode, string(body))
	}

	var startResult struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startResult); err != nil {
		return fmt.Errorf("parse start response: %w", err)
	}
	jobID := startResult.Data.ID
	if jobID == 0 {
		return fmt.Errorf("server returned job ID 0 — check API version compatibility")
	}

	rlog("info", "upload job started: id=%d", jobID)

	// Step 2: Upload the file data.
	uploadURL := fmt.Sprintf("%s/api/v2/file-upload/%d", baseURL, jobID)
	uploadResp, err := bhRequest(client, "POST", uploadURL, tokenID, tokenKey, data)
	if err != nil {
		return fmt.Errorf("upload data: %w", err)
	}
	defer uploadResp.Body.Close()

	if uploadResp.StatusCode != http.StatusOK && uploadResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(uploadResp.Body)
		return fmt.Errorf("upload data: HTTP %d: %s", uploadResp.StatusCode, string(body))
	}

	rlog("info", "file data uploaded successfully")

	// Step 3: End the upload job.
	endURL := fmt.Sprintf("%s/api/v2/file-upload/%d/end", baseURL, jobID)
	endResp, err := bhRequest(client, "POST", endURL, tokenID, tokenKey, nil)
	if err != nil {
		return fmt.Errorf("end upload: %w", err)
	}
	defer endResp.Body.Close()

	if endResp.StatusCode != http.StatusOK && endResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(endResp.Body)
		return fmt.Errorf("end upload: HTTP %d: %s", endResp.StatusCode, string(body))
	}

	rlog("info", "upload job %d finalized", jobID)
	return nil
}

// bhRequest performs an authenticated HTTP request to the BloodHound CE API.
func bhRequest(client *http.Client, method, url, tokenID, tokenKey string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader) // #nosec G107
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", tokenID, tokenKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", ToolName, Version))

	return client.Do(req)
}

// buildHTTPClient creates an HTTP client with optional TLS skip-verify.
func buildHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if uploadSettings.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(uploadSettings.Timeout) * time.Second,
	}
}

// resolveStr returns the flag value if set, otherwise the environment variable.
func resolveStr(flagVal, envKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envKey)
}
