package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var uploadBH = BHSettings{}
var uploadWait bool
var uploadWaitTimeout int
var uploadWaitInterval int

func init() {
	addBHFlags(uploadCmd, &uploadBH)
	uploadCmd.Flags().BoolVar(&uploadWait, "wait", false, "Wait for all ingest jobs to complete")
	uploadCmd.Flags().IntVar(&uploadWaitTimeout, "wait-timeout", 300, "Maximum seconds to wait for ingest completion")
	uploadCmd.Flags().IntVar(&uploadWaitInterval, "wait-interval", 5, "Seconds between status checks")
	rootCmd.AddCommand(uploadCmd)
}

var uploadCmd = &cobra.Command{
	Use:   "upload [graph.json]",
	Short: "Upload an OpenGraph JSON file to BloodHound CE and/or wait for ingest",
	Long: `Upload a previously generated OpenGraph JSON file to a BloodHound CE instance,
and optionally wait for all ingest jobs to finish processing.

If a file argument is given, it is uploaded via the file-upload API.
If --wait is specified, the command polls until all upload jobs reach a
terminal state (complete, failed, canceled, timed-out) and the datapipe
is idle. When both a file and --wait are given, the upload runs first,
then the wait begins.

If no file argument is given, --wait is required and the command only
waits for existing ingest jobs to finish.

  Flags:
    --url             BloodHound CE base URL         (or BLOODHOUND_URL)
    --token-id        API token ID                   (or BLOODHOUND_TOKEN_ID)
    --token-key       API token key/secret           (or BLOODHOUND_TOKEN_KEY)
    --username        BloodHound CE username         (or BLOODHOUND_USERNAME)
    --password        BloodHound CE password         (or BLOODHOUND_PASSWORD)
    --wait            Wait for all ingest jobs to complete
    --wait-timeout    Maximum seconds to wait (default 300)
    --wait-interval   Seconds between status checks (default 5)

Examples:
  # Upload and wait for ingest
  runZeroHound upload --wait graph.json

  # Just wait for pending jobs to finish
  runZeroHound upload --wait

  # Upload without waiting
  runZeroHound upload graph.json
`,
	Args: cobra.MaximumNArgs(1),
	Run:  runUpload,
}

func runUpload(_ *cobra.Command, args []string) {
	if len(args) == 0 && !uploadWait {
		fmt.Fprintf(os.Stderr, "error: provide a file to upload or use --wait to monitor ingest jobs\n")
		os.Exit(1)
	}

	baseURL, authHeader, err := bhResolveAuth(&uploadBH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Upload a file if one was provided.
	if len(args) > 0 {
		inputPath := args[0]

		rlog("info", "reading %s", inputPath)
		data, err := os.ReadFile(inputPath) // #nosec G304
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", inputPath, err)
			os.Exit(1)
		}

		if !json.Valid(data) {
			fmt.Fprintf(os.Stderr, "error: %s is not valid JSON\n", inputPath)
			os.Exit(1)
		}

		rlog("info", "uploading %d bytes to %s", len(data), baseURL)

		if err := uploadToBloodHound(baseURL, authHeader, data); err != nil {
			fmt.Fprintf(os.Stderr, "error: upload failed: %v\n", err)
			os.Exit(1)
		}

		rlog("info", "upload complete")
	}

	// Wait for ingest if requested.
	if uploadWait {
		if err := waitForIngest(baseURL, authHeader); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

// uploadToBloodHound performs the graph upload to BloodHound CE.
//
// BloodHound CE exposes two ingest flows:
//  1. Create an upload job:   POST /api/v2/file-upload/start
//  2. Send file data:         POST /api/v2/file-upload/{id}
//  3. Mark job complete:      POST /api/v2/file-upload/{id}/end
func uploadToBloodHound(baseURL, authHeader string, data []byte) error {
	client := bhBuildHTTPClient(&uploadBH)

	// Step 1: Start the upload job.
	startResp, err := bhAuthRequest(client, "POST", baseURL+"/api/v2/file-upload/start", authHeader, nil)
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
	uploadReq, err := http.NewRequest("POST", uploadURL, bytes.NewReader(data)) // #nosec G107
	if err != nil {
		return fmt.Errorf("upload data: %w", err)
	}
	uploadReq.Header.Set("Authorization", authHeader)
	uploadReq.Header.Set("Content-Type", "application/json")
	uploadReq.Header.Set("Content-Disposition", `attachment; filename="graph.json"`)
	uploadReq.Header.Set("User-Agent", fmt.Sprintf("%s/%s", ToolName, Version))

	uploadResp, err := client.Do(uploadReq)
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
	endResp, err := bhAuthRequest(client, "POST", endURL, authHeader, nil)
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

// Job status constants from the BloodHound CE API.
const (
	jobStatusInvalid           = -1
	jobStatusReady             = 0
	jobStatusRunning           = 1
	jobStatusComplete          = 2
	jobStatusCanceled          = 3
	jobStatusTimedOut          = 4
	jobStatusFailed            = 5
	jobStatusIngesting         = 6
	jobStatusAnalyzing         = 7
	jobStatusPartiallyComplete = 8
)

func jobStatusName(s int) string {
	switch s {
	case jobStatusInvalid:
		return "invalid"
	case jobStatusReady:
		return "ready"
	case jobStatusRunning:
		return "running"
	case jobStatusComplete:
		return "complete"
	case jobStatusCanceled:
		return "canceled"
	case jobStatusTimedOut:
		return "timed-out"
	case jobStatusFailed:
		return "failed"
	case jobStatusIngesting:
		return "ingesting"
	case jobStatusAnalyzing:
		return "analyzing"
	case jobStatusPartiallyComplete:
		return "partially-complete"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func isTerminalJobStatus(s int) bool {
	switch s {
	case jobStatusComplete, jobStatusCanceled, jobStatusTimedOut,
		jobStatusFailed, jobStatusPartiallyComplete, jobStatusInvalid:
		return true
	}
	return false
}

type fileUploadJob struct {
	ID            int64  `json:"id"`
	Status        int    `json:"status"`
	StatusMessage string `json:"status_message"`
	TotalFiles    int    `json:"total_files"`
	FailedFiles   int    `json:"failed_files"`
}

type datapipeStatus struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// waitForIngest polls BloodHound CE until all upload jobs reach a terminal
// state and the datapipe is idle.
func waitForIngest(baseURL, authHeader string) error {
	client := bhBuildHTTPClient(&uploadBH)
	timeout := time.Duration(uploadWaitTimeout) * time.Second
	interval := time.Duration(uploadWaitInterval) * time.Second
	deadline := time.Now().Add(timeout)

	rlog("info", "waiting for ingest to complete (timeout %s, interval %s)", timeout, interval)

	for {
		// Check all upload jobs.
		allDone, summary, err := checkUploadJobs(client, baseURL, authHeader)
		if err != nil {
			return fmt.Errorf("check upload jobs: %w", err)
		}

		// Check datapipe status.
		dpStatus, err := checkDatapipe(client, baseURL, authHeader)
		if err != nil {
			return fmt.Errorf("check datapipe: %w", err)
		}

		rlog("info", "jobs: %s | datapipe: %s", summary, dpStatus)

		if allDone && dpStatus == "idle" {
			rlog("info", "all ingest jobs complete, datapipe idle")
			// Print final status as JSON to stdout.
			printIngestStatus(client, baseURL, authHeader)
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for ingest (jobs: %s, datapipe: %s)", timeout, summary, dpStatus)
		}

		time.Sleep(interval)
	}
}

func checkUploadJobs(client *http.Client, baseURL, authHeader string) (allTerminal bool, summary string, err error) {
	resp, err := bhAuthRequest(client, "GET", baseURL+"/api/v2/file-upload", authHeader, nil)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []fileUploadJob `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, "", fmt.Errorf("parse response: %w", err)
	}

	if len(result.Data) == 0 {
		return true, "no jobs", nil
	}

	counts := make(map[string]int)
	pending := 0
	failed := 0
	for _, j := range result.Data {
		name := jobStatusName(j.Status)
		counts[name]++
		if !isTerminalJobStatus(j.Status) {
			pending++
		}
		if j.Status == jobStatusFailed {
			failed++
		}
	}

	parts := fmt.Sprintf("%d total", len(result.Data))
	if pending > 0 {
		parts += fmt.Sprintf(", %d pending", pending)
	}
	if failed > 0 {
		parts += fmt.Sprintf(", %d failed", failed)
	}

	return pending == 0, parts, nil
}

func checkDatapipe(client *http.Client, baseURL, authHeader string) (string, error) {
	resp, err := bhAuthRequest(client, "GET", baseURL+"/api/v2/datapipe/status", authHeader, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var dp datapipeStatus
	if err := json.Unmarshal(body, &dp); err != nil {
		return "", fmt.Errorf("parse datapipe: %w", err)
	}

	return dp.Data.Status, nil
}

func printIngestStatus(client *http.Client, baseURL, authHeader string) {
	resp, err := bhAuthRequest(client, "GET", baseURL+"/api/v2/file-upload", authHeader, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var result struct {
		Data []fileUploadJob `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

// resolveStr returns the flag value if set, otherwise the environment variable.
func resolveStr(flagVal, envKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envKey)
}
