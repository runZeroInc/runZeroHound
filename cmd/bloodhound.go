package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// BHSettings holds shared BloodHound CE connection and authentication settings.
type BHSettings struct {
	URL      string
	TokenID  string
	TokenKey string
	Username string
	Password string
	Insecure bool
	Timeout  int
}

// addBHFlags registers the common BloodHound CE flags on a cobra command.
func addBHFlags(cmd *cobra.Command, s *BHSettings) {
	cmd.Flags().StringVarP(&s.URL, "url", "u", "", "BloodHound CE base URL (or BLOODHOUND_URL)")
	cmd.Flags().StringVar(&s.TokenID, "token-id", "", "API token ID (or BLOODHOUND_TOKEN_ID)")
	cmd.Flags().StringVar(&s.TokenKey, "token-key", "", "API token key/secret (or BLOODHOUND_TOKEN_KEY)")
	cmd.Flags().StringVar(&s.Username, "username", "", "BloodHound CE username (or BLOODHOUND_USERNAME)")
	cmd.Flags().StringVar(&s.Password, "password", "", "BloodHound CE password (or BLOODHOUND_PASSWORD)")
	cmd.Flags().BoolVar(&s.Insecure, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().IntVar(&s.Timeout, "timeout", 300, "HTTP request timeout in seconds")
}

// bhResolveAuth resolves the base URL and an Authorization header value.
// Token-based auth (--token-id/--token-key) takes precedence over
// username/password login when both are provided.
func bhResolveAuth(s *BHSettings) (baseURL, authHeader string, err error) {
	baseURL = strings.TrimRight(resolveStr(s.URL, "BLOODHOUND_URL"), "/")
	if baseURL == "" {
		return "", "", fmt.Errorf("BloodHound CE URL is required (--url or BLOODHOUND_URL)")
	}

	tokenID := resolveStr(s.TokenID, "BLOODHOUND_TOKEN_ID")
	tokenKey := resolveStr(s.TokenKey, "BLOODHOUND_TOKEN_KEY")
	username := resolveStr(s.Username, "BLOODHOUND_USERNAME")
	password := resolveStr(s.Password, "BLOODHOUND_PASSWORD")

	switch {
	case tokenID != "" && tokenKey != "":
		rlog("info", "using API token authentication")
		return baseURL, fmt.Sprintf("Bearer %s %s", tokenID, tokenKey), nil

	case username != "" && password != "":
		rlog("info", "authenticating to %s as %s", baseURL, username)
		client := bhBuildHTTPClient(s)
		token, err := bhLogin(client, baseURL, username, password)
		if err != nil {
			return "", "", fmt.Errorf("login failed: %w", err)
		}
		return baseURL, fmt.Sprintf("Bearer %s", token), nil

	default:
		return "", "", fmt.Errorf("authentication required: provide --token-id/--token-key or --username/--password (or equivalent env vars)")
	}
}

// bhLogin authenticates with BloodHound CE and returns a JWT session token.
func bhLogin(client *http.Client, baseURL, username, password string) (string, error) {
	loginBody, err := json.Marshal(map[string]string{
		"login_method": "secret",
		"username":     username,
		"secret":       password,
	})
	if err != nil {
		return "", fmt.Errorf("marshal login body: %w", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/api/v2/login", bytes.NewReader(loginBody)) // #nosec G107
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", ToolName, Version))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var loginResp struct {
		Data struct {
			SessionToken string `json:"session_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("parse login response: %w", err)
	}

	if loginResp.Data.SessionToken == "" {
		return "", fmt.Errorf("login succeeded but no session token returned")
	}

	return loginResp.Data.SessionToken, nil
}

// bhAuthRequest performs an authenticated HTTP request to the BloodHound CE API.
func bhAuthRequest(client *http.Client, method, url, authHeader string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader) // #nosec G107
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", ToolName, Version))

	return client.Do(req)
}

// bhBuildHTTPClient creates an HTTP client with optional TLS skip-verify.
func bhBuildHTTPClient(s *BHSettings) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if s.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(s.Timeout) * time.Second,
	}
}
