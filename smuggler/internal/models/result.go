package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HTTPResponse represents a raw HTTP response from the server.
type HTTPResponse struct {
	// Raw full response (status line + headers + body)
	Raw string `json:"raw,omitempty"`

	// Parsed status code (e.g., 200)
	StatusCode int `json:"status_code,omitempty"`

	// Response headers map
	Headers map[string]string `json:"headers,omitempty"`

	// Response body
	Body string `json:"body,omitempty"`

	// Time taken to send request and receive full response (milliseconds)
	TimingMS int64 `json:"timing_ms,omitempty"`

	// Whether connection was closed by server
	ConnectionClosed bool `json:"connection_closed,omitempty"`

	// Error during communication (if any). Note: error will be represented
	// as a string when marshaled via ToJSON().
	Error error `json:"-"`

	// ErrorString is populated when serializing to JSON to capture Error text.
	ErrorString string `json:"error,omitempty"`
}

// ScanResult represents the final scan result for a target.
type ScanResult struct {
	Target           string        `json:"target,omitempty"`            // Target host
	Technique        string        `json:"technique,omitempty"`         // e.g., "TE.CL", "CL.TE"
	Suspicious       bool          `json:"suspicious,omitempty"`        // True if potential vulnerability detected
	Reason           string        `json:"reason,omitempty"`            // Explanation of the suspicion
	ConfidenceScore  float64       `json:"confidence_score,omitempty"`  // Confidence level 0.0-1.0 (from detector or AI)
	ResponseTimeDiff int64         `json:"response_time_diff,omitempty"`// Timing difference from baseline (milliseconds)
	BaselineResponse *HTTPResponse `json:"baseline_response,omitempty"` // The baseline response for comparison
	TestResponse     *HTTPResponse `json:"test_response,omitempty"`     // The test response

	// Thread metadata (optional)
	Thread *ThreadInfo `json:"thread,omitempty"`
}

// ThreadInfo holds optional metadata to group related scan results
// (e.g., same logical attack attempt or request thread).
type ThreadInfo struct {
	ID        string    `json:"id,omitempty"`
	ParentID  string    `json:"parent_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// ToJSON returns an indented JSON representation of the ScanResult.
// It will copy error text from HTTPResponse.Error into ErrorString for safe serialization.
func (sr *ScanResult) ToJSON() (string, error) {
	// Ensure any error values are captured as strings for JSON output
	if sr.BaselineResponse != nil && sr.BaselineResponse.Error != nil {
		sr.BaselineResponse.ErrorString = sr.BaselineResponse.Error.Error()
	}
	if sr.TestResponse != nil && sr.TestResponse.Error != nil {
		sr.TestResponse.ErrorString = sr.TestResponse.Error.Error()
	}

	data, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// PrettyString returns a compact, human-readable representation of the ScanResult.
func (sr *ScanResult) PrettyString() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", sr.Target)
	fmt.Fprintf(&b, "Technique: %s\n", sr.Technique)
	fmt.Fprintf(&b, "Suspicious: %t (confidence %.2f)\n", sr.Suspicious, sr.ConfidenceScore)
	if sr.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", sr.Reason)
	}
	if sr.Thread != nil {
		fmt.Fprintf(&b, "Thread: %s", sr.Thread.Name)
		if sr.Thread.ID != "" {
			fmt.Fprintf(&b, " (id=%s)", sr.Thread.ID)
		}
		if !sr.Thread.CreatedAt.IsZero() {
			fmt.Fprintf(&b, " created=%s", sr.Thread.CreatedAt.Format(time.RFC3339))
		}
		fmt.Fprintln(&b, "")
	}

	if sr.BaselineResponse != nil {
		fmt.Fprintf(&b, "Baseline Response: status=%d time=%dms conn_closed=%t\n",
			sr.BaselineResponse.StatusCode, sr.BaselineResponse.TimingMS, sr.BaselineResponse.ConnectionClosed)
	}
	if sr.TestResponse != nil {
		fmt.Fprintf(&b, "Test Response:     status=%d time=%dms conn_closed=%t\n",
			sr.TestResponse.StatusCode, sr.TestResponse.TimingMS, sr.TestResponse.ConnectionClosed)
	}
	if sr.ResponseTimeDiff != 0 {
		fmt.Fprintf(&b, "Response time diff: %dms\n", sr.ResponseTimeDiff)
	}
	return b.String()
}

// Print writes the pretty string to standard output.
func (sr *ScanResult) Print() {
	fmt.Print(sr.PrettyString())
}

// RequestConfig holds options for sending raw requests.
type RequestConfig struct {
	Timeout     time.Duration
	ReadTimeout time.Duration
}

// BaselineComparison represents the differences between a baseline and test response.
type BaselineComparison struct {
	// Baseline response for reference
	Baseline *HTTPResponse

	// Test response being compared
	Test *HTTPResponse

	// Status code changed from baseline
	StatusCodeChanged bool
	OldStatusCode     int
	NewStatusCode     int

	// Response timing difference (milliseconds)
	TimingDiffMS int64

	// Connection behavior changed (was closed, now open, or vice versa)
	ConnectionBehaviorChanged bool
	OldConnectionClosed       bool
	NewConnectionClosed       bool

	// Headers added, removed, or modified
	HeadersAdded    map[string]string
	HeadersRemoved  map[string]string
	HeadersModified map[string]string

	// Body size difference (bytes)
	BodySizeDiff int

	// Body content completely different
	BodyChanged bool

	// Detailed description of what changed
	Changes []string
}
