package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------- HTTP RESPONSE ----------

// HTTPResponse represents a raw HTTP response from the server.
type HTTPResponse struct {
	Raw string `json:"raw,omitempty"`

	StatusCode int `json:"status_code,omitempty"`

	Headers map[string]string `json:"headers,omitempty"`

	Body string `json:"body,omitempty"`

	TimingMS int64 `json:"timing_ms,omitempty"`

	ConnectionClosed bool `json:"connection_closed,omitempty"`

	Error error `json:"-"`

	ErrorString string `json:"error,omitempty"`
}

// ---------- SCAN RESULT ----------

// ScanResult represents the final scan result.
type ScanResult struct {
	Target     string `json:"target,omitempty"`
	Technique  string `json:"technique,omitempty"`
	Suspicious bool   `json:"suspicious,omitempty"`

	Reason string `json:"reason,omitempty"`

	// NEW: primary confidence (used by detector)
	Confidence float64 `json:"confidence,omitempty"`

	// Backward compatibility field
	ConfidenceScore float64 `json:"confidence_score,omitempty"`

	ResponseTimeDiff int64 `json:"response_time_diff,omitempty"`

	BaselineResponse *HTTPResponse `json:"baseline_response,omitempty"`
	TestResponse     *HTTPResponse `json:"test_response,omitempty"`

	Thread *ThreadInfo `json:"thread,omitempty"`
}

// GetConfidence returns whichever confidence value exists.
func (sr *ScanResult) GetConfidence() float64 {
	if sr.Confidence > 0 {
		return sr.Confidence
	}
	return sr.ConfidenceScore
}

// ---------- THREAD ----------

type ThreadInfo struct {
	ID        string    `json:"id,omitempty"`
	ParentID  string    `json:"parent_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// ---------- SERIALIZATION ----------

// ToJSON returns formatted JSON output.
func (sr *ScanResult) ToJSON() (string, error) {

	// ensure compatibility
	if sr.Confidence == 0 && sr.ConfidenceScore > 0 {
		sr.Confidence = sr.ConfidenceScore
	}
	if sr.ConfidenceScore == 0 && sr.Confidence > 0 {
		sr.ConfidenceScore = sr.Confidence
	}

	if sr.BaselineResponse != nil &&
		sr.BaselineResponse.Error != nil {
		sr.BaselineResponse.ErrorString =
			sr.BaselineResponse.Error.Error()
	}

	if sr.TestResponse != nil &&
		sr.TestResponse.Error != nil {
		sr.TestResponse.ErrorString =
			sr.TestResponse.Error.Error()
	}

	data, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ---------- PRETTY OUTPUT ----------

func (sr *ScanResult) PrettyString() string {

	var b strings.Builder
	conf := sr.GetConfidence()

	fmt.Fprintf(&b, "Target: %s\n", sr.Target)
	fmt.Fprintf(&b, "Technique: %s\n", sr.Technique)
	fmt.Fprintf(&b, "Suspicious: %t (confidence %.2f)\n",
		sr.Suspicious, conf)

	if sr.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", sr.Reason)
	}

	if sr.Thread != nil {
		fmt.Fprintf(&b, "Thread: %s", sr.Thread.Name)

		if sr.Thread.ID != "" {
			fmt.Fprintf(&b, " (id=%s)", sr.Thread.ID)
		}

		if !sr.Thread.CreatedAt.IsZero() {
			fmt.Fprintf(
				&b,
				" created=%s",
				sr.Thread.CreatedAt.Format(time.RFC3339),
			)
		}

		fmt.Fprintln(&b)
	}

	if sr.BaselineResponse != nil {
		fmt.Fprintf(
			&b,
			"Baseline Response: status=%d time=%dms conn_closed=%t\n",
			sr.BaselineResponse.StatusCode,
			sr.BaselineResponse.TimingMS,
			sr.BaselineResponse.ConnectionClosed,
		)
	}

	if sr.TestResponse != nil {
		fmt.Fprintf(
			&b,
			"Test Response:     status=%d time=%dms conn_closed=%t\n",
			sr.TestResponse.StatusCode,
			sr.TestResponse.TimingMS,
			sr.TestResponse.ConnectionClosed,
		)
	}

	if sr.ResponseTimeDiff != 0 {
		fmt.Fprintf(&b,
			"Response time diff: %dms\n",
			sr.ResponseTimeDiff)
	}

	return b.String()
}

func (sr *ScanResult) Print() {
	fmt.Print(sr.PrettyString())
}

// ---------- REQUEST CONFIG ----------

type RequestConfig struct {
	Timeout     time.Duration
	ReadTimeout time.Duration
}

// ---------- BASELINE COMPARISON ----------

type BaselineComparison struct {
	Baseline *HTTPResponse
	Test     *HTTPResponse

	StatusCodeChanged bool
	OldStatusCode     int
	NewStatusCode     int

	TimingDiffMS int64

	ConnectionBehaviorChanged bool
	OldConnectionClosed       bool
	NewConnectionClosed       bool

	HeadersAdded    map[string]string
	HeadersRemoved  map[string]string
	HeadersModified map[string]string

	BodySizeDiff int
	BodyChanged  bool

	Changes []string
}
