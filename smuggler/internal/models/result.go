package models

import "time"

// HTTPResponse represents a raw HTTP response from the server.
type HTTPResponse struct {
	// Raw full response (status line + headers + body)
	Raw string

	// Parsed status code (e.g., 200)
	StatusCode int

	// Response headers map
	Headers map[string]string

	// Response body
	Body string

	// Time taken to send request and receive full response (milliseconds)
	TimingMS int64

	// Whether connection was closed by server
	ConnectionClosed bool

	// Error during communication (if any)
	Error error
}

// ScanResult represents the final scan result for a target.
type ScanResult struct {
	Target          string
	Technique       string        // e.g., "TE.CL", "CL.TE"
	Suspicious      bool          // True if potential vulnerability detected
	Reason          string        // Explanation of the suspicion
	ResponseTimeDiff int64         // Timing difference from baseline (milliseconds)
	BaselineResponse *HTTPResponse // The baseline response for comparison
	TestResponse    *HTTPResponse  // The test response
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
