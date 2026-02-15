package baseline

import (
	"fmt"
	"strings"

	"smuggler/internal/models"
	"smuggler/internal/payload"
	"smuggler/internal/sender"
)

// Manager handles baseline requests and comparisons.
type Manager struct {
	sender *sender.RawSender
	host   string
	port   int
}

// NewManager creates a new baseline manager.
func NewManager(s *sender.RawSender, host string, port int) *Manager {
	return &Manager{
		sender: s,
		host:   host,
		port:   port,
	}
}

// CaptureBaseline sends a normal request to establish baseline behavior.
func (m *Manager) CaptureBaseline() (*models.HTTPResponse, error) {
	gen := payload.NewGenerator(m.host, m.port)
	gen.AddHeader("Connection", "close")

	baselinePayload := gen.GenerateBaseline()

	targetAddr := fmt.Sprintf("%s:%d", m.host, m.port)
	response, err := m.sender.SendRequest(targetAddr, baselinePayload)

	if err != nil {
		return response, fmt.Errorf("failed to capture baseline: %w", err)
	}

	return response, nil
}

// CompareResponses compares a test response against a baseline.
func (m *Manager) CompareResponses(baseline, test *models.HTTPResponse) *models.BaselineComparison {
	comparison := &models.BaselineComparison{
		Baseline:        baseline,
		Test:            test,
		HeadersAdded:    make(map[string]string),
		HeadersRemoved:  make(map[string]string),
		HeadersModified: make(map[string]string),
		Changes:         make([]string, 0),
	}

	// Check status code changes
	if baseline.StatusCode != test.StatusCode {
		comparison.StatusCodeChanged = true
		comparison.OldStatusCode = baseline.StatusCode
		comparison.NewStatusCode = test.StatusCode
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Status code changed: %d -> %d", baseline.StatusCode, test.StatusCode))
	}

	// Check timing differences
	timingDiff := test.TimingMS - baseline.TimingMS
	comparison.TimingDiffMS = timingDiff

	if timingDiff > 100 || timingDiff < -100 {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Timing changed: %d ms -> %d ms (diff: %d ms)", baseline.TimingMS, test.TimingMS, timingDiff))
	}

	// Check connection behavior
	if baseline.ConnectionClosed != test.ConnectionClosed {
		comparison.ConnectionBehaviorChanged = true
		comparison.OldConnectionClosed = baseline.ConnectionClosed
		comparison.NewConnectionClosed = test.ConnectionClosed
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Connection behavior changed: closed=%v -> closed=%v", baseline.ConnectionClosed, test.ConnectionClosed))
	}

	// Analyze header changes
	analyzeHeaderChanges(baseline, test, comparison)

	// Check body changes
	if baseline.Body != test.Body {
		comparison.BodyChanged = true
		comparison.BodySizeDiff = len(test.Body) - len(baseline.Body)
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Body changed: %d bytes -> %d bytes (diff: %d)", len(baseline.Body), len(test.Body), comparison.BodySizeDiff))
	}

	// Error state change
	if (baseline.Error != nil) != (test.Error != nil) {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Error state changed: %v -> %v", baseline.Error != nil, test.Error != nil))
	}

	return comparison
}

// analyzeHeaderChanges detects which headers were added, removed, or modified.
func analyzeHeaderChanges(baseline, test *models.HTTPResponse, comparison *models.BaselineComparison) {
	for key, baselineValue := range baseline.Headers {
		testValue, exists := test.Headers[key]
		if !exists {
			comparison.HeadersRemoved[key] = baselineValue
		} else if baselineValue != testValue {
			comparison.HeadersModified[key] = testValue
		}
	}

	for key, testValue := range test.Headers {
		_, exists := baseline.Headers[key]
		if !exists {
			comparison.HeadersAdded[key] = testValue
		}
	}

	if len(comparison.HeadersAdded) > 0 {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Headers added: %v", getHeaderKeys(comparison.HeadersAdded)))
	}
	if len(comparison.HeadersRemoved) > 0 {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Headers removed: %v", getHeaderKeys(comparison.HeadersRemoved)))
	}
	if len(comparison.HeadersModified) > 0 {
		comparison.Changes = append(comparison.Changes,
			fmt.Sprintf("Headers modified: %v", getHeaderKeys(comparison.HeadersModified)))
	}
}

// getHeaderKeys returns a list of header keys from a map.
func getHeaderKeys(headers map[string]string) []string {
	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}
	return keys
}

// IsSuspicious returns true if the comparison shows signs of request smuggling.
func (m *Manager) IsSuspicious(comparison *models.BaselineComparison) bool {
	// Heuristic 1: Status code changed to an error code (5xx)
	if comparison.StatusCodeChanged &&
		comparison.NewStatusCode >= 500 &&
		comparison.NewStatusCode < 600 &&
		comparison.OldStatusCode != 500 {
		return true
	}

	// Heuristic 2: Connection closed unexpectedly
	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		return true
	}

	// Heuristic 3: Significant body content changed
	if comparison.BodyChanged && comparison.BodySizeDiff != 0 {
		return true
	}

	// Heuristic 4: Response became much faster
	if comparison.TimingDiffMS < -50 {
		return true
	}

	return false
}

// SummaryString returns a human-readable summary of the comparison.
func (m *Manager) SummaryString(comparison *models.BaselineComparison) string {
	if len(comparison.Changes) == 0 {
		return "No differences detected"
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Found %d differences:\n", len(comparison.Changes)))
	for i, change := range comparison.Changes {
		summary.WriteString(fmt.Sprintf("  %d. %s\n", i+1, change))
	}

	return summary.String()
}
