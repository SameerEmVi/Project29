package baseline

import (
	"fmt"
	"sort"
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

func NewManager(s *sender.RawSender, host string, port int) *Manager {
	return &Manager{
		sender: s,
		host:   host,
		port:   port,
	}
}

// ---------- Baseline ----------

func (m *Manager) CaptureBaseline() (*models.HTTPResponse, error) {

	gen := payload.NewGenerator(m.host, m.port)
	gen.AddHeader("Connection", "close")

	payloadStr := gen.GenerateBaseline()
	target := fmt.Sprintf("%s:%d", m.host, m.port)

	resp, err := m.sender.SendRequest(target, payloadStr)
	if err != nil {
		return resp, fmt.Errorf("failed to capture baseline: %w", err)
	}

	return resp, nil
}

// ---------- Comparison ----------

func (m *Manager) CompareResponses(
	baseline, test *models.HTTPResponse,
) *models.BaselineComparison {

	comparison := &models.BaselineComparison{
		Baseline:        baseline,
		Test:            test,
		HeadersAdded:    make(map[string]string),
		HeadersRemoved:  make(map[string]string),
		HeadersModified: make(map[string]string),
		Changes:         make([]string, 0),
	}

	if baseline == nil || test == nil {
		comparison.Changes = append(comparison.Changes, "invalid baseline/test response")
		return comparison
	}

	// ---------- Status ----------
	if baseline.StatusCode != test.StatusCode {
		comparison.StatusCodeChanged = true
		comparison.OldStatusCode = baseline.StatusCode
		comparison.NewStatusCode = test.StatusCode

		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf("Status code changed: %d -> %d",
				baseline.StatusCode, test.StatusCode),
		)
	}

	// ---------- Timing ----------
	timingDiff := test.TimingMS - baseline.TimingMS
	comparison.TimingDiffMS = timingDiff

	if baseline.TimingMS > 0 &&
		(timingDiff > 100 || timingDiff < -100) {

		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf("Timing changed: %d ms -> %d ms (diff: %d ms)",
				baseline.TimingMS, test.TimingMS, timingDiff),
		)
	}

	// ---------- Connection ----------
	if baseline.ConnectionClosed != test.ConnectionClosed {
		comparison.ConnectionBehaviorChanged = true
		comparison.OldConnectionClosed = baseline.ConnectionClosed
		comparison.NewConnectionClosed = test.ConnectionClosed

		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf(
				"Connection behavior changed: closed=%v -> closed=%v",
				baseline.ConnectionClosed,
				test.ConnectionClosed,
			),
		)
	}

	// ---------- Headers ----------
	analyzeHeaderChanges(baseline, test, comparison)

	// ---------- Body ----------
	if baseline.Body != test.Body {
		comparison.BodyChanged = true
		comparison.BodySizeDiff =
			len(test.Body) - len(baseline.Body)

		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf(
				"Body changed: %d bytes -> %d bytes (diff: %d)",
				len(baseline.Body),
				len(test.Body),
				comparison.BodySizeDiff,
			),
		)
	}

	// ---------- Errors ----------
	if (baseline.Error != nil) != (test.Error != nil) {
		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf(
				"Error state changed: %v -> %v",
				baseline.Error != nil,
				test.Error != nil,
			),
		)
	}

	return comparison
}

// ---------- Header Analysis ----------

func normalizeHeaderMap(src map[string]string) map[string]string {
	out := make(map[string]string)

	for k, v := range src {
		out[strings.ToLower(k)] = v
	}

	return out
}

func analyzeHeaderChanges(
	baseline, test *models.HTTPResponse,
	comparison *models.BaselineComparison,
) {

	baseHeaders := normalizeHeaderMap(baseline.Headers)
	testHeaders := normalizeHeaderMap(test.Headers)

	for key, baseVal := range baseHeaders {

		testVal, exists := testHeaders[key]

		if !exists {
			comparison.HeadersRemoved[key] = baseVal
		} else if baseVal != testVal {
			comparison.HeadersModified[key] = testVal
		}
	}

	for key, testVal := range testHeaders {
		if _, exists := baseHeaders[key]; !exists {
			comparison.HeadersAdded[key] = testVal
		}
	}

	if len(comparison.HeadersAdded) > 0 {
		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf("Headers added: %v",
				getHeaderKeys(comparison.HeadersAdded)),
		)
	}

	if len(comparison.HeadersRemoved) > 0 {
		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf("Headers removed: %v",
				getHeaderKeys(comparison.HeadersRemoved)),
		)
	}

	if len(comparison.HeadersModified) > 0 {
		comparison.Changes = append(
			comparison.Changes,
			fmt.Sprintf("Headers modified: %v",
				getHeaderKeys(comparison.HeadersModified)),
		)
	}
}

func getHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------- Heuristics ----------

func (m *Manager) IsSuspicious(comparison *models.BaselineComparison) bool {

	if comparison.StatusCodeChanged &&
		comparison.NewStatusCode >= 500 &&
		comparison.NewStatusCode < 600 &&
		comparison.OldStatusCode != 500 {
		return true
	}

	if comparison.ConnectionBehaviorChanged &&
		comparison.NewConnectionClosed {
		return true
	}

	if comparison.BodyChanged &&
		comparison.BodySizeDiff != 0 {
		return true
	}

	if comparison.TimingDiffMS < -50 {
		return true
	}

	return false
}

// ---------- Summary ----------

func (m *Manager) SummaryString(
	comparison *models.BaselineComparison,
) string {

	if len(comparison.Changes) == 0 {
		return "No differences detected"
	}

	var out strings.Builder

	out.WriteString(
		fmt.Sprintf("Found %d differences:\n",
			len(comparison.Changes)),
	)

	for i, c := range comparison.Changes {
		out.WriteString(fmt.Sprintf("  %d. %s\n", i+1, c))
	}

	return out.String()
}
