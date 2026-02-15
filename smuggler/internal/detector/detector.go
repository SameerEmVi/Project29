package detector

import (
	"fmt"
	"strings"

	"smuggler/internal/models"
)

// Detector analyzes baseline comparisons to identify HTTP request smuggling vulnerabilities.
type Detector struct {
	confidenceThreshold float64
}

// NewDetector creates a new detector with default settings.
func NewDetector() *Detector {
	return &Detector{
		confidenceThreshold: 0.5,
	}
}

// SetConfidenceThreshold sets the minimum confidence level (0.0-1.0) to report findings.
func (d *Detector) SetConfidenceThreshold(threshold float64) *Detector {
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 1 {
		threshold = 1
	}
	d.confidenceThreshold = threshold
	return d
}

// AnalyzeCLTE analyzes a comparison for CL.TE (Content-Length / Transfer-Encoding) patterns.
func (d *Detector) AnalyzeCLTE(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "CL.TE",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}

	// Signal 1: Status code changed to 400 (Bad Request)
	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.25
		signals = append(signals, "Backend returned 400 (malformed request detection)")
	}

	// Signal 2: Status code changed to 5xx
	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.35
		signals = append(signals, "Backend returned 5xx error (possible parser confusion)")
	}

	// Signal 3: Response timing significantly decreased
	if comparison.TimingDiffMS < -30 {
		confidence += 0.15
		signals = append(signals, fmt.Sprintf("Response %d ms faster (possible early rejection)", -comparison.TimingDiffMS))
	}

	// Signal 4: Connection closed unexpectedly
	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		signals = append(signals, "Server closed connection (possible state confusion)")
	}

	// Signal 5: Body size significantly reduced
	if comparison.BodyChanged && comparison.BodySizeDiff < -200 {
		confidence += 0.15
		signals = append(signals, fmt.Sprintf("Response body %d bytes smaller (possible content absorption)", -comparison.BodySizeDiff))
	}

	// Signal 6: Transfer-Encoding header removed
	if _, exists := comparison.HeadersRemoved["Transfer-Encoding"]; exists {
		confidence += 0.10
		signals = append(signals, "Transfer-Encoding header removed by backend")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	result.Suspicious = confidence >= d.confidenceThreshold
	result.ResponseTimeDiff = comparison.TimingDiffMS

	if result.Suspicious {
		result.Reason = d.buildExplanation("CL.TE", confidence, signals)
	} else {
		result.Reason = fmt.Sprintf("Insufficient evidence (confidence: %.1f%% < %.1f%%)", confidence*100, d.confidenceThreshold*100)
	}

	return result
}

// AnalyzeTECL analyzes a comparison for TE.CL (Transfer-Encoding / Content-Length) patterns.
func (d *Detector) AnalyzeTECL(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "TE.CL",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}

	// Signal 1: Status code changed to 400 (Bad Request)
	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.25
		signals = append(signals, "Backend returned 400 (parsing error)")
	}

	// Signal 2: Status code changed to 5xx
	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.35
		signals = append(signals, "Backend returned 5xx error (server confusion)")
	}

	// Signal 3: Response timing significantly increased
	if comparison.TimingDiffMS > 1000 {
		confidence += 0.25
		signals = append(signals, fmt.Sprintf("Response %d ms slower (possible chunk reassembly delay)", comparison.TimingDiffMS))
	}

	// Signal 4: Connection closed unexpectedly
	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		signals = append(signals, "Server closed connection (chunked parsing failure)")
	}

	// Signal 5: Body size changed significantly
	if comparison.BodyChanged {
		confidence += 0.10
		signals = append(signals, fmt.Sprintf("Response body changed by %d bytes", comparison.BodySizeDiff))
	}

	// Signal 6: Content-Length header added
	if _, exists := comparison.HeadersAdded["Content-Length"]; exists {
		confidence += 0.10
		signals = append(signals, "Content-Length header added by backend")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	result.Suspicious = confidence >= d.confidenceThreshold
	result.ResponseTimeDiff = comparison.TimingDiffMS

	if result.Suspicious {
		result.Reason = d.buildExplanation("TE.CL", confidence, signals)
	} else {
		result.Reason = fmt.Sprintf("Insufficient evidence (confidence: %.1f%% < %.1f%%)", confidence*100, d.confidenceThreshold*100)
	}

	return result
}

// AnalyzeMixedTE analyzes for mixed Transfer-Encoding header exploitation.
func (d *Detector) AnalyzeMixedTE(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "Mixed-TE",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}

	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.30
		signals = append(signals, "Backend rejected mixed TE header")
	}

	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.40
		signals = append(signals, "Server error from TE header ambiguity")
	}

	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		signals = append(signals, "Connection reset (TE parser confusion)")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	result.Suspicious = confidence >= d.confidenceThreshold
	result.ResponseTimeDiff = comparison.TimingDiffMS

	if result.Suspicious {
		result.Reason = d.buildExplanation("Mixed-TE", confidence, signals)
	} else {
		result.Reason = fmt.Sprintf("Insufficient evidence (confidence: %.1f%% < %.1f%%)", confidence*100, d.confidenceThreshold*100)
	}

	return result
}

// buildExplanation creates a detailed explanation of the detection.
func (d *Detector) buildExplanation(technique string, confidence float64, signals []string) string {
	var explanation strings.Builder

	explanation.WriteString(fmt.Sprintf("Potential %s vulnerability detected (confidence: %.1f%%)\n", technique, confidence*100))
	explanation.WriteString("Detection signals:\n")

	for _, signal := range signals {
		explanation.WriteString(fmt.Sprintf("  - %s\n", signal))
	}

	switch technique {
	case "CL.TE":
		explanation.WriteString("\nTechnique: Proxy trusts Content-Length, backend trusts Transfer-Encoding.\n")
		explanation.WriteString("The server may have desynchronized request boundaries, allowing request smuggling.")
	case "TE.CL":
		explanation.WriteString("\nTechnique: Proxy trusts Transfer-Encoding, backend trusts Content-Length.\n")
		explanation.WriteString("The server may have desynchronized request boundaries, allowing request smuggling.")
	case "Mixed-TE":
		explanation.WriteString("\nTechnique: Multiple Transfer-Encoding headers with different handling.\n")
		explanation.WriteString("The server may interpret TE headers ambiguously, causing parser desynchronization.")
	}

	return explanation.String()
}

// DetectionReport summarizes results from multiple detection attempts.
type DetectionReport struct {
	Target              string
	TotalTests          int
	Vulnerable          int
	Suspicious          []*models.ScanResult
	NonSuspicious       []*models.ScanResult
	HighestConfidence   float64
	MostLikelyTechnique string
}

// GenerateReport creates a report from multiple scan results.
func (d *Detector) GenerateReport(target string, results ...*models.ScanResult) *DetectionReport {
	report := &DetectionReport{
		Target:        target,
		TotalTests:    len(results),
		Suspicious:    make([]*models.ScanResult, 0),
		NonSuspicious: make([]*models.ScanResult, 0),
	}

	for _, result := range results {
		if result.Suspicious {
			report.Vulnerable++
			report.Suspicious = append(report.Suspicious, result)
		} else {
			report.NonSuspicious = append(report.NonSuspicious, result)
		}
	}

	if report.Vulnerable > 0 {
		report.MostLikelyTechnique = report.Suspicious[0].Technique
	}

	return report
}

// String returns a formatted detection report.
func (r *DetectionReport) String() string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("=== DETECTION REPORT ===\n"))
	output.WriteString(fmt.Sprintf("Target: %s\n", r.Target))
	output.WriteString(fmt.Sprintf("Tests conducted: %d\n", r.TotalTests))
	output.WriteString(fmt.Sprintf("Vulnerable techniques: %d\n\n", r.Vulnerable))

	if r.Vulnerable > 0 {
		output.WriteString("VULNERABLE FINDINGS:\n")
		for i, result := range r.Suspicious {
			output.WriteString(fmt.Sprintf("\n%d. %s\n", i+1, result.Technique))
			output.WriteString(result.Reason)
			output.WriteString("\n")
		}
	} else {
		output.WriteString("No vulnerabilities detected.\n")
	}

	return output.String()
}
