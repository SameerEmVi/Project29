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

func NewDetector() *Detector {
	return &Detector{
		confidenceThreshold: 0.5,
	}
}

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

// ---------- Helpers ----------

func headerExistsCaseInsensitive(headers map[string]string, target string) bool {
	for k := range headers {
		if strings.EqualFold(k, target) {
			return true
		}
	}
	return false
}

func finalizeResult(
	d *Detector,
	result *models.ScanResult,
	confidence float64,
	strongSignal bool,
	comparison *models.BaselineComparison,
	technique string,
	signals []string,
) *models.ScanResult {

	if confidence > 1.0 {
		confidence = 1.0
	}

	result.Confidence = confidence
	result.Suspicious = strongSignal && confidence >= d.confidenceThreshold
	result.ResponseTimeDiff = comparison.TimingDiffMS

	if result.Suspicious {
		result.Reason = d.buildExplanation(technique, confidence, signals)
	} else {
		result.Reason = fmt.Sprintf(
			"Insufficient evidence (confidence: %.1f%% < %.1f%%)",
			confidence*100,
			d.confidenceThreshold*100,
		)
	}

	return result
}

// ---------- CL.TE ----------

func (d *Detector) AnalyzeCLTE(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "CL.TE",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}
	strongSignal := false

	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.25
		strongSignal = true
		signals = append(signals, "Backend returned 400 (malformed request detection)")
	}

	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.35
		strongSignal = true
		signals = append(signals, "Backend returned 5xx error (possible parser confusion)")
	}

	if comparison.TimingDiffMS < -30 {
		confidence += 0.15
		signals = append(signals,
			fmt.Sprintf("Response %d ms faster (possible early rejection)", -comparison.TimingDiffMS))
	}

	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		strongSignal = true
		signals = append(signals, "Server closed connection (possible state confusion)")
	}

	if comparison.BodyChanged && comparison.BodySizeDiff < -200 {
		confidence += 0.15
		signals = append(signals,
			fmt.Sprintf("Response body %d bytes smaller (possible content absorption)", -comparison.BodySizeDiff))
	}

	if headerExistsCaseInsensitive(comparison.HeadersRemoved, "Transfer-Encoding") {
		confidence += 0.10
		signals = append(signals, "Transfer-Encoding header removed by backend")
	}

	return finalizeResult(d, result, confidence, strongSignal, comparison, "CL.TE", signals)
}

// ---------- TE.CL ----------

func (d *Detector) AnalyzeTECL(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "TE.CL",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}
	strongSignal := false

	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.25
		strongSignal = true
		signals = append(signals, "Backend returned 400 (parsing error)")
	}

	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.35
		strongSignal = true
		signals = append(signals, "Backend returned 5xx error (server confusion)")
	}

	if comparison.TimingDiffMS > 1000 {
		confidence += 0.25
		signals = append(signals,
			fmt.Sprintf("Response %d ms slower (possible chunk reassembly delay)", comparison.TimingDiffMS))
	}

	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		strongSignal = true
		signals = append(signals, "Server closed connection (chunked parsing failure)")
	}

	if comparison.BodyChanged {
		confidence += 0.10
		signals = append(signals,
			fmt.Sprintf("Response body changed by %d bytes", comparison.BodySizeDiff))
	}

	if headerExistsCaseInsensitive(comparison.HeadersAdded, "Content-Length") {
		confidence += 0.10
		signals = append(signals, "Content-Length header added by backend")
	}

	return finalizeResult(d, result, confidence, strongSignal, comparison, "TE.CL", signals)
}

// ---------- Mixed TE ----------

func (d *Detector) AnalyzeMixedTE(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "Mixed-TE",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}
	strongSignal := false

	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.30
		strongSignal = true
		signals = append(signals, "Backend rejected mixed TE header")
	}

	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.40
		strongSignal = true
		signals = append(signals, "Server error from TE header ambiguity")
	}

	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		strongSignal = true
		signals = append(signals, "Connection reset (TE parser confusion)")
	}

	return finalizeResult(d, result, confidence, strongSignal, comparison, "Mixed-TE", signals)
}

// ---------- Obfuscated TE ----------

func (d *Detector) AnalyzeObfuscatedTE(target string, comparison *models.BaselineComparison) *models.ScanResult {
	result := &models.ScanResult{
		Target:           target,
		Technique:        "Obfuscated-TE",
		BaselineResponse: comparison.Baseline,
		TestResponse:     comparison.Test,
	}

	confidence := 0.0
	signals := []string{}
	strongSignal := false

	if comparison.StatusCodeChanged && comparison.NewStatusCode == 400 {
		confidence += 0.25
		strongSignal = true
		signals = append(signals, "Backend returned 400 (obfuscated TE rejection or malformed request)")
	}

	if comparison.StatusCodeChanged && comparison.NewStatusCode >= 500 {
		confidence += 0.35
		strongSignal = true
		signals = append(signals, "Backend returned 5xx error (TE obfuscation parser confusion)")
	}

	if comparison.TimingDiffMS < -30 {
		confidence += 0.15
		signals = append(signals,
			fmt.Sprintf("Response %d ms faster (obfuscated TE caused early rejection)", -comparison.TimingDiffMS))
	}

	if comparison.ConnectionBehaviorChanged && comparison.NewConnectionClosed {
		confidence += 0.20
		strongSignal = true
		signals = append(signals, "Server closed connection (TE obfuscation parser failure)")
	}

	if comparison.BodyChanged && comparison.BodySizeDiff < -200 {
		confidence += 0.15
		signals = append(signals,
			fmt.Sprintf("Response body %d bytes smaller (obfuscated TE caused content absorption)", -comparison.BodySizeDiff))
	}

	if headerExistsCaseInsensitive(comparison.HeadersRemoved, "Transfer-Encoding") {
		confidence += 0.10
		signals = append(signals, "Transfer-Encoding header removed (backend rejected obfuscation)")
	}

	return finalizeResult(d, result, confidence, strongSignal, comparison, "Obfuscated-TE", signals)
}

// ---------- Explanation ----------

func (d *Detector) buildExplanation(technique string, confidence float64, signals []string) string {
	var explanation strings.Builder

	explanation.WriteString(
		fmt.Sprintf("Potential %s vulnerability detected (confidence: %.1f%%)\n", technique, confidence*100),
	)
	explanation.WriteString("Detection signals:\n")

	if len(signals) == 0 {
		explanation.WriteString("  - Behavioral anomaly detected\n")
	}

	for _, s := range signals {
		explanation.WriteString(fmt.Sprintf("  - %s\n", s))
	}

	return explanation.String()
}

// ---------- Report ----------

type DetectionReport struct {
	Target              string
	TotalTests          int
	Vulnerable          int
	Suspicious          []*models.ScanResult
	NonSuspicious       []*models.ScanResult
	HighestConfidence   float64
	MostLikelyTechnique string
}

func (d *Detector) GenerateReport(target string, results ...*models.ScanResult) *DetectionReport {
	report := &DetectionReport{
		Target:        target,
		TotalTests:    len(results),
		Suspicious:    make([]*models.ScanResult, 0),
		NonSuspicious: make([]*models.ScanResult, 0),
	}

	highest := 0.0

	for _, result := range results {
		if result.Suspicious {
			report.Vulnerable++
			report.Suspicious = append(report.Suspicious, result)

			if result.Confidence > highest {
				highest = result.Confidence
				report.HighestConfidence = highest
				report.MostLikelyTechnique = result.Technique
			}
		} else {
			report.NonSuspicious = append(report.NonSuspicious, result)
		}
	}

	return report
}
