package scanner

import (
	"fmt"
	"strings"

	"smuggler/internal/baseline"
	"smuggler/internal/detector"
	"smuggler/internal/models"
	"smuggler/internal/payload"
	"smuggler/internal/sender"
)

// AdvancedScanner handles more complex HTTP request smuggling scenarios
// that require multi-request attacks (send payload, then probe, then check effect).
type AdvancedScanner struct {
	target           string
	port             int
	sender           *sender.RawSender
	baselineManager  *baseline.Manager
	detector         *detector.Detector
	baselineResponse *models.HTTPResponse
	results          []*models.ScanResult
	report           *detector.DetectionReport
}

// NewAdvancedScanner creates a new advanced scanner.
func NewAdvancedScanner(target string, port int) *AdvancedScanner {
	s := sender.NewRawSender()

	return &AdvancedScanner{
		target:          target,
		port:            port,
		sender:          s,
		baselineManager: baseline.NewManager(s, target, port),
		detector:        detector.NewDetector(),
		results:         make([]*models.ScanResult, 0),
	}
}

// SetConfidenceThreshold sets the detector's confidence threshold.
func (as *AdvancedScanner) SetConfidenceThreshold(threshold float64) *AdvancedScanner {
	as.detector.SetConfidenceThreshold(threshold)
	return as
}

// SetTLS enables or disables TLS/HTTPS for connections.
func (as *AdvancedScanner) SetTLS(useTLS bool) *AdvancedScanner {
	as.sender.SetTLS(useTLS)
	return as
}

// SetInsecureTLS allows insecure TLS connections.
func (as *AdvancedScanner) SetInsecureTLS(insecure bool) *AdvancedScanner {
	as.sender.SetInsecureTLS(insecure)
	return as
}

// CaptureBaseline captures normal server behavior.
func (as *AdvancedScanner) CaptureBaseline() error {
	fmt.Printf("[*] Capturing baseline response for %s:%d\n", as.target, as.port)

	resp, err := as.baselineManager.CaptureBaseline()
	if err != nil {
		return fmt.Errorf("baseline capture failed: %w", err)
	}

	as.baselineResponse = resp
	fmt.Printf("    Status: %d | Timing: %d ms | Headers: %d | Body: %d bytes\n",
		resp.StatusCode, resp.TimingMS, len(resp.Headers), len(resp.Body))

	return nil
}

// TestCLTE_GPOST tests the Web Security Academy GPOST poisoning attack.
// This is a multi-request attack that:
// 1. Sends smuggling payload with "G" character
// 2. Sends probe request that gets poisoned
// 3. Checks if response contains "GPOST" method error
func (as *AdvancedScanner) TestCLTE_GPOST() error {
	if as.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing CL.TE GPOST poisoning (multi-request attack)...\n")

	targetAddr := fmt.Sprintf("%s:%d", as.target, as.port)

	// Step 1: Send smuggling payload
	fmt.Printf("    [1] Sending smuggling payload...\n")
	smugglePayload := payload.CL_TE_GPOST_ATTACK(as.target, as.port)
	resp1, err := as.sender.SendRequest(targetAddr, smugglePayload)
	if err != nil {
		return fmt.Errorf("smuggling payload send failed: %w", err)
	}
	fmt.Printf("        Response: %d | Timing: %d ms\n", resp1.StatusCode, resp1.TimingMS)

	// Step 2: Send probe request (GET) that should be poisoned
	fmt.Printf("    [2] Sending probe request after smuggling...\n")
	probePayload := payload.ProbeRequestAfterPoison(as.target, as.port)
	resp2, err := as.sender.SendRequest(targetAddr, probePayload)
	if err != nil {
		return fmt.Errorf("probe request send failed: %w", err)
	}
	fmt.Printf("        Response: %d | Timing: %d ms\n", resp2.StatusCode, resp2.TimingMS)

	// Step 3: Analyze probe response for poisoning indicators
	fmt.Printf("    [3] Analyzing probe response for poisoning...\n")

	// Check for "GPOST" method error or similar indicators
	var suspicious bool
	var reason string

	if strings.Contains(strings.ToUpper(resp2.Raw), "GPOST") {
		suspicious = true
		reason = "Probe response contains 'GPOST' method - request successfully poisoned!"
		fmt.Printf("        ✗ SUSPICIOUS: Response contains 'GPOST' indicator\n")
	} else if strings.Contains(strings.ToUpper(resp2.Raw), "UNRECOGNIZED METHOD") {
		suspicious = true
		reason = "Probe response indicates unrecognized method - likely poisoned request"
		fmt.Printf("        ✗ SUSPICIOUS: Response mentions unrecognized method\n")
	} else if resp2.StatusCode == 405 || resp2.StatusCode == 400 {
		// Status code difference might indicate poisoning
		if resp2.StatusCode != as.baselineResponse.StatusCode {
			suspicious = true
			reason = fmt.Sprintf("Probe returned %d (baseline was %d) - possible poisoning", resp2.StatusCode, as.baselineResponse.StatusCode)
			fmt.Printf("        ~ POSSIBLE: Status code changed after smuggling\n")
		}
	}

	// Create result
	result := &models.ScanResult{
		Target:           as.target,
		Technique:        "CL.TE-GPOST",
		Suspicious:       suspicious,
		Reason:           reason,
		ResponseTimeDiff: resp2.TimingMS - as.baselineResponse.TimingMS,
		BaselineResponse: as.baselineResponse,
		TestResponse:     resp2,
	}

	as.results = append(as.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "UNCLEAR ~"
	}())

	// Print response body snippet for inspection
	if len(resp2.Body) > 0 && len(resp2.Body) < 500 {
		fmt.Printf("    Response Body Preview:\n%s\n", resp2.Body)
	} else if len(resp2.Body) > 0 {
		fmt.Printf("    Response Body (first 300 chars):\n%s...\n", resp2.Body[:300])
	}

	return nil
}

// Run executes the advanced scanning workflow.
func (as *AdvancedScanner) Run() error {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("HTTP REQUEST SMUGGLING SCANNER (ADVANCED MODE)\n")
	fmt.Printf("Target: %s:%d\n", as.target, as.port)
	fmt.Printf("%s\n\n", strings.Repeat("=", 60))

	if err := as.CaptureBaseline(); err != nil {
		return err
	}

	if err := as.TestCLTE_GPOST(); err != nil {
		return err
	}

	as.generateFinalReport()

	return nil
}

// generateFinalReport creates the detection report.
func (as *AdvancedScanner) generateFinalReport() {
	as.report = as.detector.GenerateReport(as.target, as.results...)
}

// PrintReport prints the detection report.
func (as *AdvancedScanner) PrintReport() {
	if as.report == nil {
		fmt.Println("[!] No report available. Run the scanner first.")
		return
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Print(as.report.String())
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

// GetResults returns raw scan results.
func (as *AdvancedScanner) GetResults() []*models.ScanResult {
	return as.results
}

// GetReport returns the detection report.
func (as *AdvancedScanner) GetReport() *detector.DetectionReport {
	return as.report
}

// IsVulnerable returns true if vulnerability detected.
func (as *AdvancedScanner) IsVulnerable() bool {
	if as.report == nil {
		return false
	}
	return as.report.Vulnerable > 0
}

// GetMostLikelyTechnique returns the primary vulnerability type.
func (as *AdvancedScanner) GetMostLikelyTechnique() string {
	if as.report == nil || as.report.Vulnerable == 0 {
		return "None"
	}
	return as.report.MostLikelyTechnique
}

// Summary returns a brief summary string.
func (as *AdvancedScanner) Summary() string {
	if as.report == nil {
		return "Scan not completed"
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Target: %s:%d\n", as.target, as.port))
	summary.WriteString(fmt.Sprintf("Tests run: %d\n", as.report.TotalTests))
	summary.WriteString(fmt.Sprintf("Vulnerable: %d\n", as.report.Vulnerable))

	if as.report.Vulnerable > 0 {
		summary.WriteString(fmt.Sprintf("Most likely: %s\n", as.report.MostLikelyTechnique))
		summary.WriteString("Status: VULNERABLE ✗\n")
	} else {
		summary.WriteString("Status: No confirmed vulnerabilities\n")
	}

	return summary.String()
}
