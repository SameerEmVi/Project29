# HTTP Request Smuggling Scanner - Programmatic API Reference

## Module Functions & Returns

### 1. sender/raw_sender.go

#### NewRawSender() -> *RawSender
Creates a raw HTTP sender with default timeouts (10s).

```go
sender := sender.NewRawSender()
```

#### SetTLS(bool) -> *RawSender
Enables or disables TLS/HTTPS for connections.

```go
sender := sender.NewRawSender().SetTLS(true)
```

#### SetInsecureTLS(bool) -> *RawSender
Allows insecure TLS (skip cert verification).

```go
sender := sender.NewRawSender().SetTLS(true).SetInsecureTLS(true)
```

#### SendRequest(target string, payload string) -> (*HTTPResponse, error)
Sends raw HTTP request and returns response.

**Parameters:**
- `target`: "host:port" format (e.g., "example.com:80")
- `payload`: Raw HTTP request string with CRLF line endings

**Returns:**
- `*HTTPResponse`: Complete response with timing, headers, body
- `error`: Connection or transmission error (if any)

**Example:**
```go
response, err := sender.SendRequest("example.com:80", 
    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Status:", response.StatusCode)
fmt.Println("Timing:", response.TimingMS, "ms")
```

---

### 2. payload/generator.go

#### NewGenerator(host string, port int) -> *Generator
Creates a payload builder for a target.

```go
gen := payload.NewGenerator("example.com", 80)
```

#### SetPath(path string) -> *Generator
Sets the request path (fluent API).

```go
gen.SetPath("/admin")
```

#### AddHeader(key, value string) -> *Generator
Adds custom header to all generated payloads.

```go
gen.AddHeader("User-Agent", "Scanner/1.0")
```

#### GenerateCLTEPayload(smuggledBody string) -> (string, error)
Generates CL.TE attack payload.

**Parameters:**
- `smuggledBody`: HTTP request to smuggle (e.g., "GET /admin HTTP/1.1\r\n...")

**Returns:**
- `string`: Raw HTTP request payload
- `error`: Validation error if smuggledBody is empty

**Example:**
```go
payload, err := gen.GenerateCLTEPayload("GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n")
// payload: malformed HTTP request designed to cause desynchronization
```

#### GenerateTECLPayload(smuggledBody string) -> (string, error)
Generates TE.CL attack payload (inverse of CL.TE).

#### GenerateBaseline() -> string
Generates a normal, clean HTTP request (no smuggling).

```go
baseline := gen.GenerateBaseline()
// payload: clean GET request with proper headers
```

---

### 3. payload/advanced_attacks.go

#### CL_TE_GPOST_ATTACK(host string, port int) -> string
Generates the Web Security Academy GPOST poisoning payload.

```go
payload := payload.CL_TE_GPOST_ATTACK("target.com", 443)
// Generates: POST with CL.TE + "G" character for poisoning
```

#### ProbeRequestAfterPoison(host string, port int) -> string
Generates a simple GET request for probing after poisoning.

```go
probe := payload.ProbeRequestAfterPoison("target.com", 443)
// Generates: Simple GET that will be affected by smuggled "G"
```

---

### 4. baseline/baseline.go

#### NewManager(sender *RawSender, host string, port int) -> *Manager
Creates a baseline capture & comparison manager.

```go
bm := baseline.NewManager(sender, "example.com", 80)
```

#### CaptureBaseline() -> (*HTTPResponse, error)
Sends a normal request to establish baseline behavior.

**Returns:**
- `*HTTPResponse`: The baseline server response
- `error`: If baseline capture fails

**Example:**
```go
baseline, err := bm.CaptureBaseline()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Baseline Status:", baseline.StatusCode)
```

#### CompareResponses(baseline, test *HTTPResponse) -> *BaselineComparison
Compares test response against baseline.

**Parameters:**
- `baseline`: The normal server behavior
- `test`: The test response after attack

**Returns:**
- `*BaselineComparison`: Detailed differences and analysis

**Example:**
```go
comparison := bm.CompareResponses(baselineResp, testResp)
fmt.Println("Status changed:", comparison.StatusCodeChanged)
fmt.Println("Headers removed:", comparison.HeadersRemoved)
```

#### IsSuspicious(comparison *BaselineComparison) -> bool
Quick check: does comparison show smuggling signs?

```go
if bm.IsSuspicious(comparison) {
    fmt.Println("Potential vulnerability detected")
}
```

#### SummaryString(comparison *BaselineComparison) -> string
Human-readable summary of differences.

```go
summary := bm.SummaryString(comparison)
fmt.Println(summary)
// Output:
// Found 5 differences:
//   1. Status code changed: 200 -> 400
//   2. Headers added: [Content-Length]
//   ...
```

---

### 5. detector/detector.go

#### NewDetector() -> *Detector
Creates a detection analyzer with default 50% confidence threshold.

```go
det := detector.NewDetector()
```

#### SetConfidenceThreshold(threshold float64) -> *Detector
Sets minimum confidence for reporting vulnerabilities (0.0-1.0).

```go
det.SetConfidenceThreshold(0.7) // Require 70% confidence
```

#### AnalyzeCLTE(target string, comparison *BaselineComparison) -> *ScanResult
Analyzes comparison for CL.TE patterns.

**Returns:**
- `*ScanResult`: Verdict with confidence score and signals

**Example:**
```go
result := det.AnalyzeCLTE("example.com", comparison)
fmt.Println("Suspicious:", result.Suspicious)
fmt.Println("Reason:", result.Reason)
fmt.Println("Timing diff:", result.ResponseTimeDiff, "ms")
```

#### AnalyzeTECL(target string, comparison *BaselineComparison) -> *ScanResult
Analyzes comparison for TE.CL patterns.

#### AnalyzeMixedTE(target string, comparison *BaselineComparison) -> *ScanResult
Analyzes comparison for mixed Transfer-Encoding exploitation.

#### GenerateReport(target string, results ...*ScanResult) -> *DetectionReport
Aggregates multiple test results into a final report.

**Parameters:**
- `target`: The target host
- `results`: Variable number of ScanResult objects

**Returns:**
- `*DetectionReport`: Summary with vulnerable count and most likely technique

**Example:**
```go
report := det.GenerateReport("example.com", 
    clteResult, 
    teclResult, 
    mixedteResult)
fmt.Println("Vulnerable:", report.Vulnerable)
fmt.Println("Total tests:", report.TotalTests)
```

#### String() -> string (on DetectionReport)
Formatted report for printing.

```go
fmt.Print(report.String())
// Outputs formatted vulnerability findings
```

---

### 6. scanner/scanner.go

#### NewScanner(target string, port int) -> *Scanner
Creates a standard (single-request) scanner.

```go
scan := scanner.NewScanner("example.com", 80)
```

#### SetConfidenceThreshold(threshold float64) -> *Scanner
Adjusts confidence threshold.

```go
scan.SetConfidenceThreshold(0.6)
```

#### SetTLS(bool) -> *Scanner
Enables HTTPS/TLS.

```go
scan.SetTLS(true)
```

#### SetInsecureTLS(bool) -> *Scanner
Allows insecure TLS (for labs).

```go
scan.SetInsecureTLS(true)
```

#### Run() -> error
Executes the full standard scanning workflow.

```go
if err := scan.Run(); err != nil {
    log.Fatal(err)
}
```

**Workflow:**
1. Captures baseline
2. Tests CL.TE
3. Tests TE.CL
4. Tests Mixed-TE
5. Generates report

#### GetResults() -> []*ScanResult
Returns all individual test results.

```go
results := scan.GetResults()
for _, result := range results {
    fmt.Println(result.Technique, "->", result.Suspicious)
}
```

#### GetReport() -> *DetectionReport
Returns the aggregated report.

```go
report := scan.GetReport()
fmt.Println("Most likely:", report.MostLikelyTechnique)
```

#### IsVulnerable() -> bool
Quick check: was any vulnerability detected?

```go
if scan.IsVulnerable() {
    fmt.Println("VULNERABLE")
}
```

#### GetMostLikelyTechnique() -> string
Returns the primary vulnerability type or "None".

```go
technique := scan.GetMostLikelyTechnique()
// Returns: "CL.TE", "TE.CL", "Mixed-TE", or "None"
```

#### PrintReport()
Prints formatted detection report to stdout.

```go
scan.PrintReport()
```

#### Summary() -> string
Brief text summary of scan results.

```go
fmt.Println(scan.Summary())
// Output:
// Target: example.com:80
// Tests run: 3
// Vulnerable: 1
// Most likely: CL.TE
// Status: VULNERABLE ✗
```

---

### 7. scanner/advanced_scanner.go

#### NewAdvancedScanner(target string, port int) -> *AdvancedScanner
Creates a multi-request attack scanner (for GPOST, etc.).

```go
ascan := scanner.NewAdvancedScanner("vulnerable-lab.com", 443)
```

#### SetConfidenceThreshold(threshold float64) -> *AdvancedScanner
#### SetTLS(bool) -> *AdvancedScanner
#### SetInsecureTLS(bool) -> *AdvancedScanner
(Same as standard scanner)

#### CaptureBaseline() -> error
Captures normal server behavior.

#### TestCLTE_GPOST() -> error
Executes multi-request GPOST poisoning attack:
1. Sends smuggling payload with "G"
2. Sends probe request
3. Analyzes response for "Unrecognized method GGET" etc.

```go
if err := ascan.TestCLTE_GPOST(); err != nil {
    log.Fatal(err)
}
```

#### Run() -> error
Executes full advanced scanning workflow.

```go
if err := ascan.Run(); err != nil {
    log.Fatal(err)
}
```

#### GetResults() -> []*ScanResult
#### GetReport() -> *DetectionReport
#### IsVulnerable() -> bool
#### GetMostLikelyTechnique() -> string
#### PrintReport()
#### Summary() -> string
(Same as standard scanner)

---

## Programmatic Usage Examples

### Example 1: Simple Scan

```go
package main

import (
    "fmt"
    "log"
    "smuggler/internal/scanner"
)

func main() {
    scan := scanner.NewScanner("example.com", 80)
    if err := scan.Run(); err != nil {
        log.Fatal(err)
    }
    
    if scan.IsVulnerable() {
        fmt.Println("VULNERABLE:", scan.GetMostLikelyTechnique())
    } else {
        fmt.Println("CLEAN")
    }
}
```

### Example 2: HTTPS Lab with Advanced Mode

```go
ascan := scanner.NewAdvancedScanner("lab.example.com", 443)
ascan.SetTLS(true).SetInsecureTLS(true)

if err := ascan.Run(); err != nil {
    log.Fatal(err)
}

report := ascan.GetReport()
fmt.Printf("Results: %d/%d vulnerable\n", report.Vulnerable, report.TotalTests)

for _, result := range report.Suspicious {
    fmt.Println("Found:", result.Technique)
    fmt.Println(result.Reason) // Detailed explanation
}
```

### Example 3: Manual Control

```go
sender := sender.NewRawSender().SetTLS(true)
bm := baseline.NewManager(sender, "target.com", 443)

// Step 1: Get baseline
baseline, _ := bm.CaptureBaseline()
fmt.Println("Baseline status:", baseline.StatusCode)

// Step 2: Send attack
payload := payload.GenerateCLTEPayload(...)
testResp, _ := sender.SendRequest("target.com:443", payload)

// Step 3: Compare
comparison := bm.CompareResponses(baseline, testResp)
det := detector.NewDetector()
result := det.AnalyzeCLTE("target.com", comparison)

// Step 4: Check result
fmt.Println("Vulnerable:", result.Suspicious)
```

---

## Return Value Chaining

Most scanner functions return `*Scanner` for fluent API:

```go
scan := scanner.NewScanner("target.com", 80).
    SetConfidenceThreshold(0.6).
    SetTLS(true).
    SetInsecureTLS(false)

// Now call Run()
scan.Run()
```

---

## Error Handling

Most functions return `error` as second return value:

```go
response, err := sender.SendRequest(target, payload)
if err != nil {
    // Handle connection errors, timeouts, etc.
    log.Printf("Request failed: %v", err)
}
```

---

## Data Access Patterns

### Access Raw Response
```go
results := scan.GetResults()
for _, result := range results {
    testResp := result.TestResponse
    fmt.Println("Status:", testResp.StatusCode)
    fmt.Println("Body length:", len(testResp.Body))
}
```

### Access Comparison Details
```go
// Via ScanResult
result := scan.GetResults()[0]
comparison := baseline.CompareResponses(
    result.BaselineResponse,
    result.TestResponse,
)

// Check specific changes
if comparison.StatusCodeChanged {
    fmt.Printf("Status: %d -> %d\n", 
        comparison.OldStatusCode,
        comparison.NewStatusCode)
}
```

### Iterate Results
```go
report := scan.GetReport()

// Vulnerable findings
for _, result := range report.Suspicious {
    fmt.Printf("[VULN] %s: %s\n", result.Technique, result.Reason)
}

// Clean findings
for _, result := range report.NonSuspicious {
    fmt.Printf("[CLEAN] %s\n", result.Technique)
}
```

---

## Summary

The tool provides multiple levels of abstraction:

1. **Low-level**: Raw sender for direct HTTP control
2. **Mid-level**: Payload generators and comparisons
3. **High-level**: Complete scanners (standard & advanced)

All functions return structured data suitable for:
- Human-readable reporting
- Programmatic integration
- Further analysis
- Result persistence
