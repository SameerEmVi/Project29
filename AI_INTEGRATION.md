# AI Integration Guide

## Overview

The HTTP Request Smuggling Scanner now includes **AI-powered analysis** using OpenAI's GPT models to intelligently detect and report vulnerabilities.

## Features

### 1. Intelligent Response Analysis
AI analyzes HTTP responses to identify smuggling patterns that might be missed by static rules:
- Detects status code anomalies
- Identifies timing differences that indicate desynchronization
- Recognizes content manipulation signatures

### 2. Smart Payload Suggestions
AI recommends the most promising attack payloads based on:
- Target response patterns
- Server software identification
- Previous test results
- HTTP protocol behavior

### 3. Technique Identification
AI determines the **most likely vulnerability type** with confidence scoring:
- CL.TE vs TE.CL vs Mixed-TE distinction
- Probability assessment based on evidence
- Contextual reasoning

### 4. Detailed Report Generation
AI creates professional security assessments covering:
- Executive summary
- Vulnerability details with technical depth
- Attack scenarios and impact
- Remediation recommendations

## Usage

### Basic AI Scanning

```bash
# With OpenAI API key as environment variable
export OPENAI_API_KEY="sk-..."
./bin/smuggler -target example.com -port 80 -ai

# With inline API key
./bin/smuggler -target example.com -port 443 -https -insecure -ai -api-key "sk-..."
```

### HTTPS Lab Testing with AI

```bash
./bin/smuggler \
  -target 0a8f006903f8785181c8b1a200d20006.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -api-key "sk-..." \
  -v
```

### Advanced Mode with AI

```bash
./bin/smuggler \
  -target vulnerable.lab.com \
  -port 443 \
  -https \
  -advanced \
  -ai \
  -api-key "sk-..."
```

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-target` | string | "example.com" | Target hostname |
| `-port` | int | 80 | Target port |
| `-confidence` | float | 0.5 | Confidence threshold (0.0-1.0) |
| `-https` | bool | false | Use HTTPS/TLS |
| `-insecure` | bool | false | Skip TLS cert verification |
| `-advanced` | bool | false | Enable multi-request attacks |
| `-ai` | bool | false | **Enable AI analysis** |
| `-api-key` | string | "" | **OpenAI API key** (or use env var) |
| `-v` | bool | false | Verbose output |

## Environment Variables

```bash
# Set OpenAI API key
export OPENAI_API_KEY="sk-..."

# Scanner will automatically use it
./bin/smuggler -target example.com -ai
```

## OpenAI API Setup

### 1. Create OpenAI Account
- Go to https://platform.openai.com/
- Sign up or log in
- Navigate to API keys section

### 2. Create API Key
- Click "Create new secret key"
- Copy the key (starts with `sk-`)
- Store securely

### 3. Set API Key
```bash
# Option A: Environment variable
export OPENAI_API_KEY="sk-..."

# Option B: Command line flag
./bin/smuggler -target example.com -ai -api-key "sk-..."
```

### 4. Verify Setup
```bash
# This will use AI analysis
./bin/smuggler -target example.com -port 80 -ai -v
```

## Output Examples

### Standard Scan with AI

```
============================================================
HTTP REQUEST SMUGGLING SCANNER
Target: example.com:80
============================================================

[*] Capturing baseline response...
    Status: 200 | Timing: 45 ms | Body: 5240 bytes

[*] Testing CL.TE (Content-Length / Transfer-Encoding)...
    Response: 400 | Timing: 82 ms
    
    [AI Analysis]
    Confidence: 75.0%
    Reasoning: Status code change to 400 indicates malformed request
    detection by backend. Response timing 37ms slower suggests
    parsing delay consistent with desynchronization.
    Suspicious Signals: [status_4xx, timing_increase, body_reduction]
    
    Result: SUSPICIOUS ✗

[*] Testing TE.CL (Transfer-Encoding / Content-Length)...
    Response: 200 | Timing: 48 ms
    Result: CLEAN ✓

============================================================
=== DETECTION REPORT ===

VULNERABLE FINDINGS:

1. CL.TE
Vulnerability detected by AI analysis with 75.0% confidence.
The server exhibits clear desynchronization between proxy and
backend parsers when Content-Length and Transfer-Encoding headers
conflict. Attack vector likely achievable via CL.TE poisoning.

Recommended Next Steps:
- Perform deep payload crafting with malformed chunk sizes
- Test request smuggling with poisoned headers
- Attempt cache manipulation attacks

============================================================
```

### AI Payload Suggestions

When using `-ai`, the scanner may suggest custom payloads:

```
[*] AI Payload Recommendations:

1. CL.TE with Chunk Extension [HIGH PRIORITY]
   Rationale: Server accepts Transfer-Encoding headers but
   struggles with Content-Length calculations. Chunk extension
   syntax may bypass WAF while maintaining desynchronization.

2. Mixed-TE with Obfuscation [MEDIUM PRIORITY]
   Rationale: Multiple TE headers detected in baseline.
   Obfuscated variants (e.g., "chunked;q=0.5") may exploit
   parser inconsistencies without triggering filtering.
```

## How AI Analysis Works

### Signal Scoring
The AI considers:
- **Response Status**: 4xx/5xx responses to malformed requests (+25-35% confidence)
- **Timing Anomalies**: Response time changes indicating different parsing paths (+15-25%)
- **Content Changes**: Body size/structure differences suggesting absorbed content (+15-20%)
- **Header Modifications**: Added/removed headers from test responses (+10-15%)
- **Connection Behavior**: Closure patterns indicating parser stress (+20-25%)

### Confidence Calculation
AI aggregates multiple signals:
```
confidence = Σ(signal_weights) with 1.0 maximum
```

Factors:
- Status 400 = +0.25
- Status 5xx = +0.35
- Timing >100ms faster = +0.15
- Timing >100ms slower = +0.25
- Connection closed = +0.20
- Large body reduction = +0.15
- Header changes = +0.10

### JSON Response Parsing
AI responses are validated JSON structures:
```json
{
  "is_vulnerable": true,
  "techniques": ["CL.TE"],
  "confidence": 0.75,
  "reasoning": "Status code change to 400...",
  "suspicious_signals": ["status_4xx", "timing_increase"],
  "recommendations": ["test_chunk_extension", "test_cache_poisoning"]
}
```

## Cost Considerations

### OpenAI API Pricing (as of 2024)
- **GPT-3.5-turbo**: ~$0.0005 per 1K input tokens, $0.0015 per 1K output tokens
- Typical scan: 3-5 API calls per target
- Estimated cost per scan: $0.01-0.05
- Advanced mode (multi-request): $0.02-0.10

### Reducing Costs
1. Use confidence threshold to skip low-confidence tests:
   ```bash
   ./bin/smuggler -target example.com -confidence 0.8 -ai
   ```

2. Disable AI for certain tests:
   ```bash
   # Run manual analysis for most targets, AI only for suspicious ones
   ```

3. Batch multiple targets (planned feature)

## Limitations

1. **API Dependency**: Requires internet connection and active OpenAI account
2. **Rate Limiting**: OpenAI API has rate limits (consult their docs)
3. **Accuracy**: AI is probabilistic; not 100% accurate for all scenarios
4. **Context Size**: Very long responses may be truncated in analysis
5. **Model Drift**: GPT model behavior may change with updates

## Troubleshooting

### "No response from AI"
- Check OpenAI API key is valid
- Verify internet connection
- Check API rate limits haven't been exceeded

### "API error: Invalid API key"
- Verify API key starts with `sk-`
- Ensure no spaces or extra characters in key
- Check key hasn't been revoked

### "API error 429"
- Rate limit exceeded
- Wait before retrying
- Increase time between scans

### "Failed to parse AI response"
- API returned non-JSON response
- Check API key validity
- Verify OpenAI API is accessible

## Advanced Usage

### Custom Processing

```go
import "smuggler/internal/ai"

// Use AI analyzer programmatically
analyzer := ai.NewAIAnalyzer("sk-...")

baseline := map[string]interface{}{
    "status": 200,
    "body_len": 5240,
}

testResp := map[string]interface{}{
    "status": 400,
    "body_len": 45,
}

result, err := analyzer.AnalyzeResponses(baseline, testResp, "CL.TE")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Vulnerable: %v\n", result.IsVulnerable)
fmt.Printf("Confidence: %.1f%%\n", result.Confidence*100)
```

### Technique Identification

```go
tests := map[string]map[string]interface{}{
    "CL.TE": {"status": 400, "timing_diff": 37},
    "TE.CL": {"status": 200, "timing_diff": 3},
    "Mixed-TE": {"status": 403, "timing_diff": -5},
}

technique, confidence, err := analyzer.IdentifyTechnique(tests)
fmt.Printf("Most likely: %s (%.1f%% confidence)\n", technique, confidence*100)
```

## Security Notes

⚠️ **Important**: 
- Never commit API keys to version control
- Use environment variables for production
- Rotate API keys regularly
- Monitor API usage for unauthorized access
- AI analysis is an additional layer; still verify manually

## Future Enhancements

Planned features:
- Support for different AI models (Claude, Gemini, local Ollama)
- Batch scanning with AI aggregation
- Custom prompt templates
- AI-powered payload fuzzing
- Automated remediation suggestions
- Integration with security platforms
