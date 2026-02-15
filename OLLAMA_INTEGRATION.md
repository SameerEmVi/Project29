# Ollama Integration Guide

## Overview

The HTTP Request Smuggling Scanner now supports **Ollama** - a local, privacy-friendly LLM framework that runs entirely on your machine without sending data to external APIs.

## What is Ollama?

[Ollama](https://ollama.ai) is an open-source framework for running large language models locally:
- **Privacy-first**: All data stays on your computer
- **Fast**: No network latency like cloud APIs
- **Free**: No API costs
- **Offline**: Works without internet connection
- **Flexible**: Supports many models (Llama 2, Mistral, Neural Chat, etc.)

## Installation

### 1. Install Ollama

**Linux/Mac:**
```bash
curl https://ollama.ai/install.sh | sh
```

**Windows/Docker:**
Visit https://ollama.ai for installation options.

### 2. Verify Installation
```bash
ollama --version
# Output: ollama version 0.1.0 (or newer)
```

### 3. Pull a Model

```bash
# Download Llama 2 (7B, ~4GB)
ollama pull llama2

# Or try smaller/faster models:
ollama pull mistral          # 7B, fast
ollama pull neural-chat      # 7.3B, good quality
ollama pull orca-mini        # 3B, very fast
ollama pull tinyllama        # 1.1B, lightweight
```

### 4. Start Ollama Server

```bash
# Ollama runs in background by default
# Check if running:
curl http://localhost:11434/api/tags

# Output should show your downloaded models
{
  "models": [
    {"name": "llama2:latest", "modified_at": "..."},
    {"name": "mistral:latest", "modified_at": "..."}
  ]
}
```

## Usage

### Basic Ollama Scanning

```bash
# Use default Ollama (local, localhost:11434, llama2 model)
./bin/smuggler -target example.com -port 80 -ai -ai-backend ollama

# With verbose output
./bin/smuggler -target example.com -port 80 -ai -ai-backend ollama -v
```

### Custom Ollama Configuration

```bash
# Use Mistral model instead of Llama2
./bin/smuggler \
  -target example.com \
  -port 80 \
  -ai \
  -ai-backend ollama \
  -ollama-model mistral

# Custom Ollama endpoint (e.g., remote machine)
./bin/smuggler \
  -target example.com \
  -port 80 \
  -ai \
  -ai-backend ollama \
  -ollama-endpoint http://192.168.1.100:11434 \
  -ollama-model neural-chat
```

### HTTPS Lab with Ollama

```bash
./bin/smuggler \
  -target 0a8f006903f8785181c8b1a200d20006.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -ai-backend ollama \
  -ollama-model mistral \
  -v
```

### Advanced Mode with Ollama

```bash
./bin/smuggler \
  -target vulnerable.lab.com \
  -port 443 \
  -https \
  -advanced \
  -ai \
  -ai-backend ollama \
  -ollama-model llama2
```

## CLI Flags Reference

### AI Provider Selection

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-ai` | bool | false | Enable AI-powered analysis |
| `-ai-backend` | string | "openai" | AI backend: `openai` or `ollama` |

### OpenAI Specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-api-key` | string | "" | OpenAI API key (or env var `OPENAI_API_KEY`) |

### Ollama Specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-ollama-endpoint` | string | "http://localhost:11434" | Ollama API endpoint URL |
| `-ollama-model` | string | "llama2" | Ollama model name to use |

### Other Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-target` | string | "example.com" | Target hostname |
| `-port` | int | 80 | Target port |
| `-confidence` | float | 0.5 | Confidence threshold (0.0-1.0) |
| `-https` | bool | false | Use HTTPS/TLS |
| `-insecure` | bool | false | Skip TLS cert verification |
| `-advanced` | bool | false | Enable multi-request attacks |
| `-v` | bool | false | Verbose output |

## Available Models

### Recommended Models

**For HTTP Smuggling Analysis:**

| Model | Size | Speed | Quality | Notes |
|-------|------|-------|---------|-------|
| `ollama pull llama2` | 7B (~4GB) | Slow | Good | Default, well-balanced |
| `ollama pull mistral` | 7B (~4.1GB) | Fast | Good | Recommended for this task |
| `ollama pull neural-chat` | 7.3B | Fast | Excellent | Best quality output |
| `ollama pull orca-mini` | 3B (~2GB) | Fast | Fair | Lightweight alternative |
| `ollama pull tinyllama` | 1.1B (~600MB) | Very Fast | Basic | Minimal system requirements |

**Setup examples:**
```bash
# Mistral (recommended)
ollama pull mistral
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model mistral

# Neural Chat (best quality)
ollama pull neural-chat
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model neural-chat

# Lightweight (minimal resources)
ollama pull orca-mini
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model orca-mini
```

## System Requirements

### Minimum (Lightweight Models)
- **RAM**: 4GB+
- **Storage**: 2GB+ for tinyllama
- **CPU**: Any modern processor
- **GPU**: Optional (improves speed)

### Recommended (Standard Models)
- **RAM**: 8GB+
- **Storage**: 5GB+ for 7B models
- **CPU**: Modern multi-core processor
- **GPU**: NVIDIA/AMD GPU (optional, speeds up inference 5-10x)

### GPU Acceleration

**NVIDIA GPU support:**
```bash
# Ollama automatically detects NVIDIA GPUs
# For optimal performance, install NVIDIA CUDA
# https://ollama.ai/blog/gpu

# Verify GPU detection:
ollama -v
# Should show GPU information
```

**AMD/Intel GPU:**
```bash
# AMD ROCm (experimental):
docker run --device /dev/dri -p 11434:11434 ollama/ollama

# Intel GPU (Intel Arc):
# See https://ollama.ai for instructions
```

## Performance Comparison

### Sample Scan Time (example.com)

| Configuration | Time | Memory | Notes |
|---|---|---|---|
| OpenAI gpt-3.5-turbo | 10-15s | <100MB | Network dependent |
| Ollama llama2 (CPU) | 30-60s | 1-2GB | First query slower |
| Ollama mistral (CPU) | 20-40s | 800MB-1.5GB | Faster than llama2 |
| Ollama neural-chat (CPU) | 20-45s | 1-2GB | Good balance |
| Ollama mistral (GPU) | 5-10s | 2-3GB VRAM | Much faster |
| Ollama llama2 (GPU) | 5-12s | 2-3GB VRAM | Optimal for GPU |

**Note**: First query to a model is slower (model loading). Subsequent queries are faster.

## Output Examples

### Standard Scan with Ollama

```bash
$ ./bin/smuggler -target example.com -port 80 -ai -ai-backend ollama -ollama-model mistral -v

[+] Confidence threshold: 50.0%
[+] AI-powered analysis enabled: Ollama (mistral)

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
    Reasoning: Status code change to 400 with response timing
    increase of 37ms suggests desynchronization between parsers.
    Suspicious Signals: [status_4xx, timing_increase, body_reduction]
    
    Result: SUSPICIOUS ✗

[*] Testing TE.CL...
    Response: 200 | Timing: 48 ms
    Result: CLEAN ✓

============================================================
=== DETECTION REPORT ===

VULNERABLE FINDINGS:

1. CL.TE
Potential CL.TE vulnerability detected (confidence: 75%)
The Ollama analysis indicates clear desynchronization between
proxy and backend when Content-Length and Transfer-Encoding
headers conflict.

============================================================
```

### Comparing Ollama vs OpenAI Output

**Speed difference:**
- Ollama: Analysis happens locally (faster after model loads)
- OpenAI: Network round-trip required each time

**Quality difference:**
- Ollama: Slightly different reasoning, sometimes more detailed
- OpenAI: More consistent, better at JSON parsing

**Cost difference:**
- Ollama: Free (one-time model download)
- OpenAI: ~$0.01-0.05 per scan

## Troubleshooting

### "failed to connect to Ollama"

**Issue**: Scanner can't reach Ollama server

**Solutions:**
```bash
# 1. Check if Ollama is running
curl http://localhost:11434/api/tags

# 2. Verify the endpoint
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-endpoint http://localhost:11434

# 3. If not running, start it:
ollama serve

# 4. Check firewall/network
# Make sure port 11434 is accessible
```

### "no model found: mistral"

**Issue**: Model hasn't been downloaded yet

**Solutions:**
```bash
# Download the model first
ollama pull mistral

# Verify it's installed
ollama list

# Then use it
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model mistral
```

### Slow response times

**causes:**
1. Model still loading (first query takes longer)
2. Using CPU instead of GPU
3. Underpowered system for model size

**Solutions:**
```bash
# Use smaller, faster model
ollama pull mistral  # Faster than llama2
./bin/smuggler -ai -ai-backend ollama -ollama-model mistral

# Enable GPU acceleration (see System Requirements)

# Pre-load model into memory
# (Just run `ollama pull mistral` before scanning)
```

### Out of memory errors

**Solutions:**
```bash
# Use smaller model
ollama pull orca-mini
./bin/smuggler -ai -ollama-model orca-mini

# Increase system swap (temporary)
# Or restart Ollama service to clear memory
```

### JSON parsing errors

**Issue**: Ollama's response can't be parsed

**cause:** Model isn't following JSON format instructions

**Solutions:**
```bash
# Try different model (some follow instructions better)
ollama pull neural-chat
./bin/smuggler -ai -ollama-model neural-chat

# Or fall back to OpenAI
./bin/smuggler -ai -ai-backend openai -api-key "sk-..."
```

## Advanced Usage

### Programmatic Use

```go
import "smuggler/internal/ai"

// Create Ollama analyzer
analyzer := ai.NewOllamaAnalyzer(
    "http://localhost:11434",  // endpoint
    "mistral",                  // model
)

// Use like any other provider
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

### Using with Scanner

```go
import (
    "smuggler/internal/ai"
    "smuggler/internal/scanner"
)

// Create Ollama provider
provider := ai.NewOllamaAnalyzer("http://localhost:11434", "mistral")

// Use with scanner
scan := scanner.NewScanner("example.com", 80)
scan.SetAIProvider(provider)
scan.Run()
```

### Remote Ollama Server

```bash
# Run Ollama on remote machine
# ssh user@remote.host
# ollama serve --host 0.0.0.0:11434

# Use from local scanner
./bin/smuggler \
  -target example.com \
  -ai \
  -ai-backend ollama \
  -ollama-endpoint http://remote.host:11434
```

## Switching Between Providers

### OpenAI
```bash
./bin/smuggler -target example.com -ai -ai-backend openai -api-key "sk-..."
```

### Ollama
```bash
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model mistral
```

### No AI
```bash
./bin/smuggler -target example.com
```

## Privacy & Security

### Data Privacy

**OpenAI:**
- Requests sent to OpenAI servers
- Subject to OpenAI's privacy policy
- Review: https://openai.com/policies/privacy-policy

**Ollama:**
- All data stays on your machine
- No external connections
- Complete privacy for sensitive assessments

### When to use which?

**Use Ollama when:**
- Testing sensitive/confidential targets
- Offline capability is important
- Cost is a concern
- Privacy is critical

**Use OpenAI when:**
- Need highest quality analysis
- Want API consistency
- Have consistent network connection
- Don't mind API costs

## Performance Tuning

### For Maximum Speed

```bash
# Use smallest viable model
ollama pull mistral
./bin/smuggler -ai -ai-backend ollama -ollama-model mistral

# With GPU acceleration (see System Requirements)

# Result: ~5-10s per scan
```

### For Maximum Quality

```bash
# Use larger, more capable model
ollama pull neural-chat
./bin/smuggler -ai -ai-backend ollama -ollama-model neural-chat

# Result: Best accuracy, 20-45s per scan (CPU)
```

### For Minimal Resources

```bash
# Use smallest model
ollama pull tinyllama
./bin/smuggler -ai -ai-backend ollama -ollama-model tinyllama

# Result: Works on older systems, 10-20s per scan
```

## Advantages vs Disadvantages

### Ollama Advantages ✅
- Privacy (data stays local)
- Free (after setup)
- Fast (no network latency)
- Offline capable
- Flexible (choose any model)
- GPU acceleration support
- Good for bulk scanning

### Ollama Disadvantages ❌
- Setup required
- System resources needed
- Slower first query
- Variable quality by model
- GPU cost (energy)

### OpenAI Advantages ✅
- No setup needed
- Highest quality output
- Consistent behavior
- Fast for single queries
- works everywhere
- API reliability

### OpenAI Disadvantages ❌
- API cost (~$0.01-0.05 per scan)
- Data sent to external server
- Requires internet connection
- Privacy concerns for some use cases

## Resources

- **Ollama**: https://ollama.ai
- **Model Library**: https://ollama.ai/library
- **GitHub**: https://github.com/jmorganca/ollama
- **Documentation**: https://github.com/jmorganca/ollama/tree/main/docs

## Support

For Ollama-specific issues:
1. Check Ollama status: `curl http://localhost:11434/api/tags`
2. Review Ollama logs: Check console where `ollama serve` runs
3. Try different model: `ollama pull neural-chat`
4. Reset Ollama: Restart the server and re-pull models
