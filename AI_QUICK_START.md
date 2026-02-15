# AI Providers Quick Start

## Side-by-Side Comparison

### OpenAI (Cloud-based)

```bash
# Setup (one-time)
export OPENAI_API_KEY="sk-..."

# Basic scan
./bin/smuggler -target example.com -ai

# HTTPS lab
./bin/smuggler \
  -target 0a8f006903f8785181c8b1a200d20006.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai

# Advanced mode
./bin/smuggler -target example.com -ai -advanced
```

### Ollama (Local)

```bash
# Setup (one-time)
ollama pull mistral

# Basic scan
./bin/smuggler -target example.com -ai -ai-backend ollama

# HTTPS lab
./bin/smuggler \
  -target 0a8f006903f8785181c8b1a200d20006.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -ai-backend ollama \
  -ollama-model mistral

# Advanced mode
./bin/smuggler -target example.com -ai -ai-backend ollama -advanced
```

## Quick Decision Matrix

| Need | Use | Command |
|------|-----|---------|
| **Quick setup, highest quality** | OpenAI | `./bin/smuggler -target example.com -ai` |
| **Free, privacy-focused** | Ollama | `./bin/smuggler -target example.com -ai -ai-backend ollama` |
| **Fast, small system** | Ollama Mistral | `./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model mistral` |
| **Best quality, local** | Ollama Neural-Chat | `./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model neural-chat` |
| **Minimal resources** | Ollama TinyLlama | `./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model tinyllama` |

## Setup Scenarios

### Scenario 1: I want to try AI quickly

**Use OpenAI:**
```bash
export OPENAI_API_KEY="sk-..."  # Get from https://platform.openai.com
./bin/smuggler -target example.com -ai -v
```

### Scenario 2: I want free, private, local AI

**Use Ollama:**
```bash
# First time: Download model
ollama pull mistral

# Then: Use it
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model mistral -v
```

### Scenario 3: I'm testing many targets

**Use Ollama:**
```bash
# Download once
ollama pull mistral

# Scan multiple
for target in example.com github.com google.com; do
  echo "Scanning $target..."
  ./bin/smuggler -target $target -ai -ai-backend ollama -ollama-model mistral
done
```

### Scenario 4: I need best quality

**Use OpenAI:**
```bash
export OPENAI_API_KEY="sk-..."
./bin/smuggler -target example.com -ai -confidence 0.8
```

## All Flags Reference

### Provider Selection
```bash
-ai                  # Enable AI analysis
-ai-backend string   # openai (default) or ollama
```

### OpenAI Only
```bash
-api-key string      # Your OpenAI API key
```

### Ollama Only
```bash
-ollama-endpoint string   # Default: http://localhost:11434
-ollama-model string      # Default: llama2
                          # Options: mistral, neural-chat, orca-mini, etc.
```

### Scanning Options
```bash
-target string       # Target hostname
-port int           # Target port (default: 80)
-https              # Use HTTPS/TLS
-insecure           # Skip cert verification
-confidence float   # Confidence threshold (0.0-1.0)
-advanced           # Multi-request scanning
-v                  # Verbose output
```

## Examples by Use Case

### Public Target (Web Security Academy Lab)

**With OpenAI:**
```bash
./bin/smuggler \
  -target 0a2500100486d31f8572f975009000e1.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -v
```

**With Ollama:**
```bash
ollama pull mistral  # One-time setup

./bin/smuggler \
  -target 0a2500100486d31f8572f975009000e1.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -ai-backend ollama \
  -ollama-model mistral \
  -v
```

### Internal Network Target

**With Ollama (privacy-focused):**
```bash
./bin/smuggler \
  -target internal-api.company.local \
  -port 8080 \
  -ai \
  -ai-backend ollama \
  -ollama-model mistral
```

### Bulk Scanning

**With Ollama (cost-effective):**
```bash
#!/bin/bash
targets=("example.com" "github.com" "google.com")

for target in "${targets[@]}"; do
  echo "[*] Scanning $target"
  ./bin/smuggler -target $target -ai -ai-backend ollama -ollama-model mistral
done
```

### High Confidence Detection

**With OpenAI (most reliable):**
```bash
./bin/smuggler \
  -target example.com \
  -ai \
  -confidence 0.75 \
  -v
```

## Performance Comparison

| Scenario | OpenAI | Ollama (CPU) | Ollama (GPU) |
|----------|--------|---|---|
| Setup time | 2 min | 5 min (1st) | 5 min (1st) |
| Per-scan time | 10-15s | 30-60s | 5-10s |
| Cost per scan | ~$0.02 | $0 | $0 (energy) |
| Quality | Excellent | Good | Excellent |
| Privacy | External | Local | Local |
| Internet required | Yes | No | No |

## Troubleshooting Quick Links

### OpenAI Issues
See [AI_INTEGRATION.md](AI_INTEGRATION.md) → Troubleshooting

### Ollama Issues
See [OLLAMA_INTEGRATION.md](OLLAMA_INTEGRATION.md) → Troubleshooting

## Model Selection Guide

### For HTTP Smuggling Analysis

| Model | Best For | Speed | Quality |
|-------|----------|-------|---------|
| llama2 | Balanced | Medium | Good |
| mistral | Fast scanning | Fast | Good |
| neural-chat | Best results | Medium | Excellent |
| orca-mini | Low resources | Fast | Fair |
| tinyllama | Minimal systems | Very Fast | Basic |

```bash
# Recommended for most users
ollama pull mistral

# If you have GPU
ollama pull neural-chat

# On older systems
ollama pull orca-mini
```

## Switching Providers

### Start with OpenAI, switch to Ollama

```bash
# Phase 1: Test with OpenAI
export OPENAI_API_KEY="sk-..."
./bin/smuggler -target example.com -ai

# Phase 2: Try Ollama
ollama pull mistral
./bin/smuggler -target example.com -ai -ai-backend ollama

# Phase 3: Use what works better for you
```

## Next Steps

- **OpenAI users**: See [AI_INTEGRATION.md](AI_INTEGRATION.md)
- **Ollama users**: See [OLLAMA_INTEGRATION.md](OLLAMA_INTEGRATION.md)
- **General info**: See [TOOL_OUTPUTS.md](TOOL_OUTPUTS.md)
- **API reference**: See [PROGRAMMING_API.md](PROGRAMMING_API.md)
