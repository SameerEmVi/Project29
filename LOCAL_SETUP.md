# Local Setup & Running Guide

## Prerequisites

1. **Git** - To clone the repository
2. **Go 1.21+** - To compile the scanner
3. **Ollama** - With models installed (you already have this!)

## Step 1: Clone/Download the Project

```bash
# If cloning from GitHub
git clone https://github.com/SameerEmVi/Project29.git
cd Project29/smuggler

# Or if you already have it
cd /path/to/Project29/smuggler
```

## Step 2: Build the Binary

```bash
# On Windows
go build -o bin\smuggler.exe .\cmd\main.go

# On Mac/Linux
go build -o bin/smuggler ./cmd/main.go
```

## Step 3: Run with Ollama

### Windows

```bash
# Simple way - using the run.bat script
run.bat 0afe007a042f81858020b29d00550007.web-security-academy.net xploiter/pentester:latest

# Or manually
.\bin\smuggler.exe ^
  -target 0afe007a042f81858020b29d00550007.web-security-academy.net ^
  -port 443 ^
  -https ^
  -insecure ^
  -ai ^
  -ai-backend ollama ^
  -ollama-model "xploiter/pentester:latest" ^
  -v
```

### Mac/Linux

```bash
# Simple way - using the run.sh script
chmod +x run.sh
./run.sh 0afe007a042f81858020b29d00550007.web-security-academy.net xploiter/pentester:latest

# Or manually
./bin/smuggler \
  -target 0afe007a042f81858020b29d00550007.web-security-academy.net \
  -port 443 \
  -https \
  -insecure \
  -ai \
  -ai-backend ollama \
  -ollama-model "xploiter/pentester:latest" \
  -v
```

## Understanding the Output

### Phase 1: Baseline Capture
```
[*] Capturing baseline response for target:443
    Status: 200 | Timing: 781 ms | Body: 8083 bytes
```
- Scanner captures normal server behavior

### Phase 2: Attack Tests
```
[*] Testing CL.TE (Content-Length / Transfer-Encoding)...
    Response: 400 | Timing: 633 ms
    [AI Analysis - Waiting for Ollama...]
    Result: SUSPICIOUS ✗
```
- Scanner sends CL.TE smuggling payload
- Ollama pentester model analyzes response
- Shows confidence & reasoning

### Phase 3: Report
```
=== DETECTION REPORT ===
VULNERABLE FINDINGS:
1. CL.TE - [Pentester model analysis here]
```

## Troubleshooting

### "Ollama not running or not installed"

**Solution:**
```bash
# Start Ollama service
ollama serve

# In another terminal, verify
ollama list
```

### "Model not found: xploiter/pentester:latest"

**Solution:**
```bash
# List your models
ollama list

# Use one you have
./bin/smuggler -target example.com -ai -ai-backend ollama -ollama-model WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest
```

### Build errors

**Solution:**
```bash
# Update Go modules
go mod tidy

# Try building again
go build -o bin/smuggler ./cmd/main.go
```

### Connection refused

**Issue:** Scanner can't reach Ollama

**Solution:**
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# If it works, Ollama is running
# Try the scan again
```

## Quick Commands

### Test example.com
```bash
./run.sh example.com xploiter/pentester:latest
```

### Test Web Security Academy Lab
```bash
./run.sh 0afe007a042f81858020b29d00550007.web-security-academy.net xploiter/pentester:latest
```

### Test with different model
```bash
# WhiteRabbitNeo (best quality)
./run.sh example.com "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"

# Deepseek (fast, lightweight)
./run.sh example.com deepseek-coder:1.3b
```

### Advanced mode (multi-request attacks)
```bash
./bin/smuggler \
  -target example.com \
  -ai \
  -ai-backend ollama \
  -ollama-model "xploiter/pentester:latest" \
  -advanced
```

### Change confidence threshold
```bash
./bin/smuggler \
  -target example.com \
  -ai \
  -ai-backend ollama \
  -ollama-model "xploiter/pentester:latest" \
  -confidence 0.75
```

## Project Structure

```
Project29/
├── smuggler/
│   ├── bin/
│   │   └── smuggler.exe (or smuggler on Mac/Linux)
│   ├── cmd/
│   │   └── main.go (CLI entry point)
│   ├── internal/
│   │   ├── ai/
│   │   │   ├── provider.go (interface)
│   │   │   ├── analyzer.go (OpenAI)
│   │   │   └── ollama.go (Ollama)
│   │   ├── sender/
│   │   ├── payload/
│   │   ├── baseline/
│   │   ├── detector/
│   │   ├── scanner/
│   │   └── models/
│   ├── run.bat (Windows launcher)
│   ├── run.sh (Mac/Linux launcher)
│   └── go.mod
├── OLLAMA_INTEGRATION.md
├── AI_INTEGRATION.md
├── AI_QUICK_START.md
└── README.md
```

## What Each Component Does

1. **Sender** - Sends raw HTTP requests via TCP/TLS
2. **Payload Generator** - Creates CL.TE, TE.CL, Mixed-TE attack payloads
3. **Baseline Manager** - Captures normal server behavior for comparison
4. **Detector** - Analyzes responses for smuggling indicators
5. **AI Provider** - Feeds analysis to Ollama for expert interpretation
6. **Scanner** - Orchestrates entire workflow

## Performance Tips

### For Faster Scanning
```bash
# Use lighter model
./run.sh example.com deepseek-coder:1.3b

# Or reduce confidence (skips borderline cases)
./run.sh example.com xploiter/pentester:latest -confidence 0.7
```

### For Best Quality Analysis
```bash
# Use heavier model
./run.sh example.com "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"

# Or lower confidence (catches more cases)
./run.sh example.com xploiter/pentester:latest -confidence 0.4
```

## Next Steps

1. **Run your first scan:** `./run.sh example.com xploiter/pentester:latest`
2. **Check the output:** Review AI reasoning from pentester model
3. **Try different targets:** Test against your targets
4. **Experiment with models:** Compare quality/speed of different models

---

## Commands Quick Reference

| Task | Windows | Mac/Linux |
|------|---------|-----------|
| Build | `go build -o bin\smuggler.exe .\cmd\main.go` | `go build -o bin/smuggler ./cmd/main.go` |
| Run | `run.bat example.com xploiter/pentester:latest` | `./run.sh example.com xploiter/pentester:latest` |
| Update | `git pull` | `git pull` |
| Check Ollama | `curl http://localhost:11434/api/tags` | `curl http://localhost:11434/api/tags` |

Enjoy scanning! 🔥
