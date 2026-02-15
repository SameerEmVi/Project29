#!/bin/bash

# HTTP Request Smuggling Scanner - Local Runner with Ollama
# Run this from the smuggler directory

echo ""
echo "============================================================"
echo "HTTP Request Smuggling Scanner - Local Test with Ollama"
echo "============================================================"
echo ""

# Check if binary exists
if [ ! -f "bin/smuggler" ]; then
    echo "[!] Binary not found. Building..."
    go build -o bin/smuggler ./cmd/main.go
    if [ $? -ne 0 ]; then
        echo "[!] Build failed!"
        exit 1
    fi
fi

echo "[+] Scanner binary ready: bin/smuggler"
echo "[+] Ollama models configured:"
echo "    - xploiter/pentester:latest (recommended)"
echo "    - WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"
echo "    - deepseek-coder:1.3b"
echo ""

# Get URL from command line or use default
if [ -z "$1" ]; then
    TARGET="example.com"
    PORT=80
    HTTPS_FLAGS=""
    echo "[*] No target specified. Using default: example.com"
    echo ""
    echo "Usage: ./run.sh [url] [model]"
    echo "Example: ./run.sh 'example.com' 'xploiter/pentester:latest'"
    echo ""
else
    TARGET="$1"
    PORT=443
    HTTPS_FLAGS="-https -insecure"
    echo "[+] Target: $TARGET"
    echo ""
fi

# Get model or use default
if [ -z "$2" ]; then
    MODEL="xploiter/pentester:latest"
else
    MODEL="$2"
fi

echo "[+] Using model: $MODEL"
echo ""
echo "============================================================"
echo "Starting scan..."
echo "============================================================"
echo ""

# Run the scanner
./bin/smuggler \
    -target "$TARGET" \
    -port $PORT \
    $HTTPS_FLAGS \
    -ai \
    -ai-backend ollama \
    -ollama-model "$MODEL" \
    -v

echo ""
echo "============================================================"
echo "Scan complete!"
echo "============================================================"
