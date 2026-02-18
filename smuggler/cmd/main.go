package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"smuggler/internal/ai"
	"smuggler/internal/scanner"
)

func main() {
	// Command-line flags
	target := flag.String("target", "", "Target host or URL to scan (e.g. example.com or https://example.com:8443)")
	targets := flag.String("targets", "", "Comma-separated list of targets (hostnames or URLs)")
	inputFile := flag.String("input-file", "", "Path to file containing targets (one per line)")
	port := flag.Int("port", 443, "Target port")
	confidence := flag.Float64("confidence", 0.5, "Minimum confidence threshold (0.0-1.0)")
	https := flag.Bool("https", false, "Use HTTPS/TLS connection")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (for lab/testing only)")
	verbose := flag.Bool("v", false, "Verbose output")
	_ = flag.Bool("advanced", false, "(deprecated)")
	
	// AI flags
	useAI := flag.Bool("ai", false, "Enable AI-powered analysis")
	aiBackend := flag.String("ai-backend", "openai", "AI backend: openai or ollama")
	apiKey := flag.String("api-key", "", "OpenAI API key for AI analysis")
	ollamaEndpoint := flag.String("ollama-endpoint", "http://localhost:11434", "Ollama API endpoint")
	ollamaModel := flag.String("ollama-model", "llama2", "Ollama model name (llama2, mistral, neural-chat, etc.)")

	flag.Parse()

	// Gather targets list
	var targetList []string

	// Prefer explicit -target, then -targets, then -input-file, then positional args
	if *target != "" {
		targetList = append(targetList, *target)
	}
	if *targets != "" {
		for _, t := range strings.Split(*targets, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targetList = append(targetList, t)
			}
		}
	}
	if *inputFile != "" {
		f, err := os.Open(*inputFile)
		if err != nil {
			log.Fatalf("failed to open input file: %v", err)
		}
		defer f.Close()
		scannerFile := bufio.NewScanner(f)
		for scannerFile.Scan() {
			line := strings.TrimSpace(scannerFile.Text())
			if line != "" {
				targetList = append(targetList, line)
			}
		}
		if err := scannerFile.Err(); err != nil {
			log.Fatalf("error reading input file: %v", err)
		}
	}

	// Positional args are also treated as targets
	for _, a := range flag.Args() {
		a = strings.TrimSpace(a)
		if a != "" {
			targetList = append(targetList, a)
		}
	}

	if len(targetList) == 0 {
		log.Fatal("No targets provided. Use -target, -targets, -input-file, or pass targets as arguments")
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("Port must be between 1 and 65535")
	}

	if *confidence < 0 || *confidence > 1 {
		log.Fatal("Confidence threshold must be between 0.0 and 1.0")
	}

	var aiProvider ai.Provider
	if *useAI {
		if *aiBackend == "openai" {
			if *apiKey == "" {
				*apiKey = os.Getenv("OPENAI_API_KEY")
			}
			if *apiKey == "" {
				log.Fatal("OpenAI backend requires -api-key or OPENAI_API_KEY environment variable")
			}
			aiProvider = ai.NewAIAnalyzer(*apiKey)
		} else if *aiBackend == "ollama" {
			aiProvider = ai.NewOllamaAnalyzer(*ollamaEndpoint, *ollamaModel)
		} else {
			log.Fatalf("Unknown AI backend: %s (use 'openai' or 'ollama')", *aiBackend)
		}
	}

	// Helper to normalize target strings into host:port and tls decision
	normalize := func(raw string) (string, int, bool, error) {
		// Trim surrounding whitespace and trailing slash
		raw = strings.TrimSpace(raw)
		raw = strings.TrimSuffix(raw, "/")

		// If it looks like a URL, parse it
		if strings.Contains(raw, "://") {
			u, err := url.Parse(raw)
			if err != nil {
				return "", 0, false, err
			}
			host := u.Host
			useTLS := u.Scheme == "https"
			h, p, err := net.SplitHostPort(host)
			if err == nil {
				pi, _ := strconv.Atoi(p)
				return h, pi, useTLS, nil
			}
			// no explicit port
			if h == "" {
				h = host
			}
			if useTLS {
				return h, 443, true, nil
			}
			return h, 80, false, nil
		}

		// Raw host, maybe with :port
		if strings.Contains(raw, ":") {
			h, p, err := net.SplitHostPort(raw)
			if err == nil {
				pi, err := strconv.Atoi(p)
				if err != nil {
					return "", 0, false, err
				}
				// heuristics: if port == 443 assume TLS
				useTLS := pi == 443
				return h, pi, useTLS, nil
			}
		}

		// Default port/transport from flags
		if *port == 443 || *https {
			return raw, 443, true, nil
		}
		return raw, *port, *https, nil
	}

	if *verbose {
		fmt.Printf("[+] Confidence threshold: %.1f%%\n", *confidence*100)
		if *https {
			fmt.Printf("[+] Using HTTPS/TLS\n")
			if *insecure {
				fmt.Printf("[+] WARNING: TLS certificate verification disabled\n")
			}
		}
        
		if *useAI && aiProvider != nil {
			fmt.Printf("[+] AI-powered analysis enabled: %s\n", aiProvider.Name())
		}
		fmt.Println()
	}

	// Iterate targets sequentially
	for _, raw := range targetList {
		host, p, useTLS, err := normalize(raw)
		if err != nil {
			log.Printf("[!] Skipping target %s: normalization error: %v", raw, err)
			continue
		}

		if *verbose {
			fmt.Printf("\n============================================================\n")
			fmt.Printf("Scanning target: %s (port: %d, tls: %t)\n", host, p, useTLS)
			fmt.Printf("============================================================\n")
		}

		// Use temporary variables for this iteration
		t := host
		pp := p
		thttps := useTLS

		if err := scanner.RunFullScan(t, pp, thttps, *insecure, *confidence, aiProvider); err != nil {
			log.Fatalf("[!] Scan failed for %s: %v", t, err)
		}
	}
}




