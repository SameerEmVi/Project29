package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"smuggler/internal/ai"
	"smuggler/internal/scanner"
)

func main() {
	// Command-line flags
	target := flag.String("target", "example.com", "Target host to scan")
	port := flag.Int("port", 80, "Target port")
	confidence := flag.Float64("confidence", 0.5, "Minimum confidence threshold (0.0-1.0)")
	https := flag.Bool("https", false, "Use HTTPS/TLS connection")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (for lab/testing only)")
	verbose := flag.Bool("v", false, "Verbose output")
	advanced := flag.Bool("advanced", false, "Use advanced multi-request detection (for GPOST attacks)")
	
	// AI flags
	useAI := flag.Bool("ai", false, "Enable AI-powered analysis")
	aiBackend := flag.String("ai-backend", "openai", "AI backend: openai or ollama")
	apiKey := flag.String("api-key", "", "OpenAI API key for AI analysis")
	ollamaEndpoint := flag.String("ollama-endpoint", "http://localhost:11434", "Ollama API endpoint")
	ollamaModel := flag.String("ollama-model", "llama2", "Ollama model name (llama2, mistral, neural-chat, etc.)")

	flag.Parse()

	// Validate inputs
	if *target == "" {
		log.Fatal("Target cannot be empty")
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("Port must be between 1 and 65535")
	}

	if *confidence < 0 || *confidence > 1 {
		log.Fatal("Confidence threshold must be between 0.0 and 1.0")
	}

	// Setup AI provider if enabled
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

	// Auto-detect HTTPS if port is 443
	if *port == 443 && !*https {
		*https = true
	}

	if *verbose {
		fmt.Printf("[+] Confidence threshold: %.1f%%\n", *confidence*100)
		if *https {
			fmt.Printf("[+] Using HTTPS/TLS\n")
			if *insecure {
				fmt.Printf("[+] WARNING: TLS certificate verification disabled\n")
			}
		}
		if *advanced {
			fmt.Printf("[+] Using advanced multi-request scanner\n")
		}
		if *useAI && aiProvider != nil {
			fmt.Printf("[+] AI-powered analysis enabled: %s\n", aiProvider.Name())
		}
		fmt.Println()
	}

	// Choose scanner mode
	if *advanced {
		runAdvancedScanner(target, port, confidence, https, insecure, aiProvider)
	} else {
		runStandardScanner(target, port, confidence, https, insecure, aiProvider)
	}
}

func runStandardScanner(target *string, port *int, confidence *float64, https *bool, insecure *bool, aiProvider ai.Provider) {
	// PHASE 5: SCANNER ENGINE
	// Create and configure scanner
	s := scanner.NewScanner(*target, *port)
	s.SetConfidenceThreshold(*confidence)

	if *https {
		s.SetTLS(true)
		if *insecure {
			s.SetInsecureTLS(true)
		}
	}

	// Set AI provider if enabled
	if aiProvider != nil {
		s.SetAIProvider(aiProvider)
	}

	// Run the full scan
	if err := s.Run(); err != nil {
		log.Fatalf("[!] Scan failed: %v\n", err)
	}

	// Print the report
	s.PrintReport()

	// Print summary
	fmt.Printf("\n%s\n", s.Summary())

	// Exit with appropriate code
	if s.IsVulnerable() {
		fmt.Println("\n[!] VULNERABLE SERVER DETECTED")
		fmt.Printf("[!] Most likely technique: %s\n", s.GetMostLikelyTechnique())
	} else {
		fmt.Println("\n[✓] No vulnerabilities detected")
	}
}

func runAdvancedScanner(target *string, port *int, confidence *float64, https *bool, insecure *bool, aiProvider ai.Provider) {
	// Advanced multi-request scanner
	s := scanner.NewAdvancedScanner(*target, *port)
	s.SetConfidenceThreshold(*confidence)

	if *https {
		s.SetTLS(true)
		if *insecure {
			s.SetInsecureTLS(true)
		}
	}

	// Set AI provider if enabled
	if aiProvider != nil {
		s.SetAIProvider(aiProvider)
	}

	// Run the advanced scan
	if err := s.Run(); err != nil {
		log.Fatalf("[!] Scan failed: %v\n", err)
	}

	// Print the report
	s.PrintReport()

	// Print summary
	fmt.Printf("\n%s\n", s.Summary())

	// Exit with appropriate code
	if s.IsVulnerable() {
		fmt.Println("\n[!] VULNERABLE SERVER DETECTED")
		fmt.Printf("[!] Most likely technique: %s\n", s.GetMostLikelyTechnique())
	} else {
		fmt.Println("\n[✓] No confirmed vulnerabilities")
	}
}
