package main

import (
	"flag"
	"fmt"
	"log"

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
		fmt.Println()
	}

	// Choose scanner mode
	if *advanced {
		runAdvancedScanner(target, port, confidence, https, insecure)
	} else {
		runStandardScanner(target, port, confidence, https, insecure)
	}
}

func runStandardScanner(target *string, port *int, confidence *float64, https *bool, insecure *bool) {
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

func runAdvancedScanner(target *string, port *int, confidence *float64, https *bool, insecure *bool) {
	// Advanced multi-request scanner
	s := scanner.NewAdvancedScanner(*target, *port)
	s.SetConfidenceThreshold(*confidence)

	if *https {
		s.SetTLS(true)
		if *insecure {
			s.SetInsecureTLS(true)
		}
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
