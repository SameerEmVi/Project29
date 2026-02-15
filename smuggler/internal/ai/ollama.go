package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OllamaAnalyzer handles Ollama (local LLM) integration for intelligent analysis
type OllamaAnalyzer struct {
	endpoint string // e.g., "http://localhost:11434"
	model    string // e.g., "llama2", "mistral", "neural-chat"
}

// NewOllamaAnalyzer creates a new Ollama analyzer
func NewOllamaAnalyzer(endpoint, model string) *OllamaAnalyzer {
	if endpoint == "" {
		endpoint = "http://localhost:11434" // Ollama default
	}
	if model == "" {
		model = "llama2" // Ollama default model
	}
	return &OllamaAnalyzer{
		endpoint: endpoint,
		model:    model,
	}
}

// Name returns the provider name
func (o *OllamaAnalyzer) Name() string {
	return fmt.Sprintf("Ollama (%s)", o.model)
}

// AnalyzeResponses uses Ollama to identify smuggling patterns
func (o *OllamaAnalyzer) AnalyzeResponses(baseline, testResponse map[string]interface{}, testType string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`You are a security expert analyzing HTTP responses for request smuggling vulnerabilities.

Test Type: %s
Baseline: Status=%v, Body=%v bytes
Test Response: Status=%v, Body=%v bytes

Output ONLY this exact JSON format (no markdown, no code blocks, no explanation, no comments):
{
"is_vulnerable": true,
"techniques": ["CL.TE"],
"confidence": 0.75,
"reasoning": "Explanation here",
"suspicious_signals": ["signal1", "signal2"],
"recommendations": ["action1", "action2"]
}`,
		testType,
		baseline["status"], baseline["body_len"],
		testResponse["status"], testResponse["body_len"])

	result := &AnalysisResult{}
	if err := o.callOllama(prompt, result); err != nil {
		return nil, err
	}

	return result, nil
}

// SuggestPayloads uses Ollama to recommend attack strategies
func (o *OllamaAnalyzer) SuggestPayloads(targetInfo map[string]string, previousResults map[string]interface{}) ([]*PayloadSuggestion, error) {
	prompt := fmt.Sprintf(`You are a penetration testing expert. Suggest HTTP Request Smuggling attack payloads.
Target: %v
Previous Results: %v

Output ONLY this exact JSON format (no markdown, no code blocks, no explanation, no comments):
[
{"technique": "CL.TE", "description": "Content-Length vs Transfer-Encoding", "payload_strategy": "strategy_here", "priority": "high", "rationale": "rationale_here"}
]`,
		targetInfo, previousResults)

	var suggestions []*PayloadSuggestion
	if err := o.callOllama(prompt, &suggestions); err != nil {
		return nil, err
	}

	return suggestions, nil
}

// GenerateReport uses Ollama to create a detailed vulnerability report
func (o *OllamaAnalyzer) GenerateReport(scanResults map[string]interface{}, allResponses []map[string]interface{}) (string, error) {
	prompt := fmt.Sprintf(`Create a brief security assessment for HTTP Request Smuggling vulnerability scan.
Results: %v

Provide a concise report focusing on findings and recommendations.`, scanResults)

	return o.callOllamaString(prompt)
}

// IdentifyTechnique uses Ollama to determine most likely smuggling method
func (o *OllamaAnalyzer) IdentifyTechnique(allTestResults map[string]map[string]interface{}) (string, float64, error) {
	prompt := fmt.Sprintf(`Analyze HTTP Request Smuggling test results and identify the most likely vulnerability technique.
Results: %v

Output ONLY this exact JSON (no markdown, no code blocks, no explanation, no comments):
{"most_likely_technique": "CL.TE", "confidence": 0.85}`, allTestResults)

	type Result struct {
		Technique  string  `json:"most_likely_technique"`
		Confidence float64 `json:"confidence"`
	}

	result := &Result{}
	if err := o.callOllama(prompt, result); err != nil {
		return "", 0, err
	}

	return result.Technique, result.Confidence, nil
}

// cleanupJSON removes common formatting issues from LLM-generated JSON
// Handles: comments, trailing commas, extra whitespace
func cleanupJSON(jsonStr string) string {
	var result []byte
	inString := false
	escape := false

	for i := 0; i < len(jsonStr); i++ {
		ch := jsonStr[i]

		// Track if we're inside a string
		if ch == '"' && !escape {
			inString = !inString
			result = append(result, ch)
			escape = false
			continue
		}

		// Handle escape sequences
		if ch == '\\' && inString {
			escape = !escape
			result = append(result, ch)
			continue
		}
		escape = false

		// Skip comments outside strings (// style)
		if !inString && ch == '/' && i+1 < len(jsonStr) && jsonStr[i+1] == '/' {
			// Skip until end of line
			for i < len(jsonStr) && jsonStr[i] != '\n' {
				i++
			}
			continue
		}

		// Skip C-style comments /* */
		if !inString && ch == '/' && i+1 < len(jsonStr) && jsonStr[i+1] == '*' {
			i += 2
			for i < len(jsonStr)-1 {
				if jsonStr[i] == '*' && jsonStr[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		// Remove trailing commas before } or ]
		if ch == ',' {
			// Look ahead for closing bracket
			j := i + 1
			for j < len(jsonStr) && (jsonStr[j] == ' ' || jsonStr[j] == '\n' || jsonStr[j] == '\t' || jsonStr[j] == '\r') {
				j++
			}
			if j < len(jsonStr) && (jsonStr[j] == '}' || jsonStr[j] == ']') {
				// Skip this comma
				continue
			}
		}

		result = append(result, ch)
	}

	return string(result)
}

// callOllama makes a request to Ollama API and parses JSON response
func (o *OllamaAnalyzer) callOllama(prompt string, dest interface{}) error {
	payload := map[string]interface{}{
		"model":  o.model,
		"prompt": prompt,
		"stream": false,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Ollama API endpoint
	url := fmt.Sprintf("%s/api/generate", o.endpoint)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to connect to Ollama at %s: %w", o.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Ollama API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse Ollama response: %w", err)
	}

	if apiResp.Error != "" {
		return fmt.Errorf("Ollama error: %s", apiResp.Error)
	}

	// Extract JSON from response
	content := apiResp.Response
	
	// Try to find JSON in the response
	startIdx := -1
	for i := 0; i < len(content); i++ {
		if content[i] == '{' || content[i] == '[' {
			startIdx = i
			break
		}
	}

	if startIdx == -1 {
		return fmt.Errorf("no JSON found in Ollama response: %s", content)
	}

	jsonStr := content[startIdx:]
	
	// Clean up JSON: remove comments, trailing commas, etc.
	jsonStr = cleanupJSON(jsonStr)
	
	if err := json.Unmarshal([]byte(jsonStr), dest); err != nil {
		return fmt.Errorf("failed to parse JSON from Ollama: %w\nCleaned response: %s", err, jsonStr)
	}

	return nil
}

// callOllamaString makes a request and returns raw string response
func (o *OllamaAnalyzer) callOllamaString(prompt string) (string, error) {
	payload := map[string]interface{}{
		"model":  o.model,
		"prompt": prompt,
		"stream": false,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Ollama API endpoint
	url := fmt.Sprintf("%s/api/generate", o.endpoint)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to connect to Ollama at %s: %w", o.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to parse Ollama response: %w", err)
	}

	if apiResp.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", apiResp.Error)
	}

	return apiResp.Response, nil
}
