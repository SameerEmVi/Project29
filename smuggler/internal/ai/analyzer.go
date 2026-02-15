package ai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AIAnalyzer handles OpenAI integration for intelligent analysis
type AIAnalyzer struct {
	apiKey string
	model  string
}

// AnalysisResult contains AI's assessment of vulnerability
type AnalysisResult struct {
	IsVulnerable      bool     `json:"is_vulnerable"`
	Techniques        []string `json:"techniques"`
	Confidence        float64  `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	SuspiciousSignals []string `json:"suspicious_signals"`
	Recommendations   []string `json:"recommendations"`
}

// PayloadSuggestion contains AI-recommended attack payload
type PayloadSuggestion struct {
	Technique       string `json:"technique"`
	Description     string `json:"description"`
	PayloadStrategy string `json:"payload_strategy"`
	Priority        string `json:"priority"`
	Rationale       string `json:"rationale"`
}

// NewAIAnalyzer creates a new AI analyzer with OpenAI client
func NewAIAnalyzer(apiKey string) *AIAnalyzer {
	return &AIAnalyzer{
		apiKey: apiKey,
		model:  "gpt-3.5-turbo",
	}
}

// AnalyzeResponses uses AI to identify smuggling patterns
func (a *AIAnalyzer) AnalyzeResponses(baseline, testResponse map[string]interface{}, testType string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Analyze if these HTTP responses indicate request smuggling:

Test: %s
Baseline Status: %v, Body: %v bytes
Test Status: %v, Body: %v bytes

Respond with valid JSON only:
{"is_vulnerable": bool, "techniques": [], "confidence": 0.0, "reasoning": "", "suspicious_signals": [], "recommendations": []}`,
		testType,
		baseline["status"], baseline["body_len"],
		testResponse["status"], testResponse["body_len"])

	result := &AnalysisResult{}
	if err := a.callOpenAI(prompt, result); err != nil {
		return nil, err
	}

	return result, nil
}

// SuggestPayloads uses AI to recommend attack strategies
func (a *AIAnalyzer) SuggestPayloads(targetInfo map[string]string, previousResults map[string]interface{}) ([]*PayloadSuggestion, error) {
	prompt := fmt.Sprintf(`Given target %v and previous results %v, suggest the top 2 HTTP Request Smuggling attack payloads.
Respond with JSON array only: [{"technique": "", "description": "", "payload_strategy": "", "priority": "", "rationale": ""}]`,
		targetInfo, previousResults)

	var suggestions []*PayloadSuggestion
	if err := a.callOpenAI(prompt, &suggestions); err != nil {
		return nil, err
	}

	return suggestions, nil
}

// GenerateReport uses AI to create a detailed vulnerability report
func (a *AIAnalyzer) GenerateReport(scanResults map[string]interface{}, allResponses []map[string]interface{}) (string, error) {
	prompt := fmt.Sprintf(`Create a brief security assessment for HTTP Request Smuggling scan: %v`, scanResults)

	return a.callOpenAIString(prompt)
}

// IdentifyTechnique uses AI to determine most likely smuggling method
func (a *AIAnalyzer) IdentifyTechnique(allTestResults map[string]map[string]interface{}) (string, float64, error) {
	prompt := fmt.Sprintf(`Based on test results %v, identify the most likely smuggling technique.
Respond with JSON only: {"most_likely_technique": "CL.TE", "confidence": 0.85}`, allTestResults)

	type Result struct {
		Technique  string  `json:"most_likely_technique"`
		Confidence float64 `json:"confidence"`
	}

	result := &Result{}
	if err := a.callOpenAI(prompt, result); err != nil {
		return "", 0, err
	}

	return result.Technique, result.Confidence, nil
}

// callOpenAI makes a request to OpenAI API and parses JSON response
func (a *AIAnalyzer) callOpenAI(prompt string, dest interface{}) error {
	payload := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a security analyst. Respond with valid JSON only.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.3,
		"max_tokens":  500,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(string(data)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %w", err)
	}

	if apiResp.Error.Message != "" {
		return fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return fmt.Errorf("no response from AI")
	}

	content := apiResp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), dest); err != nil {
		return fmt.Errorf("failed to parse AI response: %w", err)
	}

	return nil
}

// callOpenAIString makes a request and returns raw string response
func (a *AIAnalyzer) callOpenAIString(prompt string) (string, error) {
	payload := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a security expert.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.5,
		"max_tokens":  1000,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(string(data)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	if apiResp.Error.Message != "" {
		return "", fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("no response from AI")
	}

	return apiResp.Choices[0].Message.Content, nil
}
