package ai

import (
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type AIAnalyzer struct {
	apiKey string
	model  string
	client *http.Client
}

type AnalysisResult struct {
	IsVulnerable      bool     `json:"is_vulnerable"`
	Techniques        []string `json:"techniques"`
	Confidence        float64  `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	SuspiciousSignals []string `json:"suspicious_signals"`
	Recommendations   []string `json:"recommendations"`
}

type PayloadSuggestion struct {
	Technique       string `json:"technique"`
	Description     string `json:"description"`
	PayloadStrategy string `json:"payload_strategy"`
	Priority        string `json:"priority"`
	Rationale       string `json:"rationale"`
}

func NewAIAnalyzer(apiKey string) *AIAnalyzer {
	return &AIAnalyzer{
		apiKey: apiKey,
		model:  "gpt-3.5-turbo",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (a *AIAnalyzer) Name() string {
	return "OpenAI"
}

// ---------- PUBLIC METHODS ----------

func (a *AIAnalyzer) AnalyzeResponses(
	ctx context.Context,
	baseline, testResponse map[string]interface{},
	testType string,
) (*AnalysisResult, error) {

	prompt := fmt.Sprintf(
		`Analyze if these HTTP responses indicate request smuggling:

Test: %s
Baseline Status: %v, Body: %v bytes
Test Status: %v, Body: %v bytes

Respond with valid JSON only:
{"is_vulnerable": bool, "techniques": [], "confidence": 0.0, "reasoning": "", "suspicious_signals": [], "recommendations": []}`,
		testType,
		baseline["status"], baseline["body_len"],
		testResponse["status"], testResponse["body_len"],
	)

	result := &AnalysisResult{}
	err := a.callOpenAIJSON(prompt, result)
	return result, err
}

func (a *AIAnalyzer) SuggestPayloads(
	ctx context.Context,
	targetInfo map[string]string,
	previousResults map[string]interface{},
) ([]*PayloadSuggestion, error) {

	prompt := fmt.Sprintf(
		`Given target %v and previous results %v, suggest the top 2 HTTP Request Smuggling attack payloads.
Respond with JSON array only.`,
		targetInfo, previousResults,
	)

	var out []*PayloadSuggestion
	err := a.callOpenAIJSON(prompt, &out)
	return out, err
}

func (a *AIAnalyzer) GenerateReport(
	ctx context.Context,
	scanResults map[string]interface{},
	allResponses []map[string]interface{},
) (string, error) {

	prompt := fmt.Sprintf(
		`Create a brief security assessment for HTTP Request Smuggling scan: %v`,
		scanResults,
	)

	return a.callOpenAIString(prompt)
}

func (a *AIAnalyzer) IdentifyTechnique(
	ctx context.Context,
	allTestResults map[string]map[string]interface{},
) (string, float64, error) {

	prompt := fmt.Sprintf(
		`Based on test results %v, identify the most likely smuggling technique.
Respond with JSON only: {"most_likely_technique":"CL.TE","confidence":0.85}`,
		allTestResults,
	)

	type Result struct {
		Technique  string  `json:"most_likely_technique"`
		Confidence float64 `json:"confidence"`
	}

	r := &Result{}
	err := a.callOpenAIJSON(prompt, r)
	if err != nil {
		return "", 0, err
	}

	return r.Technique, r.Confidence, nil
}

// ---------- INTERNAL CORE ----------

func (a *AIAnalyzer) callOpenAIJSON(prompt string, dest interface{}) error {

	raw, err := a.callOpenAI(prompt, true)
	if err != nil {
		return err
	}

	raw = cleanJSON(raw)

	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return fmt.Errorf("failed to parse AI JSON: %w", err)
	}

	return nil
}

func (a *AIAnalyzer) callOpenAIString(prompt string) (string, error) {
	return a.callOpenAI(prompt, false)
}

func (a *AIAnalyzer) callOpenAI(prompt string, strictJSON bool) (string, error) {

	if a.apiKey == "" {
		return "", fmt.Errorf("missing API key")
	}

	systemMsg := "You are a security analyst."
	if strictJSON {
		systemMsg = "You are a security analyst. Respond with valid JSON only."
	}

	payload := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemMsg},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.3,
		"max_tokens":  700,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(
		"POST",
		"https://api.openai.com/v1/chat/completions",
		bytes.NewReader(data),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to decode API response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("no AI response")
	}

	return apiResp.Choices[0].Message.Content, nil
}

// ---------- HELPERS ----------

// removes ```json wrappers
func cleanJSON(in string) string {
	in = strings.TrimSpace(in)

	in = strings.TrimPrefix(in, "```json")
	in = strings.TrimPrefix(in, "```")
	in = strings.TrimSuffix(in, "```")

	return strings.TrimSpace(in)
}
