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

type OllamaAnalyzer struct {
	endpoint string
	model    string
	client   *http.Client
}

func NewOllamaAnalyzer(endpoint, model string) *OllamaAnalyzer {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama2"
	}

	return &OllamaAnalyzer{
		endpoint: endpoint,
		model:    model,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (o *OllamaAnalyzer) Name() string {
	return fmt.Sprintf("Ollama (%s)", o.model)
}

// ---------- PUBLIC ----------

func (o *OllamaAnalyzer) AnalyzeResponses(
	ctx context.Context,
	baseline, testResponse map[string]interface{},
	testType string,
) (*AnalysisResult, error) {

	prompt := fmt.Sprintf(`You are a security expert analyzing HTTP responses for request smuggling vulnerabilities.

Test Type: %s
Baseline: Status=%v, Body=%v bytes
Test Response: Status=%v, Body=%v bytes

Output ONLY valid JSON.`,
		testType,
		baseline["status"], baseline["body_len"],
		testResponse["status"], testResponse["body_len"])

	result := &AnalysisResult{}
	err := o.callOllamaJSON(prompt, result)
	return result, err
}

func (o *OllamaAnalyzer) SuggestPayloads(
	ctx context.Context,
	targetInfo map[string]string,
	previousResults map[string]interface{},
) ([]*PayloadSuggestion, error) {

	prompt := fmt.Sprintf(
		`Suggest HTTP Request Smuggling payloads.
Target: %v
Previous Results: %v
Output JSON array only.`,
		targetInfo, previousResults,
	)

	var out []*PayloadSuggestion
	err := o.callOllamaJSON(prompt, &out)
	return out, err
}

func (o *OllamaAnalyzer) GenerateReport(
	ctx context.Context,
	scanResults map[string]interface{},
	allResponses []map[string]interface{},
) (string, error) {

	prompt := fmt.Sprintf(
		`Create a brief security assessment for HTTP Request Smuggling scan: %v`,
		scanResults,
	)

	return o.callOllamaString(prompt)
}

func (o *OllamaAnalyzer) IdentifyTechnique(
	ctx context.Context,
	allTestResults map[string]map[string]interface{},
) (string, float64, error) {

	prompt := fmt.Sprintf(
		`Identify most likely request smuggling technique.
Results: %v
Return JSON only: {"most_likely_technique":"CL.TE","confidence":0.85}`,
		allTestResults,
	)

	type Result struct {
		Technique  string  `json:"most_likely_technique"`
		Confidence float64 `json:"confidence"`
	}

	r := &Result{}
	err := o.callOllamaJSON(prompt, r)
	if err != nil {
		return "", 0, err
	}

	return r.Technique, r.Confidence, nil
}

// ---------- CORE ----------

func (o *OllamaAnalyzer) callOllamaJSON(prompt string, dest interface{}) error {

	raw, err := o.callOllama(prompt)
	if err != nil {
		return err
	}

	raw = extractJSON(raw)
	raw = cleanupJSON(raw)

	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return fmt.Errorf("failed to parse JSON from Ollama: %w\nResponse: %s", err, raw)
	}

	return nil
}

func (o *OllamaAnalyzer) callOllamaString(prompt string) (string, error) {
	return o.callOllama(prompt)
}

func (o *OllamaAnalyzer) callOllama(prompt string) (string, error) {

	payload := map[string]interface{}{
		"model":  o.model,
		"prompt": prompt,
		"stream": false,
	}

	data, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/api/generate", o.endpoint)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Ollama: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama API error %d: %s",
			resp.StatusCode, string(body))
	}

	var apiResp struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse Ollama response: %w", err)
	}

	if apiResp.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", apiResp.Error)
	}

	return apiResp.Response, nil
}

// ---------- HELPERS ----------

// extracts first balanced JSON block
func extractJSON(input string) string {

	input = strings.TrimSpace(input)
	input = strings.TrimPrefix(input, "```json")
	input = strings.TrimPrefix(input, "```")
	input = strings.TrimSuffix(input, "```")

	start := strings.IndexAny(input, "{[")
	if start == -1 {
		return input
	}

	depth := 0

	for i := start; i < len(input); i++ {
		switch input[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return input[start : i+1]
			}
		}
	}

	return input[start:]
}

// removes trailing commas safely
func cleanupJSON(s string) string {

	var out []byte
	inString := false
	escape := false

	for i := 0; i < len(s); i++ {
		ch := s[i]

		if ch == '"' && !escape {
			inString = !inString
		}

		if ch == '\\' && inString {
			escape = !escape
		} else {
			escape = false
		}

		if !inString && ch == ',' {
			j := i + 1
			for j < len(s) &&
				(s[j] == ' ' || s[j] == '\n' ||
					s[j] == '\t' || s[j] == '\r') {
				j++
			}
			if j < len(s) &&
				(s[j] == '}' || s[j] == ']') {
				continue
			}
		}

		out = append(out, ch)
	}

	return string(out)
}
