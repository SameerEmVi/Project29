package ai

import "context"

// Provider defines a common interface for AI backends
// (OpenAI, Ollama, future local models, etc.)
type Provider interface {

	// AnalyzeResponses analyzes HTTP responses for smuggling patterns.
	AnalyzeResponses(
		ctx context.Context,
		baseline, testResponse map[string]interface{},
		testType string,
	) (*AnalysisResult, error)

	// SuggestPayloads recommends attack payload strategies.
	SuggestPayloads(
		ctx context.Context,
		targetInfo map[string]string,
		previousResults map[string]interface{},
	) ([]*PayloadSuggestion, error)

	// GenerateReport creates a vulnerability report.
	GenerateReport(
		ctx context.Context,
		scanResults map[string]interface{},
		allResponses []map[string]interface{},
	) (string, error)

	// IdentifyTechnique determines the most likely smuggling method.
	IdentifyTechnique(
		ctx context.Context,
		allTestResults map[string]map[string]interface{},
	) (string, float64, error)

	// Name returns provider name (for logging/debugging).
	Name() string
}

// Compile-time interface validation.
// Ensures implementations always satisfy Provider.
var (
	_ Provider = (*AIAnalyzer)(nil)
	_ Provider = (*OllamaAnalyzer)(nil)
)
