package ai

// Provider is an interface for different AI backends (OpenAI, Ollama, etc.)
type Provider interface {
	// AnalyzeResponses analyzes HTTP responses for smuggling patterns
	AnalyzeResponses(baseline, testResponse map[string]interface{}, testType string) (*AnalysisResult, error)

	// SuggestPayloads recommends attack payloads based on results
	SuggestPayloads(targetInfo map[string]string, previousResults map[string]interface{}) ([]*PayloadSuggestion, error)

	// GenerateReport creates a detailed vulnerability report
	GenerateReport(scanResults map[string]interface{}, allResponses []map[string]interface{}) (string, error)

	// IdentifyTechnique determines the most likely smuggling method
	IdentifyTechnique(allTestResults map[string]map[string]interface{}) (string, float64, error)

	// Name returns the provider name for logging
	Name() string
}

// Ensure both implementations satisfy the interface
var (
	_ Provider = (*AIAnalyzer)(nil)
	_ Provider = (*OllamaAnalyzer)(nil)
)
