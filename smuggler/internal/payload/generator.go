package payload

import (
	"fmt"
	"strings"
)

// Generator builds raw HTTP payloads for request smuggling detection.
// It focuses on crafting malformed requests that expose parser desynchronization.
type Generator struct {
	host    string
	port    int
	method  string
	path    string
	headers map[string]string
}

// NewGenerator creates a new payload generator for a target.
func NewGenerator(host string, port int) *Generator {
	return &Generator{
		host:    host,
		port:    port,
		method:  "GET",
		path:    "/",
		headers: make(map[string]string),
	}
}

// SetMethod sets the HTTP method for generated payloads.
func (g *Generator) SetMethod(method string) *Generator {
	g.method = method
	return g
}

// SetPath sets the request path.
func (g *Generator) SetPath(path string) *Generator {
	g.path = path
	return g
}

// AddHeader adds a custom header to the request.
func (g *Generator) AddHeader(key, value string) *Generator {
	g.headers[key] = value
	return g
}

// buildBaseRequest builds the foundation HTTP request without body manipulation.
// This is reusable by all payload generators.
func (g *Generator) buildBaseRequest() string {
	var buf strings.Builder

	// Request line
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", g.method, g.path))

	// Host header (mandatory)
	buf.WriteString(fmt.Sprintf("Host: %s:%d\r\n", g.host, g.port))

	// Custom headers
	for key, value := range g.headers {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	return buf.String()
}

// GenerateCLTEPayload generates a CL.TE (Content-Length / Transfer-Encoding) payload.
// CL.TE is designed to desynchronize servers where the proxy trusts Content-Length
// and the backend trusts Transfer-Encoding (chunked).
func (g *Generator) GenerateCLTEPayload(smoggledBody string) (string, error) {
	if smoggledBody == "" {
		return "", fmt.Errorf("smuggled body cannot be empty")
	}

	return GenerateCLTE(g.buildBaseRequest(), smoggledBody), nil
}

// GenerateTECLPayload generates a TE.CL (Transfer-Encoding / Content-Length) payload.
// TE.CL is designed to desynchronize servers where the proxy trusts Transfer-Encoding
// and the backend trusts Content-Length.
func (g *Generator) GenerateTECLPayload(smoggledBody string) (string, error) {
	if smoggledBody == "" {
		return "", fmt.Errorf("smuggled body cannot be empty")
	}

	return GenerateTECL(g.buildBaseRequest(), smoggledBody), nil
}

// GenerateBaseline generates a normal request with no smuggling attempt.
// Use this for establishing baseline behavior.
func (g *Generator) GenerateBaseline() string {
	var buf strings.Builder
	buf.WriteString(g.buildBaseRequest())
	buf.WriteString("Connection: close\r\n")
	buf.WriteString("\r\n")
	return buf.String()
}
