package sender

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"smuggler/internal/models"
)

// RawSender handles sending raw HTTP payloads over TCP and reading responses.
type RawSender struct {
	timeout     time.Duration
	readTimeout time.Duration
	useTLS      bool
	insecureTLS bool
}

// NewRawSender creates a new raw HTTP sender with default timeouts.
func NewRawSender() *RawSender {
	return &RawSender{
		timeout:     10 * time.Second,
		readTimeout: 10 * time.Second,
	}
}

// NewRawSenderWithTimeout creates a new raw HTTP sender with custom timeouts.
func NewRawSenderWithTimeout(timeout, readTimeout time.Duration) *RawSender {
	return &RawSender{
		timeout:     timeout,
		readTimeout: readTimeout,
	}
}

// SetTLS enables or disables TLS for connections.
func (rs *RawSender) SetTLS(useTLS bool) *RawSender {
	rs.useTLS = useTLS
	return rs
}

// SetInsecureTLS allows insecure TLS connections (skip certificate verification).
// Use only for testing/lab environments!
func (rs *RawSender) SetInsecureTLS(insecure bool) *RawSender {
	rs.insecureTLS = insecure
	return rs
}

// SendRequest sends a raw HTTP request to the target and returns the response.
// The payloadStr must be a complete, valid HTTP request with CRLF line endings.
// target should be in the format "host:port" (e.g., "example.com:80" or "example.com:443" for HTTPS).
func (rs *RawSender) SendRequest(target string, payloadStr string) (*models.HTTPResponse, error) {
	startTime := time.Now()
	response := &models.HTTPResponse{
		Headers: make(map[string]string),
	}

	// Establish connection (TCP or TLS)
	var conn net.Conn
	var err error

	if rs.useTLS {
		// TLS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: rs.insecureTLS,
		}
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: rs.timeout},
			"tcp",
			target,
			tlsConfig,
		)
	} else {
		// Plain TCP connection
		conn, err = net.DialTimeout("tcp", target, rs.timeout)
	}

	if err != nil {
		response.Error = fmt.Errorf("failed to connect to %s: %w", target, err)
		return response, response.Error
	}
	defer func() {
		// Check if connection was closed
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := conn.Read(make([]byte, 1))
		if err != nil && strings.Contains(err.Error(), "i/o timeout") {
			response.ConnectionClosed = true
		}
		conn.Close()
	}()

	// Set write timeout
	conn.SetWriteDeadline(time.Now().Add(rs.timeout))

	// Send raw payload
	_, err = conn.Write([]byte(payloadStr))
	if err != nil {
		response.Error = fmt.Errorf("failed to send request: %w", err)
		return response, response.Error
	}

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(rs.readTimeout))

	responseData, err := readFullResponse(conn)
	if err != nil {
		response.Error = fmt.Errorf("failed to read response: %w", err)
		response.Raw = responseData
		return response, response.Error
	}

	// Calculate timing
	response.TimingMS = time.Since(startTime).Milliseconds()
	response.Raw = responseData

	// Parse response
	parseHTTPResponse(response)

	return response, nil
}

// readFullResponse reads the complete HTTP response from the connection.
// It reads status line, headers, and body.
func readFullResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var responseBuf strings.Builder

	// Read until we've gotten headers and body
	// We'll read in chunks and try to detect end of response
	for {
		line, err := reader.ReadString('\n')
		responseBuf.WriteString(line)

		if err != nil && err.Error() != "EOF" {
			// Timeout or other error - return what we have
			return responseBuf.String(), nil
		}

		if err != nil && err.Error() == "EOF" {
			return responseBuf.String(), nil
		}
	}
}

// parseHTTPResponse parses the raw HTTP response into structured data.
func parseHTTPResponse(response *models.HTTPResponse) {
	lines := strings.Split(response.Raw, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse status line
	statusLine := lines[0]
	parts := strings.Fields(statusLine)
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &response.StatusCode)
	}

	// Parse headers
	var headerEndIdx int
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			headerEndIdx = i
			break
		}

		// Parse header
		if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			response.Headers[key] = value
		}
	}

	// Extract body (everything after the empty line)
	if headerEndIdx < len(lines) {
		bodyLines := lines[headerEndIdx+1:]
		response.Body = strings.Join(bodyLines, "\r\n")
	}
}
