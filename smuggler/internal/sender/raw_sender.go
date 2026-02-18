package sender

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"smuggler/internal/models"
)

type RawSender struct {
	timeout     time.Duration
	readTimeout time.Duration
	useTLS      bool
	insecureTLS bool
}

func NewRawSender() *RawSender {
	return &RawSender{
		timeout:     10 * time.Second,
		readTimeout: 10 * time.Second,
	}
}

func NewRawSenderWithTimeout(timeout, readTimeout time.Duration) *RawSender {
	return &RawSender{
		timeout:     timeout,
		readTimeout: readTimeout,
	}
}

func (rs *RawSender) SetTLS(useTLS bool) *RawSender {
	rs.useTLS = useTLS
	return rs
}

func (rs *RawSender) SetInsecureTLS(insecure bool) *RawSender {
	rs.insecureTLS = insecure
	return rs
}

func (rs *RawSender) SendRequest(target string, payloadStr string) (*models.HTTPResponse, error) {
	startTime := time.Now()

	response := &models.HTTPResponse{
		Headers: make(map[string]string),
	}

	var conn net.Conn
	var err error

	if rs.useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: rs.insecureTLS,
			MinVersion:         tls.VersionTLS12,
		}

		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: rs.timeout},
			"tcp",
			target,
			tlsConfig,
		)
	} else {
		conn, err = net.DialTimeout("tcp", target, rs.timeout)
	}

	if err != nil {
		response.Error = fmt.Errorf("failed to connect to %s: %w", target, err)
		return response, response.Error
	}

	defer conn.Close()

	// Write request
	conn.SetWriteDeadline(time.Now().Add(rs.timeout))

	_, err = conn.Write([]byte(payloadStr))
	if err != nil {
		response.Error = fmt.Errorf("failed to send request: %w", err)
		return response, response.Error
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(rs.readTimeout))

	raw, readErr := readFullResponse(conn)
	response.Raw = raw
	response.TimingMS = time.Since(startTime).Milliseconds()

	if readErr != nil && readErr != io.EOF {
		// timeout = connection probably kept alive
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			response.ConnectionClosed = false
		} else {
			response.ConnectionClosed = true
		}
	}

	parseHTTPResponse(response)

	return response, nil
}

// reads until timeout/EOF safely
func readFullResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var buf strings.Builder
	tmp := make([]byte, 4096)

	for {
		n, err := reader.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}

		if err != nil {
			return buf.String(), err
		}
	}
}

// parseHTTPResponse parses raw HTTP response safely.
func parseHTTPResponse(response *models.HTTPResponse) {

	if response.Raw == "" {
		return
	}

	lines := strings.Split(response.Raw, "\r\n")
	if len(lines) == 0 {
		return
	}

	// status line
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &response.StatusCode)
	}

	headerEnd := -1

	for i := 1; i < len(lines); i++ {

		line := lines[i]

		if line == "" {
			headerEnd = i
			break
		}

		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])

		response.Headers[key] = val
	}

	if headerEnd != -1 && headerEnd+1 < len(lines) {
		response.Body = strings.Join(lines[headerEnd+1:], "\r\n")
	}
}
