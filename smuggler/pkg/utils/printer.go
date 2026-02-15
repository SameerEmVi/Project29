package utils

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io"
    "sort"
    "time"

    "smuggler/internal/models"
)

// WriteJSONLine marshals a single ScanResult as compact JSON and writes it
// followed by a newline (JSON-lines). It ensures error strings are captured.
func WriteJSONLine(w io.Writer, sr *models.ScanResult) error {
    if sr == nil {
        return nil
    }
    if sr.BaselineResponse != nil && sr.BaselineResponse.Error != nil {
        sr.BaselineResponse.ErrorString = sr.BaselineResponse.Error.Error()
    }
    if sr.TestResponse != nil && sr.TestResponse.Error != nil {
        sr.TestResponse.ErrorString = sr.TestResponse.Error.Error()
    }

    b, err := json.Marshal(sr)
    if err != nil {
        return err
    }
    // write with bufio to reduce syscalls
    bw := bufio.NewWriter(w)
    if _, err := bw.Write(b); err != nil {
        return err
    }
    if err := bw.WriteByte('\n'); err != nil {
        return err
    }
    return bw.Flush()
}

// WriteJSONLines writes multiple ScanResults as JSON-lines to the writer.
func WriteJSONLines(w io.Writer, results []*models.ScanResult) error {
    bw := bufio.NewWriter(w)
    for _, r := range results {
        if r == nil {
            continue
        }
        if r.BaselineResponse != nil && r.BaselineResponse.Error != nil {
            r.BaselineResponse.ErrorString = r.BaselineResponse.Error.Error()
        }
        if r.TestResponse != nil && r.TestResponse.Error != nil {
            r.TestResponse.ErrorString = r.TestResponse.Error.Error()
        }
        b, err := json.Marshal(r)
        if err != nil {
            return err
        }
        if _, err := bw.Write(b); err != nil {
            return err
        }
        if err := bw.WriteByte('\n'); err != nil {
            return err
        }
    }
    return bw.Flush()
}

// GroupByThread groups ScanResults by thread ID. Results without thread ID
// are grouped under the key "__no_thread".
func GroupByThread(results []*models.ScanResult) map[string][]*models.ScanResult {
    grouped := make(map[string][]*models.ScanResult)
    for _, r := range results {
        key := "__no_thread"
        if r != nil && r.Thread != nil && r.Thread.ID != "" {
            key = r.Thread.ID
        }
        grouped[key] = append(grouped[key], r)
    }
    return grouped
}

// SortedThreadKeys returns thread keys ordered by thread CreatedAt (oldest first).
// The special "__no_thread" key will appear last.
func SortedThreadKeys(grouped map[string][]*models.ScanResult) []string {
    type tinfo struct {
        key string
        at  time.Time
    }
    arr := make([]tinfo, 0, len(grouped))
    for k, v := range grouped {
        ti := tinfo{key: k}
        if k == "__no_thread" {
            ti.at = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
        } else if len(v) > 0 && v[0] != nil && v[0].Thread != nil {
            ti.at = v[0].Thread.CreatedAt
        }
        arr = append(arr, ti)
    }
    sort.Slice(arr, func(i, j int) bool { return arr[i].at.Before(arr[j].at) })
    keys := make([]string, 0, len(arr))
    for _, a := range arr {
        keys = append(keys, a.key)
    }
    return keys
}

// PrintGroupedHuman writes grouped ScanResults in a human-friendly way to w.
func PrintGroupedHuman(w io.Writer, grouped map[string][]*models.ScanResult) error {
    keys := SortedThreadKeys(grouped)
    for _, k := range keys {
        rs := grouped[k]
        if len(rs) == 0 {
            continue
        }
        // print header
        var header string
        if k == "__no_thread" {
            header = "No Thread"
        } else if rs[0] != nil && rs[0].Thread != nil {
            header = fmt.Sprintf("Thread: %s (id=%s created=%s)", rs[0].Thread.Name, rs[0].Thread.ID, rs[0].Thread.CreatedAt.Format(time.RFC3339))
        } else {
            header = fmt.Sprintf("Thread: %s", k)
        }
        if _, err := fmt.Fprintln(w, header); err != nil {
            return err
        }
        for _, r := range rs {
            if r == nil {
                continue
            }
            if _, err := fmt.Fprintln(w, r.PrettyString()); err != nil {
                return err
            }
            if _, err := fmt.Fprintln(w, "----"); err != nil {
                return err
            }
        }
    }
    return nil
}
