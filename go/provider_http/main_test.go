package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decodeRows(t *testing.T, output string) map[string]responseRow {
	t.Helper()
	rows := map[string]responseRow{}
	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var row responseRow
		if err := decoder.Decode(&row); err != nil {
			t.Fatal(err)
		}
		rows[row.ID] = row
	}
	return rows
}

func TestRunHandlesGETPOSTAndSafeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": r.URL.Query().Get("ioc")})
		case "/post":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.Error(w, "secret upstream detail", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	jobs := []requestJob{
		{ID: "get", Method: "GET", URL: server.URL + "/get", Params: map[string]any{"ioc": "a.invalid"}},
		{ID: "post", Method: "POST", URL: server.URL + "/post", Body: map[string]any{"ok": true}},
		{ID: "error", Method: "GET", URL: server.URL + "/error?token=SENTINEL", Headers: map[string]string{"Authorization": "SENTINEL"}},
	}
	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	for _, job := range jobs {
		if err := encoder.Encode(job); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := run(&input, &output, 3, 1000); err != nil {
		t.Fatal(err)
	}
	rows := decodeRows(t, output.String())
	if !rows["get"].OK || !rows["post"].OK {
		t.Fatalf("unexpected success rows: %#v", rows)
	}
	if rows["error"].ErrorKind != "http" || rows["error"].StatusCode != 503 {
		t.Fatalf("unexpected error row: %#v", rows["error"])
	}
	if strings.Contains(rows["error"].Message, "SENTINEL") || strings.Contains(rows["error"].Message, "secret upstream") {
		t.Fatalf("unsafe error message: %s", rows["error"].Message)
	}
}

func TestSafeEndpointRemovesCredentialsAndQuery(t *testing.T) {
	got := safeEndpoint("https://user:pass@example.invalid:8443/path?token=secret#frag")
	if got != "https://example.invalid:8443/path" {
		t.Fatalf("safeEndpoint = %q", got)
	}
}
