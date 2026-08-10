package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type requestJob struct {
	ID             string            `json:"id"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers,omitempty"`
	Params         map[string]any    `json:"params,omitempty"`
	Body           any               `json:"body,omitempty"`
	TimeoutSeconds float64           `json:"timeout_seconds,omitempty"`
}

type responseRow struct {
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	Payload    any    `json:"payload,omitempty"`
	ErrorKind  string `json:"error_kind,omitempty"`
	Message    string `json:"message,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

type rateLimiter struct {
	mu     sync.Mutex
	nextAt time.Time
	step   time.Duration
}

func newRateLimiter(rate int) *rateLimiter {
	if rate < 1 {
		rate = 1
	}
	return &rateLimiter{step: time.Second / time.Duration(rate)}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()
	start := now
	if r.nextAt.After(now) {
		start = r.nextAt
	}
	r.nextAt = start.Add(r.step)
	r.mu.Unlock()

	delay := time.Until(start)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func safeEndpoint(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		if index := strings.IndexAny(raw, "?#"); index >= 0 {
			return raw[:index]
		}
		return raw
	}
	host := parsed.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	return parsed.Scheme + "://" + host + parsed.EscapedPath()
}

func addParams(raw string, params map[string]any) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	for key, value := range params {
		if value == nil {
			continue
		}
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				query.Add(key, fmt.Sprint(item))
			}
		default:
			query.Set(key, fmt.Sprint(value))
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func classifyNetworkError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connection"
}

func execute(client *http.Client, limiter *rateLimiter, job requestJob) responseRow {
	endpoint := safeEndpoint(job.URL)
	method := strings.ToUpper(strings.TrimSpace(job.Method))
	if method != http.MethodGet && method != http.MethodPost {
		return responseRow{ID: job.ID, ErrorKind: "request", Message: "Unsupported HTTP method for " + endpoint}
	}
	timeout := time.Duration(job.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	requestURL, err := addParams(job.URL, job.Params)
	if err != nil {
		return responseRow{ID: job.ID, ErrorKind: "request", Message: "Invalid request URL for " + endpoint}
	}
	var body io.Reader
	if method == http.MethodPost {
		encoded, encodeErr := json.Marshal(job.Body)
		if encodeErr != nil {
			return responseRow{ID: job.ID, ErrorKind: "request", Message: "Invalid JSON request body for " + endpoint}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return responseRow{ID: job.ID, ErrorKind: "request", Message: "Invalid request for " + endpoint}
	}
	for key, value := range job.Headers {
		req.Header.Set(key, value)
	}
	if method == http.MethodPost && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := limiter.wait(ctx); err != nil {
		return responseRow{ID: job.ID, ErrorKind: classifyNetworkError(err), Message: "Request timed out for " + endpoint}
	}
	resp, err := client.Do(req)
	if err != nil {
		kind := classifyNetworkError(err)
		message := "Connection failed for " + endpoint
		if kind == "timeout" {
			message = "Request timed out for " + endpoint
		}
		return responseRow{ID: job.ID, ErrorKind: kind, Message: message}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseRow{
			ID: job.ID, ErrorKind: "http", StatusCode: resp.StatusCode,
			Message: "HTTP " + strconv.Itoa(resp.StatusCode) + " for " + endpoint,
		}
	}
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	var payload any
	if err := decoder.Decode(&payload); err != nil {
		return responseRow{
			ID: job.ID, ErrorKind: "json_decode", StatusCode: resp.StatusCode,
			Message: "Invalid JSON response from " + endpoint + " (status " + strconv.Itoa(resp.StatusCode) + ")",
		}
	}
	return responseRow{ID: job.ID, OK: true, Payload: payload, StatusCode: resp.StatusCode}
}

func run(input io.Reader, output io.Writer, workers, rate int) error {
	if workers < 1 {
		workers = 1
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        workers * 2,
		MaxIdleConnsPerHost: workers,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport}
	limiter := newRateLimiter(rate)
	jobs := make(chan requestJob)
	rows := make(chan responseRow)
	var wg sync.WaitGroup

	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				rows <- execute(client, limiter, job)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(rows)
	}()

	decodeErr := make(chan error, 1)
	go func() {
		defer close(jobs)
		scanner := bufio.NewScanner(input)
		buffer := make([]byte, 64*1024)
		scanner.Buffer(buffer, 16*1024*1024)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var job requestJob
			if err := json.Unmarshal(line, &job); err != nil {
				decodeErr <- fmt.Errorf("invalid input JSON: %w", err)
				return
			}
			if strings.TrimSpace(job.ID) == "" {
				decodeErr <- errors.New("request id must not be empty")
				return
			}
			jobs <- job
		}
		decodeErr <- scanner.Err()
	}()

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	for row := range rows {
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return <-decodeErr
}

func main() {
	workers := flag.Int("workers", 20, "maximum concurrent HTTP requests")
	rate := flag.Int("rate", 100, "maximum request starts per second")
	flag.Parse()
	if err := run(os.Stdin, os.Stdout, *workers, *rate); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
