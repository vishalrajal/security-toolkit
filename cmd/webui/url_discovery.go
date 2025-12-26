package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// URLRecord represents a discovered URL with metadata
type URLRecord struct {
	OriginalURL    string   `json:"original_url"`
	FinalURL       string   `json:"final_url,omitempty"`
	AssociatedHost string   `json:"associated_host"`
	StatusCode     int      `json:"status_code"`
	RedirectChain  []string `json:"redirect_chain,omitempty"`
	Source         string   `json:"source"`
	Parameters     []string `json:"parameters,omitempty"`
	Tags           []string `json:"tags,omitempty"` // js, php, sensitive, admin, etc.
	Classification string   `json:"classification"` // e.g., "endpoint", "file", "parameterized"
}

// runURLDiscoveryAggressive coordinates the discovery, normalization, resolution, and classification pipeline
func runURLDiscoveryAggressive(ctx context.Context, hosts []string, progress func(int, string)) ([]URLRecord, error) {
	if len(hosts) == 0 {
		return []URLRecord{}, nil
	}

	progress(5, "Initializing discovery...")
	log.Printf("[Discovery] Starting URL discovery for %d hosts", len(hosts))

	// 1. Discovery (Katana + GAU)
	discoveredRaw := make(chan string, 2000)
	var wg sync.WaitGroup

	progress(10, "Running Katana & GAU...")

	// Run Katana
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := executeKatana(ctx, hosts, discoveredRaw); err != nil {
			log.Printf("[Katana] Error: %v", err)
		}
	}()

	// Run GAU (if available)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := executeGau(ctx, hosts, discoveredRaw); err != nil {
			log.Printf("[Gau] Error: %v", err)
		}
	}()

	go func() {
		wg.Wait()
		close(discoveredRaw)
	}()

	// Collect raw URLs
	var rawURLs []string
	for u := range discoveredRaw {
		rawURLs = append(rawURLs, u)
		// Hard limit to avoid memory issues and long resolution times
		if len(rawURLs) >= 2000 {
			log.Printf("[Discovery] reached raw URL limit (2000), skipping remaining")
			break
		}
	}

	// 2. Normalization & Deduplication
	uniqueURLs := normalizeAndDedup(rawURLs)
	log.Printf("[Discovery] found %d unique URLs", len(uniqueURLs))
	progress(40, "Deduplicating URLs...")

	// 3. Resolution (Headless check for redirects) & Classification
	// Limit resolution to a reasonable number to keep it fast
	maxToResolve := 1000 // Increased from 500
	if len(uniqueURLs) > maxToResolve {
		log.Printf("[Discovery] limiting resolution to first %d URLs", maxToResolve)
		uniqueURLs = uniqueURLs[:maxToResolve]
	}

	results := make([]URLRecord, 0, len(uniqueURLs))
	resultsChan := make(chan URLRecord, len(uniqueURLs))
	sem := make(chan struct{}, 100) // Increased concurrency to 100

	var resolutionWg sync.WaitGroup

	// Create a custom client with redirect policy
	client := &http.Client{
		Timeout: 3 * time.Second, // Faster timeout
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	log.Printf("[Discovery] resolving %d URLs...", len(uniqueURLs))
	progress(50, fmt.Sprintf("Resolving %d unique URLs...", len(uniqueURLs)))

	count := 0
	var mu sync.Mutex

	for _, u := range uniqueURLs {
		resolutionWg.Add(1)
		go func(targetUrl string) {
			defer resolutionWg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				rec := resolveAndClassify(ctx, client, targetUrl)
				resultsChan <- rec

				mu.Lock()
				count++
				if count%10 == 0 {
					p := 50 + (count * 50 / len(uniqueURLs))
					progress(p, fmt.Sprintf("Resolved %d/%d URLs...", count, len(uniqueURLs)))
				}
				mu.Unlock()
			case <-ctx.Done():
				return
			}
		}(u)
	}

	go func() {
		resolutionWg.Wait()
		close(resultsChan)
	}()

	for r := range resultsChan {
		results = append(results, r)
	}

	return results, nil
}

func executeKatana(ctx context.Context, hosts []string, outChan chan<- string) error {
	katanaPath := findKatanaBinary()
	if katanaPath == "" {
		return fmt.Errorf("katana binary not found")
	}

	// Create inputs file
	var inputBuf bytes.Buffer
	for _, h := range hosts {
		if !strings.HasPrefix(h, "http") {
			inputBuf.WriteString("https://" + h + "\n") // Prefer HTTPS
			inputBuf.WriteString("http://" + h + "\n")
		} else {
			inputBuf.WriteString(h + "\n")
		}
	}

	// katana -silent -d 1 -c 150 -ct 1m
	cmd := exec.CommandContext(ctx, katanaPath,
		"-silent",
		"-d", "1", // Aggressive depth reduction
		"-c", "150", // High concurrency
		"-ct", "1m", // 1 minute limit per target
		"-no-color",
	)
	cmd.Stdin = &inputBuf

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			outChan <- line
		}
	}

	return cmd.Wait()
}

func executeGau(ctx context.Context, hosts []string, outChan chan<- string) error {
	gauPath := findGauBinary()
	if gauPath == "" {
		return nil // Optional, skip
	}

	// gau runs per domain typically
	// gau <domain>
	// supporting multiple domains via stdin
	cmd := exec.CommandContext(ctx, gauPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		for _, h := range hosts {
			fmt.Fprintln(stdin, h)
		}
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			outChan <- line
		}
	}

	return cmd.Wait()
}

func normalizeAndDedup(urls []string) []string {
	unique := make(map[string]struct{})
	var result []string

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}

		// Remove Fragment
		u.Fragment = ""

		// Sort Query Params
		q := u.Query()
		if len(q) > 0 {
			u.RawQuery = q.Encode() // Encode sorts by key
		}

		// Remove Trailing Slash
		if u.Path != "/" && strings.HasSuffix(u.Path, "/") {
			u.Path = strings.TrimSuffix(u.Path, "/")
		}

		normalized := u.String()
		if _, exists := unique[normalized]; !exists {
			unique[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	return result
}

func resolveAndClassify(ctx context.Context, client *http.Client, targetUrl string) URLRecord {
	rec := URLRecord{
		OriginalURL: targetUrl,
		Source:      "discovery", // Could differentiate if we tracked it upstream
		Tags:        []string{},
	}

	// Extract associated host
	if u, err := url.Parse(targetUrl); err == nil {
		rec.AssociatedHost = u.Hostname()

		// Basic classification by extension
		ext := strings.ToLower(filepath.Ext(u.Path))
		if ext != "" {
			rec.Tags = append(rec.Tags, strings.TrimPrefix(ext, "."))
			if ext == ".js" || ext == ".json" || ext == ".xml" {
				rec.Classification = "asset"
			}
		}

		// Params
		for k := range u.Query() {
			rec.Parameters = append(rec.Parameters, k)
		}
		if len(rec.Parameters) > 0 {
			rec.Classification = "parameterized"
			rec.Tags = append(rec.Tags, "params")
		}

		// Sensitive keywords
		lowerPath := strings.ToLower(u.Path)
		keywords := []string{"admin", "login", "api", "dev", "staging", "internal", "config"}
		for _, k := range keywords {
			if strings.Contains(lowerPath, k) {
				rec.Tags = append(rec.Tags, k)
				rec.Classification = "sensitive" // Upgrade classification
			}
		}
	}

	// Resolve
	// Use HEAD first for speed? Or GET if we want content type? HEAD is enough for redirects.
	req, err := http.NewRequestWithContext(ctx, "HEAD", targetUrl, nil)
	if err == nil {
		// Fake user agent
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityToolkit/1.0)")

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			rec.StatusCode = resp.StatusCode
			rec.FinalURL = resp.Request.URL.String()

			if rec.OriginalURL != rec.FinalURL {
				rec.Tags = append(rec.Tags, "redirect")
				rec.RedirectChain = append(rec.RedirectChain, rec.FinalURL) // Simplified chain
			}
		}
	}

	if rec.Classification == "" {
		rec.Classification = "endpoint"
	}

	return rec
}

func findKatanaBinary() string {
	exeName := "katana"
	if runtime.GOOS == "windows" {
		exeName = "katana.exe"
	}

	if cwd, err := os.Getwd(); err == nil {
		localPath := filepath.Join(cwd, exeName)
		if _, err := os.Stat(localPath); err == nil {
			return localPath
		}
		// Try parent (root of repo if we are in cmd/webui)
		parentPath := filepath.Join(filepath.Dir(filepath.Dir(cwd)), exeName) // e:\subfinder
		if _, err := os.Stat(parentPath); err == nil {
			return parentPath
		}
		// Try explicit location e:\subfinder\katana\cmd\katana
		// Assuming we are in e:\subfinder\cmd\webui
		// ../../katana/cmd/katana
		buildPath := filepath.Join(filepath.Dir(filepath.Dir(cwd)), "katana", "cmd", "katana", exeName)
		if _, err := os.Stat(buildPath); err == nil {
			return buildPath
		}
	}

	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}
	return ""
}

func findGauBinary() string {
	exeName := "gau"
	if runtime.GOOS == "windows" {
		exeName = "gau.exe"
	}
	// Only check PATH for gau as it's not vendored
	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}
	return ""
}
