package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type scanRequest struct {
	Domain             string `json:"domain"`
	URL                string `json:"url"`
	ResolveWithDNSX    bool   `json:"resolve_dns"`
	PortScan           bool   `json:"port_scan"`
	EnableURLDiscovery bool   `json:"url_discovery"`
}

type scanResponse struct {
	Success        bool        `json:"success"`
	Output         string      `json:"output,omitempty"`
	ErrorText      string      `json:"error,omitempty"`
	DiscoveredURLs []URLRecord `json:"discovered_urls,omitempty"`
}

type progressUpdate struct {
	Type       string        `json:"type"`
	Percentage int           `json:"percentage,omitempty"`
	Message    string        `json:"message,omitempty"`
	Data       *scanResponse `json:"data,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fs := http.FileServer(http.Dir("web"))
	http.Handle("/", fs)
	http.HandleFunc("/api/scan", handleScan)

	log.Printf("Starting Subfinder Web UI on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	req.URL = strings.TrimSpace(req.URL)

	if req.Domain == "" && req.URL == "" {
		http.Error(w, "domain or seed url is required", http.StatusBadRequest)
		return
	}

	// Setup streaming
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback to non-streaming if flusher not available (unlikely in Go standard server)
		log.Println("Streaming not supported, status updates will be missing")
	}

	sendUpdate := func(p int, msg string) {
		update := progressUpdate{Type: "progress", Percentage: p, Message: msg}
		json.NewEncoder(w).Encode(update)
		if flusher != nil {
			flusher.Flush()
		}
	}

	sendResult := func(res scanResponse) {
		update := progressUpdate{Type: "result", Data: &res}
		json.NewEncoder(w).Encode(update)
		if flusher != nil {
			flusher.Flush()
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	sendUpdate(5, "Initializing...")

	var cleaned string

	// Only run subfinder/dnsx if domain is provided
	if req.Domain != "" {
		sendUpdate(10, "Enumerating subdomains...")
		// Find subfinder binary
		subfinderPath := findSubfinderBinary()
		if subfinderPath == "" {
			sendResult(scanResponse{
				Success:   false,
				ErrorText: "subfinder binary not found.",
			})
			return
		}

		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, subfinderPath, "-d", req.Domain, "-silent", "-t", "100")
		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			cleaned := stripBanner(out.String())
			sendResult(scanResponse{
				Success:   false,
				Output:    cleaned,
				ErrorText: err.Error(),
			})
			return
		}

		cleaned = stripBanner(out.String())

		// Optional DNS resolution with dnsx
		if req.ResolveWithDNSX {
			sendUpdate(30, "Resolving subdomains...")
			dnsxPath := findDNSXBinary()
			if dnsxPath == "" {
				sendResult(scanResponse{
					Success:   false,
					Output:    cleaned,
					ErrorText: "dnsx binary not found.",
				})
				return
			}

			var dnsxOut bytes.Buffer
			dnsxCmd := exec.CommandContext(ctx, dnsxPath, "-silent", "-t", "150")
			dnsxCmd.Stdin = strings.NewReader(cleaned)
			dnsxCmd.Stdout = &dnsxOut
			dnsxCmd.Stderr = &dnsxOut

			if err := dnsxCmd.Run(); err != nil {
				sendResult(scanResponse{
					Success:   false,
					Output:    stripBanner(dnsxOut.String()),
					ErrorText: err.Error(),
				})
				return
			}

			cleaned = stripBanner(dnsxOut.String())
		}
	}

	// Prepare collected hosts for next steps (PortScan or URL Discovery)
	var finalHosts []string
	lines := strings.Split(cleaned, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			finalHosts = append(finalHosts, l)
		}
	}

	// Add seed URL if provided
	if req.URL != "" {
		finalHosts = append(finalHosts, req.URL)
	}

	var discovered []URLRecord

	// URL Discovery Module
	if req.EnableURLDiscovery && len(finalHosts) > 0 {
		sendUpdate(50, "Discovering URLs...")
		// Aggressive speed: Only crawl a subset of hosts if there are many
		discoveryHosts := finalHosts
		if len(discoveryHosts) > 20 {
			log.Printf("Too many hosts for discovery (%d), limiting to top 20", len(discoveryHosts))
			discoveryHosts = discoveryHosts[:20]
		}

		log.Printf("Starting URL Discovery for %d hosts...", len(discoveryHosts))
		recs, err := runURLDiscoveryAggressive(ctx, discoveryHosts, func(p int, msg string) {
			// runURLDiscovery will provide 0-100 progress for its own phase
			// Map it to range 50-95
			offsetP := 50 + (p * 45 / 100)
			sendUpdate(offsetP, msg)
		})
		if err != nil {
			log.Printf("URL Discovery error: %v", err)
		}
		discovered = recs
		log.Printf("Discovered %d URLs", len(discovered))
	}

	// Optional port scan + correlation
	if req.PortScan {
		sendUpdate(95, "Correlating port data...")
		jsonOut, err := correlateWithPortScan(ctx, cleaned)
		if err != nil {
			sendResult(scanResponse{
				Success:   false,
				Output:    cleaned,
				ErrorText: err.Error(),
			})
			return
		}
		cleaned = jsonOut
	}

	sendUpdate(100, "Scan Complete")
	sendResult(scanResponse{
		Success:        true,
		Output:         cleaned,
		DiscoveredURLs: discovered,
	})
}

func findSubfinderBinary() string {
	exeName := "subfinder"
	if runtime.GOOS == "windows" {
		exeName = "subfinder.exe"
	}

	// Try current directory first
	if cwd, err := os.Getwd(); err == nil {
		localPath := filepath.Join(cwd, exeName)
		if _, err := os.Stat(localPath); err == nil {
			return localPath
		}
		// Try parent directory (where webui might be run from)
		parentPath := filepath.Join(filepath.Dir(cwd), exeName)
		if _, err := os.Stat(parentPath); err == nil {
			return parentPath
		}
	}

	// Try PATH
	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}

	return ""
}

func findDNSXBinary() string {
	exeName := "dnsx"
	if runtime.GOOS == "windows" {
		exeName = "dnsx.exe"
	}

	if cwd, err := os.Getwd(); err == nil {
		// Try root of this project
		localPath := filepath.Join(cwd, exeName)
		if _, err := os.Stat(localPath); err == nil {
			return localPath
		}
		// Try dnsx/cmd/dnsx
		nestedPath := filepath.Join(cwd, "dnsx", "cmd", "dnsx", exeName)
		if _, err := os.Stat(nestedPath); err == nil {
			return nestedPath
		}
	}

	// Try PATH
	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}
	return ""
}

func findHTTPXBinary() string {
	exeName := "httpx"
	if runtime.GOOS == "windows" {
		exeName = "httpx.exe"
	}

	if cwd, err := os.Getwd(); err == nil {
		// Try root of this project
		localPath := filepath.Join(cwd, exeName)
		if _, err := os.Stat(localPath); err == nil {
			return localPath
		}
		// Try httpx/cmd/httpx (source build location)
		nestedPath := filepath.Join(cwd, "httpx", "cmd", "httpx", exeName)
		if _, err := os.Stat(nestedPath); err == nil {
			return nestedPath
		}
	}

	// Try standard Go bin location for Windows
	// C:\Users\<User>\go\bin\httpx.exe
	homeDir, err := os.UserHomeDir()
	if err == nil {
		goBinPath := filepath.Join(homeDir, "go", "bin", exeName)
		if _, err := os.Stat(goBinPath); err == nil {
			return goBinPath
		}
	}

	// Try PATH, but verify it's not the Python one
	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}
	return ""
}

type httpxMeta struct {
	Status     int
	Title      string
	Tech       []string
	Location   string
	IsRedirect bool
	IsJSON     bool
}

// runHTTPXEnrichment calls httpx (if available) to gather status/title/tech info.
func runHTTPXEnrichment(ctx context.Context, hosts []string) map[string]httpxMeta {
	result := make(map[string]httpxMeta)
	httpxPath := findHTTPXBinary()

	if httpxPath == "" {
		log.Println("WARNING: httpx binary not found. enhanced alive status and tech detection will be disabled.")
		return result
	}
	if len(hosts) == 0 {
		return result
	}

	var stdinBuf bytes.Buffer
	for _, h := range hosts {
		stdinBuf.WriteString(h)
		stdinBuf.WriteByte('\n')
	}

	// Keep enrichment bounded so UI stays responsive
	// Increased timeout to ensure reliable scanning
	cmdCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	// Added -follow-redirects to get final status code
	cmd := exec.CommandContext(cmdCtx, httpxPath,
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-location", // capture redirect location
		"-follow-redirects",
		"-no-color",
		"-t", "100",
	)
	cmd.Stdin = &stdinBuf
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("httpx enrichment failed: %v. Stderr: %s", err, stderr.String())
		return result
	}

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		// Normalize key to hostname so it matches our host strings
		hostKey := ""
		if v, ok := obj["host"].(string); ok && v != "" {
			hostKey = v
		} else if v, ok := obj["url"].(string); ok && v != "" {
			if u, err := url.Parse(v); err == nil {
				hostKey = u.Hostname()
			}
		}

		// Fallback: checks if the input was just a domain and the URL field contains it
		if hostKey == "" {
			if v, ok := obj["input"].(string); ok && v != "" {
				hostKey = v
			}
		}

		if hostKey == "" {
			continue
		}

		meta := httpxMeta{}
		if v, ok := obj["status_code"].(float64); ok {
			meta.Status = int(v)
		}
		if v, ok := obj["title"].(string); ok {
			meta.Title = v
		}
		if v, ok := obj["location"].(string); ok {
			meta.Location = v
		}

		// tech or technologies field may be present
		if raw, ok := obj["technologies"]; ok {
			if arr, ok := raw.([]interface{}); ok {
				for _, t := range arr {
					if s, ok := t.(string); ok {
						meta.Tech = append(meta.Tech, s)
					}
				}
			}
		} else if raw, ok := obj["tech"]; ok {
			if arr, ok := raw.([]interface{}); ok {
				for _, t := range arr {
					if s, ok := t.(string); ok {
						meta.Tech = append(meta.Tech, s)
					}
				}
			}
		}

		// Response properties
		if v, ok := obj["content_type"].(string); ok {
			ct := strings.ToLower(v)
			if strings.Contains(ct, "application/json") {
				meta.IsJSON = true
			}
		}
		if meta.Status >= 300 && meta.Status < 400 {
			meta.IsRedirect = true
		}

		result[hostKey] = meta
	}

	return result
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// stripBanner removes the subfinder ASCII banner and footer lines
func stripBanner(text string) string {
	lines := strings.Split(text, "\n")
	filtered := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Drop known banner/footer lines
		if strings.Contains(trimmed, "projectdiscovery.io") {
			continue
		}
		if strings.HasPrefix(trimmed, "_______") ||
			strings.HasPrefix(trimmed, "__") ||
			strings.HasPrefix(trimmed, "/ ___/") ||
			strings.HasPrefix(trimmed, "(__  )") ||
			strings.HasPrefix(trimmed, "/____/") {
			continue
		}

		filtered = append(filtered, line)
	}

	// Trim leading empty lines after filtering
	for len(filtered) > 0 && strings.TrimSpace(filtered[0]) == "" {
		filtered = filtered[1:]
	}

	return strings.Join(filtered, "\n")
}

// correlateWithPortScan takes newline-separated hosts, resolves them, scans a few ports,
// and returns a pretty-printed JSON array of correlated host objects with advanced risk scoring.
func correlateWithPortScan(ctx context.Context, hostsText string) (string, error) {
	type hostInfo struct {
		Host        string   `json:"host"`
		IP          string   `json:"ip"`
		Ports       []int    `json:"ports"`
		Service     string   `json:"service,omitempty"`
		Category    string   `json:"category,omitempty"`
		Priority    string   `json:"priority,omitempty"`
		Alive       bool     `json:"alive"`
		AliveStatus int      `json:"alive_status"`
		RiskScore   int      `json:"risk_score"`
		RiskLevel   string   `json:"risk_level"`
		RiskReasons []string `json:"risk_reasons"`
		Status      int      `json:"status,omitempty"`
		Title       string   `json:"title,omitempty"`
		Tech        []string `json:"tech,omitempty"`
	}

	const maxHostsForPortScan = 100

	lines := strings.Split(hostsText, "\n")
	seenHosts := make(map[string]struct{})
	hosts := make([]string, 0, len(lines))
	for _, line := range lines {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		if _, ok := seenHosts[host]; ok {
			continue
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	// Hard-limit number of hosts for fast UX
	if len(hosts) > maxHostsForPortScan {
		hosts = hosts[:maxHostsForPortScan]
	}
	if len(hosts) == 0 {
		return "[]", nil
	}

	// Enrich with httpx (status, title, tech, basic response info)
	httpxInfo := runHTTPXEnrichment(ctx, hosts)

	var results []hostInfo
	// Small, focused port set to keep scans fast
	portsToCheck := []int{80, 443, 8080, 8443}

	// Use a shorter overall timeout for portscan phase
	psCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type scanResult struct {
		host      string
		ip        string
		openPorts []int
	}

	jobs := make(chan string)
	resultsCh := make(chan scanResult, len(hosts))

	worker := func() {
		for host := range jobs {
			var ipStr string
			addrs, err := net.DefaultResolver.LookupIPAddr(psCtx, host)
			if err == nil && len(addrs) > 0 {
				ipStr = addrs[0].IP.String()
			}

			var openPorts []int
			targetIP := ipStr
			if targetIP == "" {
				targetIP = host
			}
			for _, p := range portsToCheck {
				dialer := net.Dialer{Timeout: 250 * time.Millisecond}
				conn, err := dialer.DialContext(psCtx, "tcp", net.JoinHostPort(targetIP, strconv.Itoa(p)))
				if err == nil {
					_ = conn.Close()
					openPorts = append(openPorts, p)
				}
			}

			select {
			case resultsCh <- scanResult{host: host, ip: ipStr, openPorts: openPorts}:
			case <-psCtx.Done():
				return
			}
		}
	}

	// Start limited number of workers for concurrency
	workerCount := 100
	if workerCount > len(hosts) {
		workerCount = len(hosts)
	}
	for i := 0; i < workerCount; i++ {
		go worker()
	}

	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)

	scanMap := make(map[string]scanResult, len(hosts))
	for i := 0; i < len(hosts); i++ {
		select {
		case res := <-resultsCh:
			scanMap[res.host] = res
		case <-psCtx.Done():
			// Time budget exceeded; use whatever we have so far
			goto done
		}
	}
done:

	for _, host := range hosts {
		res := scanMap[host]
		ipStr := res.ip
		openPorts := res.openPorts

		hinfo := httpxInfo[host]

		// Alive logic
		alive := false
		if hinfo.Status >= 200 && hinfo.Status < 500 { // Allow 4xx as "alive" regarding reachability
			alive = true
		} else if hinfo.Status == 0 && len(openPorts) > 0 {
			alive = true
		}

		service := ""
		if alive {
			service = "web"
		}

		// Calculate Advanced Risk Score
		riskScore, riskLevel, riskReasons, category := calculateAdvancedRiskScore(host, openPorts, hinfo)

		results = append(results, hostInfo{
			Host:        host,
			IP:          ipStr,
			Ports:       openPorts,
			Service:     service,
			Category:    category,
			Priority:    riskLevel, // Using Risk Level as Priority
			Alive:       alive,
			AliveStatus: hinfo.Status,
			RiskScore:   riskScore,
			RiskLevel:   riskLevel,
			RiskReasons: riskReasons,
			Status:      hinfo.Status,
			Title:       hinfo.Title,
			Tech:        hinfo.Tech,
		})
	}

	// Sort by risk score (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// calculateAdvancedRiskScore implements the detailed risk scoring model provided by the user.
func calculateAdvancedRiskScore(host string, openPorts []int, info httpxMeta) (int, string, []string, string) {
	score := 0
	reasons := []string{}
	h := strings.ToLower(host)

	// --- Base Category Score ---
	category := "unknown"
	baseScore := 10

	// Determine category based on naming/content
	// Check for static/CDN first?
	isCDN := false
	for _, t := range info.Tech {
		tLow := strings.ToLower(t)
		if strings.Contains(tLow, "cdn") || strings.Contains(tLow, "cloudfront") || strings.Contains(tLow, "cloudflare") || strings.Contains(tLow, "akamai") || strings.Contains(tLow, "fastly") {
			isCDN = true
			break
		}
	}

	if isCDN {
		category = "static/cdn"
		baseScore = 5
	} else if strings.HasPrefix(h, "admin.") || strings.Contains(h, ".admin.") || strings.Contains(h, "admin-") {
		category = "admin"
		baseScore = 50
	} else if strings.HasPrefix(h, "auth.") || strings.Contains(h, ".auth.") || strings.Contains(h, "login") || strings.Contains(h, "signin") {
		category = "auth"
		baseScore = 45
	} else if strings.HasPrefix(h, "api.") || strings.Contains(h, ".api.") || info.IsJSON {
		category = "api"
		baseScore = 40
	} else if strings.HasPrefix(h, "corp.") || strings.Contains(h, ".corp.") || strings.Contains(h, "internal") || strings.Contains(h, "intranet") {
		category = "internal/corp"
		baseScore = 35
	} else if len(openPorts) > 0 || info.Status > 0 {
		category = "web"
		baseScore = 20
	}

	score += baseScore
	reasons = append(reasons, category+" category")

	// --- Exposure Modifier ---
	if info.Status >= 200 && info.Status < 300 {
		score += 30
		reasons = append(reasons, "public exposure (200)")
	} else if info.Status == 401 || info.Status == 403 || info.IsRedirect {
		score += 15
		reasons = append(reasons, "limited exposure ("+strconv.Itoa(info.Status)+")")
	} else {
		// 404, 0, 5xx
		score += 0
		reasons = append(reasons, "no public exposure")
	}

	// --- Port Risk ---
	nonStandardCount := 0
	for _, p := range openPorts {
		if p != 80 && p != 443 {
			nonStandardCount++
		}
	}
	if nonStandardCount > 1 {
		score += 25
		reasons = append(reasons, "multiple non-standard ports")
	} else if nonStandardCount == 1 {
		score += 15
		reasons = append(reasons, "one non-standard port")
	} else {
		// Only 80/443
		score += 0
	}

	// --- Technology Signals ---
	if info.IsJSON {
		score += 10
		reasons = append(reasons, "API response (JSON)")
	}

	// Admin framework detected?
	isAdminTech := false
	isLegacy := false
	for _, t := range info.Tech {
		tLow := strings.ToLower(t)
		if strings.Contains(tLow, "admin") || strings.Contains(tLow, "panel") || strings.Contains(tLow, "dashboard") {
			isAdminTech = true
		}
		if strings.Contains(tLow, "php") && (strings.Contains(tLow, "5.") || strings.Contains(tLow, "4.")) {
			isLegacy = true
		}
		if strings.Contains(tLow, "asp.net") && strings.Contains(tLow, "2.0") {
			isLegacy = true
		}
		// Add more legacy heuristics as needed
	}

	if isAdminTech {
		score += 10
		reasons = append(reasons, "admin framework detected")
	}
	if isLegacy {
		score += 10
		reasons = append(reasons, "legacy technology")
	}

	// Modern CDN / HTTP-3 only: +0 (already handled by default)

	// --- Negative Signals (Penalties) ---
	if info.Status == 404 || strings.Contains(strings.ToLower(info.Title), "error") {
		score -= 20
		reasons = append(reasons, "error page detected")
	}

	// CDN / cache hostname pattern
	// Covered partly by category, but explicit penalty asked
	if isCDN {
		score -= 20
		reasons = append(reasons, "CDN / cache hostname pattern")
	}

	// Redirect to parent auth domain
	// Heuristic: location contains "login" or "auth" and is different domain?
	// For simplicity, if it's a redirect to *auth* or *login* we penalize as likely handled
	if info.IsRedirect {
		loc := strings.ToLower(info.Location)
		if strings.Contains(loc, "login") || strings.Contains(loc, "auth") {
			score -= 10
			reasons = append(reasons, "redirect to parent auth domain")
		}
	}

	// Big-tech managed infrastructure
	// Heuristic: check tech or CNAME/Location for google/aws/azure/fb
	isBigTech := false
	bigTechKeywords := []string{"google", "amazon", "aws", "azure", "microsoft", "facebook", "cloudflare", "akamai"}
	for _, t := range info.Tech {
		for _, bt := range bigTechKeywords {
			if strings.Contains(strings.ToLower(t), bt) {
				isBigTech = true
				break
			}
		}
	}
	if isBigTech {
		score -= 10
		reasons = append(reasons, "big-tech managed infrastructure")
	}

	// Clamp final score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Determine Risk Level
	level := "low"
	switch {
	case score >= 80:
		level = "critical"
	case score >= 60:
		level = "high"
	case score >= 40:
		level = "medium"
	default:
		level = "low"
	}

	return score, level, reasons, category
}
