package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VulnTemplate represents a vulnerability check template
// Enhanced with detailed documentation and additional fields
type VulnTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	MatchString string   `json:"match_string"`
	StatusCode  int      `json:"status_code"`
	Tags        []string `json:"tags"`
	CVE         string   `json:"cve,omitempty"`
}

// Scanner manages vulnerability scanning operations
// Enhanced with additional configuration options and result tracking
type Scanner struct {
	Targets       []string
	Templates     []VulnTemplate
	Threads       int
	Timeout       time.Duration
	Results       []ScanResult
	Verbose       bool
	OutputFile    string
	FollowRedirect bool
	mu            sync.Mutex
	wg            sync.WaitGroup
}

// ScanResult represents the result of a vulnerability scan
type ScanResult struct {
	Target       string    `json:"target"`
	VulnID       string    `json:"vuln_id"`
	VulnName     string    `json:"vuln_name"`
	Severity     string    `json:"severity"`
	Found        bool      `json:"found"`
	StatusCode   int       `json:"status_code"`
	ResponseTime int64     `json:"response_time_ms"`
	Timestamp    time.Time `json:"timestamp"`
	Details      string    `json:"details,omitempty"`
}

// NewScanner creates a new Scanner instance with default settings
func NewScanner(targets []string, templates []VulnTemplate) *Scanner {
	return &Scanner{
		Targets:        targets,
		Templates:      templates,
		Threads:        10,
		Timeout:        10 * time.Second,
		Results:        make([]ScanResult, 0),
		Verbose:        false,
		FollowRedirect: false,
	}
}

// LoadTemplates loads vulnerability templates from a JSON file
func LoadTemplates(filename string) ([]VulnTemplate, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var templates []VulnTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return templates, nil
}

// LoadTargets loads target URLs from a file
func LoadTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open targets file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading targets: %w", err)
	}

	return targets, nil
}

// CheckVulnerability performs a single vulnerability check
func (s *Scanner) CheckVulnerability(target string, template VulnTemplate) ScanResult {
	start := time.Now()
	result := ScanResult{
		Target:    target,
		VulnID:    template.ID,
		VulnName:  template.Name,
		Severity:  template.Severity,
		Found:     false,
		Timestamp: start,
	}

	// Construct the full URL
	url := target + template.Path

	// Create HTTP client with custom settings
	client := &http.Client{
		Timeout: s.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !s.FollowRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Create request
	req, err := http.NewRequest(template.Method, url, nil)
	if err != nil {
		result.Details = fmt.Sprintf("Error creating request: %v", err)
		return result
	}

	// Set User-Agent
	req.Header.Set("User-Agent", "GoVulnScanner/1.0")

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		result.Details = fmt.Sprintf("Request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ResponseTime = time.Since(start).Milliseconds()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Details = fmt.Sprintf("Error reading response: %v", err)
		return result
	}

	// Check if vulnerability is found
	if template.StatusCode > 0 && resp.StatusCode == template.StatusCode {
		if template.MatchString == "" || strings.Contains(string(body), template.MatchString) {
			result.Found = true
			result.Details = "Vulnerability detected based on status code and response content"
		}
	} else if template.MatchString != "" && strings.Contains(string(body), template.MatchString) {
		result.Found = true
		result.Details = "Vulnerability detected based on response content match"
	}

	return result
}

// Scan executes the vulnerability scanning process
func (s *Scanner) Scan() {
	sem := make(chan struct{}, s.Threads)

	for _, target := range s.Targets {
		for _, template := range s.Templates {
			s.wg.Add(1)
			sem <- struct{}{}

			go func(t string, tmpl VulnTemplate) {
				defer s.wg.Done()
				defer func() { <-sem }()

				result := s.CheckVulnerability(t, tmpl)

				s.mu.Lock()
				s.Results = append(s.Results, result)
				if result.Found && s.Verbose {
					fmt.Printf("[+] VULNERABILITY FOUND: %s on %s (Severity: %s)\n",
						result.VulnName, result.Target, result.Severity)
				}
				s.mu.Unlock()
			}(target, template)
		}
	}

	s.wg.Wait()
}

// SaveResults saves scan results to a JSON file
func (s *Scanner) SaveResults(filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(s.Results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	return nil
}

// PrintSummary prints a summary of scan results
func (s *Scanner) PrintSummary() {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := len(s.Results)
	found := 0
	severityCount := make(map[string]int)

	for _, result := range s.Results {
		if result.Found {
			found++
			severityCount[result.Severity]++
		}
	}

	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Total Checks: %d\n", total)
	fmt.Printf("Vulnerabilities Found: %d\n", found)
	fmt.Println("\nBy Severity:")
	for severity, count := range severityCount {
		fmt.Printf("  %s: %d\n", severity, count)
	}
}

func main() {
	// Command-line flags
	targetFile := flag.String("targets", "targets.txt", "File containing target URLs")
	target := flag.String("target", "", "Single target URL")
	templateFile := flag.String("templates", "templates.json", "File containing vulnerability templates")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	output := flag.String("output", "results.json", "Output file for results")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	followRedirect := flag.Bool("follow-redirect", false, "Follow HTTP redirects")

	flag.Parse()

	// Load templates
	templates, err := LoadTemplates(*templateFile)
	if err != nil {
		log.Fatalf("Error loading templates: %v", err)
	}

	// Load targets
	var targets []string
	if *target != "" {
		targets = []string{*target}
	} else {
		targets, err = LoadTargets(*targetFile)
		if err != nil {
			log.Fatalf("Error loading targets: %v", err)
		}
	}

	if len(targets) == 0 {
		log.Fatal("No targets specified")
	}

	// Create scanner
	scanner := NewScanner(targets, templates)
	scanner.Threads = *threads
	scanner.Timeout = time.Duration(*timeout) * time.Second
	scanner.Verbose = *verbose
	scanner.OutputFile = *output
	scanner.FollowRedirect = *followRedirect

	fmt.Printf("Starting vulnerability scan...\n")
	fmt.Printf("Targets: %d\n", len(targets))
	fmt.Printf("Templates: %d\n", len(templates))
	fmt.Printf("Threads: %d\n", *threads)
	fmt.Println()

	// Run scan
	scanner.Scan()

	// Print summary
	scanner.PrintSummary()

	// Save results
	if err := scanner.SaveResults(*output); err != nil {
		log.Printf("Error saving results: %v", err)
	} else {
		fmt.Printf("\nResults saved to: %s\n", *output)
	}
}
