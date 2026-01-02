package main

import (
	"bufio"
	"crypto/tls"
	 "io"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VulnTemplate represents a web application penetration testing expert vulnerability check template
// Enhanced with detailed documentation and additional fields for comprehensive security assessment
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

// Scanner manages web application penetration testing expert vulnerability scanning operations
// Enhanced with additional configuration options and result tracking for professional security testing
type Scanner struct {
	Targets       []string
	Templates     []VulnTemplate
	HTTPClient    *http.Client
	Concurrency   int
	Timeout       time.Duration
	Results       []ScanResult
	ResultsMutex  sync.Mutex
	Verbose       bool
	OutputFile    string
	UserAgent     string
	FollowRedirect bool
}

// ScanResult represents the result of a web application penetration testing expert vulnerability scan
// Captures detailed information about identified security issues
type ScanResult struct {
	Target      string    `json:"target"`
	Vuln        string    `json:"vulnerability"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	CVE         string    `json:"cve,omitempty"`
	Tags        []string  `json:"tags"`
}

// NewScanner creates a new web application penetration testing expert Scanner instance with default settings
// Initializes the scanner with professional security testing configurations
func NewScanner(targets []string, concurrency int, timeout time.Duration) *Scanner {
	return &Scanner{
		Targets:     targets,
		Concurrency: concurrency,
		Timeout:     timeout,
		HTTPClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		UserAgent:      "Web Application Penetration Testing Expert Scanner/1.0",
		FollowRedirect: false,
	}
}

// LoadTemplates loads vulnerability templates from a JSON file for web application penetration testing
// Supports comprehensive security testing configurations
func (s *Scanner) LoadTemplates(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read template file: %v", err)
	}

	if err := json.Unmarshal(data, &s.Templates); err != nil {
		return fmt.Errorf("failed to parse templates: %v", err)
	}

	if s.Verbose {
		log.Printf("Loaded %d web application penetration testing templates\n", len(s.Templates))
	}

	return nil
}

// ScanTarget performs web application penetration testing expert vulnerability checks on a single target
// Executes comprehensive security assessments
func (s *Scanner) ScanTarget(target string) {
	if s.Verbose {
		log.Printf("Starting web application penetration testing on: %s\n", target)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)

	for _, template := range s.Templates {
		wg.Add(1)
		go func(t VulnTemplate) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			s.checkVulnerability(target, t)
		}(template)
	}

	wg.Wait()
}

// checkVulnerability performs a single web application penetration testing expert vulnerability check
// Evaluates specific security vulnerabilities with expert precision
func (s *Scanner) checkVulnerability(target string, template VulnTemplate) {
	url := target + template.Path

	req, err := http.NewRequest(template.Method, url, nil)
	if err != nil {
		if s.Verbose {
			log.Printf("Error creating request for %s: %v\n", url, err)
		}
		return
	}

	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		if s.Verbose {
			log.Printf("Error scanning %s: %v\n", url, err)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.Verbose {
			log.Printf("Error reading response from %s: %v\n", url, err)
		}
		return
	}

	// Check if vulnerability exists based on web application penetration testing expert criteria
	if (template.StatusCode == 0 || resp.StatusCode == template.StatusCode) &&
		(template.MatchString == "" || strings.Contains(string(body), template.MatchString)) {

		result := ScanResult{
			Target:      target,
			Vuln:        template.Name,
			Severity:    template.Severity,
			Description: template.Description,
			Timestamp:   time.Now(),
			CVE:         template.CVE,
			Tags:        template.Tags,
		}

		s.ResultsMutex.Lock()
		s.Results = append(s.Results, result)
		s.ResultsMutex.Unlock()

		fmt.Printf("[+] Web Application Penetration Testing Expert Found: %s on %s [%s]\n",
			template.Name, url, template.Severity)
	}
}

// Run executes the web application penetration testing expert scanner on all targets
// Performs comprehensive professional security assessment
func (s *Scanner) Run() {
	if s.Verbose {
		log.Printf("Starting web application penetration testing expert scan on %d targets\n", len(s.Targets))
	}

	for _, target := range s.Targets {
		s.ScanTarget(target)
	}

	if s.Verbose {
		log.Printf("Completed web application penetration testing expert scan. Found %d vulnerabilities\n", len(s.Results))
	}
}

// SaveResults saves web application penetration testing expert scan results to a JSON file
// Provides detailed security assessment documentation
func (s *Scanner) SaveResults(filename string) error {
	data, err := json.MarshalIndent(s.Results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %v", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %v", err)
	}

	log.Printf("Web application penetration testing expert results saved to: %s\n", filename)
	return nil
}

func main() {
	// Command line flags for web application penetration testing expert tool
	targetsFile := flag.String("targets", "", "File containing target URLs (one per line)")
	templatesFile := flag.String("templates", "templates.json", "JSON file containing vulnerability templates")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent scans")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	output := flag.String("output", "results.json", "Output file for scan results")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	if *targetsFile == "" {
		log.Fatal("Please provide a targets file using -targets flag")
	}

	// Read targets from file
	file, err := os.Open(*targetsFile)
	if err != nil {
		log.Fatalf("Failed to open targets file: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading targets file: %v", err)
	}

	if len(targets) == 0 {
		log.Fatal("No targets found in the targets file")
	}

	// Initialize web application penetration testing expert scanner
	s := NewScanner(targets, *concurrency, time.Duration(*timeout)*time.Second)
	s.Verbose = *verbose
	s.OutputFile = *output

	// Load vulnerability templates
	if err := s.LoadTemplates(*templatesFile); err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	// Run web application penetration testing expert scan
	fmt.Println("========================================")
	fmt.Println("Web Application Penetration Testing Expert Scanner")
	fmt.Println("========================================")
	s.Run()

	// Save results
	if len(s.Results) > 0 {
		if err := s.SaveResults(*output); err != nil {
			log.Printf("Failed to save results: %v", err)
		}
	} else {
		fmt.Println("\nNo vulnerabilities found during web application penetration testing expert scan.")
	}
}
