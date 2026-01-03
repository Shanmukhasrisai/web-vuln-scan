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
	"regexp"
	"strings"
	"sync"
	"time"
)

// VulnTemplate represents a comprehensive vulnerability check template for Web2 & Web3 security testing
type VulnTemplate struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Description string `json:"description"`
	Severity string `json:"severity"`
	Path string `json:"path"`
	Method string `json:"method"`
	MatchString string `json:"match_string"`
	StatusCode int `json:"status_code"`
	Regex string `json:"regex,omitempty"`
	Tags []string `json:"tags"`
	CVE string `json:"cve,omitempty"`
	TestType string `json:"test_type"`
}

// Scanner manages comprehensive security scanning for Web2 & Web3 vulnerabilities
type Scanner struct {
	Targets []string
	Templates []VulnTemplate
	HTTPClient *http.Client
	Concurrency int
	Timeout time.Duration
	Results []ScanResult
	ResultsMutex sync.Mutex
	Verbose bool
	OutputFile string
	UserAgent string
	FollowRedirect bool
	EnableWeb3 bool
}

// ScanResult captures detailed vulnerability findings
type ScanResult struct {
	Target string `json:"target"`
	Vuln string `json:"vulnerability"`
	Severity string `json:"severity"`
	Description string `json:"description"`
	Timestamp time.Time `json:"timestamp"`
	CVE string `json:"cve,omitempty"`
	Tags []string `json:"tags"`
	TestType string `json:"test_type"`
	Recommendation string `json:"recommendation,omitempty"`
}

// NewScanner creates a new Scanner instance with security configurations
func NewScanner(targets []string, concurrency int, timeout time.Duration) *Scanner {
	return &Scanner{
		Targets: targets,
		Concurrency: concurrency,
		Timeout: timeout,
		HTTPClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		UserAgent: "Advanced Web Security Scanner/2.0",
		FollowRedirect: false,
	}
}

// LoadTemplates loads vulnerability templates from JSON configuration
func (s *Scanner) LoadTemplates(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read template file: %v", err)
	}
	if err := json.Unmarshal(data, &s.Templates); err != nil {
		return fmt.Errorf("failed to parse templates: %v", err)
	}
	if s.Verbose {
		log.Printf("Loaded %d security templates\n", len(s.Templates))
	}
	return nil
}

// ScanTarget performs comprehensive vulnerability checks on a single target
func (s *Scanner) ScanTarget(target string) {
	if s.Verbose {
		log.Printf("Starting security scan on: %s\n", target)
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

// checkVulnerability performs a single vulnerability check with comprehensive analysis
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

	// Check vulnerability based on multiple criteria
	vulnFound := false
	if (template.StatusCode == 0 || resp.StatusCode == template.StatusCode) {
		if template.MatchString != "" {
			if strings.Contains(string(body), template.MatchString) {
				vulnFound = true
			}
		} else if template.Regex != "" {
			re, err := regexp.Compile(template.Regex)
			if err == nil && re.Match(body) {
				vulnFound = true
			}
		} else {
			vulnFound = true
		}
	}

	if vulnFound {
		recommendation := s.getRecommendation(template.Name, template.TestType)
		result := ScanResult{
			Target: target,
			Vuln: template.Name,
			Severity: template.Severity,
			Description: template.Description,
			Timestamp: time.Now(),
			CVE: template.CVE,
			Tags: template.Tags,
			TestType: template.TestType,
			Recommendation: recommendation,
		}
		s.ResultsMutex.Lock()
		s.Results = append(s.Results, result)
		s.ResultsMutex.Unlock()
		fmt.Printf("[+] Vulnerability Found: %s on %s [%s]\n",
			template.Name, url, template.Severity)
	}
}

// getRecommendation provides actionable remediation advice
func (s *Scanner) getRecommendation(vulnName, testType string) string {
	recommendations := map[string]string{
		"SQL Injection": "Use parameterized queries and prepared statements. Validate and sanitize user inputs.",
		"XSS": "Implement output encoding, Content Security Policy (CSP), and input validation.",
		"CSRF": "Implement CSRF tokens, SameSite cookies, and verify origin headers.",
		"Authentication Bypass": "Strengthen authentication mechanisms, implement MFA, use strong session management.",
		"Insecure Direct Object References": "Implement proper authorization checks and access controls.",
		"Sensitive Data Exposure": "Encrypt sensitive data in transit and at rest using TLS/SSL and AES.",
		"Missing WAF": "Deploy a Web Application Firewall (WAF) to filter malicious requests.",
		"Reentrancy": "Use checks-effects-interactions pattern and reentrancy guards in smart contracts.",
		"Integer Overflow": "Use SafeMath library or Solidity ^0.8.0 with built-in overflow protection.",
	}
	if rec, ok := recommendations[vulnName]; ok {
		return rec
	}
	return "Review security best practices for " + testType
}

// Run executes the scanner on all targets
func (s *Scanner) Run() {
	if s.Verbose {
		log.Printf("Starting security scan on %d targets\n", len(s.Targets))
	}
	for _, target := range s.Targets {
		s.ScanTarget(target)
	}
	if s.Verbose {
		log.Printf("Completed scan. Found %d vulnerabilities\n", len(s.Results))
	}
}

// SaveResults saves scan results to JSON file with proper error handling
func (s *Scanner) SaveResults(filename string) error {
	data, err := json.MarshalIndent(s.Results, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %v", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %v", err)
	}
	log.Printf("Results saved to: %s\n", filename)
	return nil
}

func main() {
	targetsFile := flag.String("targets", "", "File containing target URLs (one per line)")
	templatesFile := flag.String("templates", "templates.json", "JSON file containing vulnerability templates")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent scans")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	output := flag.String("output", "results.json", "Output file for scan results")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	enableWeb3 := flag.Bool("web3", false, "Enable Web3/blockchain vulnerability checks")
	flag.Parse()

	if *targetsFile == "" {
		log.Fatal("Please provide a targets file using -targets flag")
	}

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

	s := NewScanner(targets, *concurrency, time.Duration(*timeout)*time.Second)
	s.Verbose = *verbose
	s.OutputFile = *output
	s.EnableWeb3 = *enableWeb3

	if err := s.LoadTemplates(*templatesFile); err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	fmt.Println("========================================")
	fmt.Println("Advanced Web Security Scanner v2.0")
	if *enableWeb3 {
		fmt.Println("[+] Web3/Blockchain Security Checks Enabled")
	}
	fmt.Println("========================================")
	s.Run()

	if len(s.Results) > 0 {
		if err := s.SaveResults(*output); err != nil {
			log.Printf("Failed to save results: %v", err)
		}
		fmt.Printf("\n[!] Found %d vulnerabilities\n", len(s.Results))
	} else {
		fmt.Println("\n[+] No vulnerabilities found during security scan.")
	}
}
