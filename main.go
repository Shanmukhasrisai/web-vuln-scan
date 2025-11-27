package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VulnTemplate represents a vulnerability check template
type VulnTemplate struct {
	ID          string
	Name        string
	Severity    string
	Path        string
	Method      string
	MatchString string
	StatusCode  int
}

// Scanner manages vulnerability scanning operations
type Scanner struct {
	Targets   []string
	Templates []VulnTemplate
	Threads   int
	Timeout   time.Duration
	Results   []string
	mu        sync.Mutex
}

// NewScanner creates a new vulnerability scanner instance
func NewScanner(threads int, timeout int) *Scanner {
	return &Scanner{
		Threads: threads,
		Timeout: time.Duration(timeout) * time.Second,
		Results: make([]string, 0),
	}
}

// LoadTargets loads target URLs from a file
func (s *Scanner) LoadTargets(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			s.Targets = append(s.Targets, target)
		}
	}
	return scanner.Err()
}

// LoadTemplates loads vulnerability check templates
func (s *Scanner) LoadTemplates() {
	s.Templates = []VulnTemplate{
		{
			ID:          "VULN-001",
			Name:        "Git Config Exposure",
			Severity:    "High",
			Path:        "/.git/config",
			Method:      "GET",
			MatchString: "[core]",
			StatusCode:  200,
		},
		{
			ID:          "VULN-002",
			Name:        "phpinfo() Exposure",
			Severity:    "Medium",
			Path:        "/phpinfo.php",
			Method:      "GET",
			MatchString: "PHP Version",
			StatusCode:  200,
		},
		{
			ID:          "VULN-003",
			Name:        "Admin Panel Exposure",
			Severity:    "Medium",
			Path:        "/admin",
			Method:      "GET",
			MatchString: "admin",
			StatusCode:  200,
		},
		{
			ID:          "VULN-004",
			Name:        "Backup File Exposure",
			Severity:    "High",
			Path:        "/backup.sql",
			Method:      "GET",
			MatchString: "SQL",
			StatusCode:  200,
		},
		{
			ID:          "VULN-005",
			Name:        "Environment File Exposure",
			Severity:    "Critical",
			Path:        "/.env",
			Method:      "GET",
			MatchString: "=",
			StatusCode:  200,
		},
	}
}

// CheckVulnerability checks a single target against a template
func (s *Scanner) CheckVulnerability(target string, template VulnTemplate) {
	url := target + template.Path

	// Create HTTP client with custom settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   s.Timeout,
	}

	// Create request
	req, err := http.NewRequest(template.Method, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "GoVulnScanner/1.0")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if status code matches
	if resp.StatusCode != template.StatusCode {
		return
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Check if match string is present
	if strings.Contains(string(body), template.MatchString) {
		result := fmt.Sprintf("[%s] [%s] %s - %s", template.Severity, template.ID, template.Name, url)
		s.mu.Lock()
		s.Results = append(s.Results, result)
		s.mu.Unlock()
		fmt.Println(result)
	}
}

// Scan initiates the vulnerability scanning process
func (s *Scanner) Scan() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Threads)

	fmt.Printf("[*] Starting scan with %d threads\n", s.Threads)
	fmt.Printf("[*] Loaded %d targets\n", len(s.Targets))
	fmt.Printf("[*] Loaded %d templates\n\n", len(s.Templates))

	for _, target := range s.Targets {
		for _, template := range s.Templates {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(t string, tmpl VulnTemplate) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore
				s.CheckVulnerability(t, tmpl)
			}(target, template)
		}
	}

	wg.Wait()
	fmt.Printf("\n[*] Scan completed. Found %d vulnerabilities\n", len(s.Results))
}

// SaveResults saves scan results to a file
func (s *Scanner) SaveResults(filename string) error {
	if len(s.Results) == 0 {
		return nil
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range s.Results {
		_, err := writer.WriteString(result + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func main() {
	// Command line flags
	targetFile := flag.String("t", "targets.txt", "File containing target URLs")
	target := flag.String("u", "", "Single target URL")
	threads := flag.Int("c", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	output := flag.String("o", "results.txt", "Output file for results")
	flag.Parse()

	// Banner
	fmt.Println("")
	fmt.Println("  ██████╗  ██████╗     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗")
	fmt.Println(" ██╔════╝ ██╔═══██╗    ██║   ██║██║   ██║██║     ████╗  ██║")
	fmt.Println(" ██║  ███╗██║   ██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║")
	fmt.Println(" ██║   ██║██║   ██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║")
	fmt.Println(" ╚██████╔╝╚██████╔╝     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║")
	fmt.Println("  ╚═════╝  ╚═════╝       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝")
	fmt.Println("")
	fmt.Println("         Simple Vulnerability Scanner v1.0")
	fmt.Println("         Inspired by Nuclei")
	fmt.Println("")

	// Create scanner
	scanner := NewScanner(*threads, *timeout)

	// Load templates
	scanner.LoadTemplates()

	// Load targets
	if *target != "" {
		scanner.Targets = append(scanner.Targets, *target)
	} else {
		err := scanner.LoadTargets(*targetFile)
		if err != nil {
			fmt.Printf("[!] Error loading targets: %v\n", err)
			os.Exit(1)
		}
	}

	if len(scanner.Targets) == 0 {
		fmt.Println("[!] No targets specified. Use -u for single target or -t for target file")
		os.Exit(1)
	}

	// Run scan
	scanner.Scan()

	// Save results
	if len(scanner.Results) > 0 {
		err := scanner.SaveResults(*output)
		if err != nil {
			fmt.Printf("[!] Error saving results: %v\n", err)
		} else {
			fmt.Printf("[*] Results saved to %s\n", *output)
		}
	}
}
