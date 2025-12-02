# GoVulnScanner

## Overview

GoVulnScanner is a fast and flexible web application penetration testing tool designed for cybersecurity professionals, similar to Nuclei. It enables automated security testing by scanning web applications, APIs, and network infrastructure for known vulnerabilities, misconfigurations, and security exposures. Like Nuclei, it uses template-based detection to identify security issues quickly and efficiently, making it an essential tool for penetration testers, security researchers, and DevSecOps teams.

This tool is specifically designed for:

- Web application security testing and vulnerability assessment
- API security scanning and endpoint testing
- Automated penetration testing workflows
- Security research and bug bounty hunting
- DevSecOps integration and continuous security monitoring

## Key Features

- `ScanTargets(targets []string)` - Scan multiple targets concurrently
- `SetThreads(count int)` - Set number of concurrent threads
- `SetTimeout(seconds int)` - Set request timeout
- `SetVerbose(enabled bool)` - Enable/disable verbose logging
- `SetTemplates(templates []Template)` - Load custom vulnerability templates
- `SetHeaders(headers map[string]string)` - Set custom HTTP headers

#### Result Methods

- `FilterBySeverity(levels []string)` - Filter results by severity level
- `FilterByTag(tags []string)` - Filter results by template tags
- `ExportToJSON(filename string)` - Export results to JSON file
- `ExportToHTML(filename string)` - Export results to HTML report
- `GetStatistics()` - Get scan statistics and summary

## Installation

```bash
# Clone the repository
git clone https://github.com/Shanmukhasrisai/go-vuln-scanner.git

# Navigate to the project directory
cd go-vuln-scanner

# Build the project
go build -o govulnscanner cmd/govulnscanner/main.go

# Run the scanner
./govulnscanner --target https://example.com
```

## Examples

### Example 1: Quick Web Application Scan

```bash
./govulnscanner --target https://mywebapp.com --output scan-report.json
```

### Example 2: Comprehensive Network Scan

```bash
./govulnscanner --target-list network-hosts.txt --threads 25 --timeout 30 --verbose
```

### Example 3: Targeted Vulnerability Assessment

```bash
./govulnscanner --target https://api.example.com --tags cve,exposure --severity critical --output critical-vulnerabilities.json
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.
