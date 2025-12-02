# GoVulnScanner

## Overview
GoVulnScanner is a fast and flexible vulnerability scanning tool for cybersecurity professionals, similar to Nuclei. It enables automated security testing by scanning web applications, APIs, and network infrastructure for known vulnerabilities, misconfigurations, and security exposures. Like Nuclei, it uses template-based detection to identify security issues quickly and efficiently.

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
go build -o go-vuln-scanner
# Run the scanner
./go-vuln-scanner -target https://example.com
```

## Examples
### Example 1: Quick Web Application Scan
```bash
./go-vuln-scanner -target https://mywebapp.com -output report.json
```

### Example 2: Comprehensive Network Scan
```bash
./go-vuln-scanner -list network_hosts.txt -threads 25 -timeout 30 -verbose
```

### Example 3: Targeted Vulnerability Assessment
```bash
./go-vuln-scanner -target https://api.example.com -tags cve,exposure -severity critical -output critical_vulns.json
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is open source and available under the MIT License.
