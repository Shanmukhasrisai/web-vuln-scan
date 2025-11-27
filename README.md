# Go Vulnerability Scanner

A simple yet powerful vulnerability scanner written in Go, inspired by [Nuclei](https://github.com/projectdiscovery/nuclei). This tool allows you to scan web applications for common vulnerabilities using customizable templates.

## Features

- 🚀 **Fast Multi-threaded Scanning**: Concurrent scanning with configurable thread count
- 🎯 **Template-based Detection**: Built-in vulnerability templates for common issues
- 🔍 **Flexible Target Input**: Scan single targets or multiple targets from a file
- ⏱️ **Customizable Timeout**: Configure request timeout to suit your needs
- 📊 **Results Export**: Save scan results to a file for later analysis
- 🔒 **TLS Support**: Handles HTTPS connections with insecure certificate support

## Built-in Vulnerability Templates

The scanner comes with the following built-in templates:

| ID | Name | Severity | Description |
|---------|---------------------------|----------|----------------------------------------------|
| VULN-001 | Git Config Exposure | High | Detects exposed .git/config files |
| VULN-002 | phpinfo() Exposure | Medium | Detects exposed phpinfo.php files |
| VULN-003 | Admin Panel Exposure | Medium | Detects accessible admin panels |
| VULN-004 | Backup File Exposure | High | Detects exposed backup files |
| VULN-005 | Environment File Exposure | Critical | Detects exposed .env configuration files |

## Installation

### Prerequisites

- Go 1.21 or higher

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Shanmukhasrisai/go-vuln-scanner.git
cd go-vuln-scanner

# Build the binary
go build -o vuln-scanner main.go

# Or install directly
go install
```

## Usage

### Command Line Options

```
-t string
    File containing target URLs (default "targets.txt")
-u string
    Single target URL
-c int
    Number of concurrent threads (default 10)
-timeout int
    Request timeout in seconds (default 10)
-o string
    Output file for results (default "results.txt")
```

### Scanning a Single Target

```bash
./vuln-scanner -u https://example.com
```

### Scanning Multiple Targets from a File

```bash
# Create a targets file (or copy from targets.txt.example)
cp targets.txt.example targets.txt

# Edit targets.txt and add your target URLs
vim targets.txt

# Run the scanner
./vuln-scanner -t targets.txt
```

### Customizing Concurrency and Timeout

```bash
# Use 20 threads with 15 second timeout
./vuln-scanner -u https://example.com -c 20 -timeout 15
```

### Saving Results

```bash
# Save results to custom output file
./vuln-scanner -t targets.txt -o my_scan_results.txt
```

## Example Output

```
  ██████╗  ██████╗     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
 ██╔════╝ ██╔═══██╗    ██║   ██║██║   ██║██║     ████╗  ██║
 ██║  ███╗██║   ██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║
 ██║   ██║██║   ██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
 ╚██████╔╝╚██████╔╝     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
  ╚═════╝  ╚═════╝       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝

         Simple Vulnerability Scanner v1.0
         Inspired by Nuclei

[*] Starting scan with 10 threads
[*] Loaded 3 targets
[*] Loaded 5 templates

[High] [VULN-001] Git Config Exposure - https://example.com/.git/config
[Critical] [VULN-005] Environment File Exposure - https://testsite.com/.env
[Medium] [VULN-003] Admin Panel Exposure - https://example2.com/admin

[*] Scan completed. Found 3 vulnerabilities
[*] Results saved to results.txt
```

## Targets File Format

The targets file should contain one URL per line. Lines starting with `#` are treated as comments.

```
# Example targets.txt
https://example.com
https://testsite.com
http://192.168.1.100

# This is a comment
https://anothersite.com
```

## Architecture

### Core Components

1. **Scanner**: Main scanning engine that manages concurrency and orchestrates the scanning process
2. **VulnTemplate**: Defines vulnerability check templates with matching criteria
3. **HTTP Client**: Handles HTTP/HTTPS requests with custom timeout and TLS configuration
4. **Results Manager**: Thread-safe results collection and export

### Adding Custom Templates

To add your own vulnerability templates, modify the `LoadTemplates()` function in `main.go`:

```go
s.Templates = append(s.Templates, VulnTemplate{
    ID:          "VULN-006",
    Name:        "Custom Vulnerability",
    Severity:    "High",
    Path:        "/custom-path",
    Method:      "GET",
    MatchString: "vulnerability-indicator",
    StatusCode:  200,
})
```

## Security Considerations

⚠️ **Important**: This tool is designed for security testing purposes only. Always ensure you have proper authorization before scanning any targets.

- Only scan systems you own or have explicit permission to test
- Be mindful of the scan intensity (thread count) to avoid overwhelming target systems
- Some scans may trigger security alerts or IDS/IPS systems
- Use responsibly and ethically

## Contributing

Contributions are welcome! Here are some ways you can contribute:

- Add new vulnerability templates
- Improve detection accuracy
- Add support for custom template files (YAML/JSON)
- Enhance reporting capabilities
- Fix bugs and improve performance

## Roadmap

- [ ] Support for external template files (YAML/JSON format)
- [ ] Advanced matching patterns (regex, status codes)
- [ ] HTML report generation
- [ ] Integration with vulnerability databases
- [ ] Support for authenticated scans
- [ ] Rate limiting options
- [ ] Proxy support

## License

This project is open source and available under the MIT License.

## Acknowledgments

- Inspired by [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei)
- Built with ❤️ using Go

## Disclaimer

This tool is provided for educational and ethical security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before scanning any systems.

---

**Happy Scanning!** 🔍🛡️
