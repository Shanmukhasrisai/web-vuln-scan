# GoVulnScanner

## Overview

GoVulnScanner is a high-performance, template-based vulnerability detection engine designed for security professionals and penetration testers. Built for speed and accuracy, it identifies 100+ known CVEs, misconfigurations, and security exposures across web applications, APIs, and network infrastructure.

The scanner employs a modular template system enabling rapid detection of emerging threats while maintaining low false-positive rates. Optimized for both standalone security assessments and CI/CD pipeline integration.

**Primary Use Cases:**
- Enterprise-grade vulnerability assessment and penetration testing
- Bug bounty reconnaissance and targeted exploitation
- Continuous security monitoring in DevSecOps pipelines
- Security research and threat validation
- API security testing and endpoint enumeration

## Core Capabilities

**Scanning Engine:**
- `ScanTargets(targets []string)` - Concurrent multi-target scanning with intelligent queue management
- `SetThreads(count int)` - Configurable worker pool for optimized resource utilization
- `SetTimeout(seconds int)` - Granular request timeout control for network resilience
- `SetVerbose(enabled bool)` - Debug-level logging for troubleshooting and analysis

**Detection & Configuration:**
- `SetTemplates(templates []Template)` - Dynamic template loading for custom vulnerability signatures
- `SetHeaders(headers map[string]string)` - Custom HTTP header injection for authentication and evasion
- Template-based detection engine supporting 100+ CVE signatures
- TLS/SSL support with configurable certificate validation
- Flexible target input (URLs, CIDR ranges, file lists)

## Python Integration

Native Python bindings enable seamless workflow automation and custom security tooling development.

**Features:**
- **Python API Wrapper** - Direct access to scanner functionality via native bindings
- **Script Extensibility** - Develop custom vulnerability checks and detection logic
- **Automation Support** - Integration with existing Python-based security frameworks

### Python Examples

#### Basic Vulnerability Scan
```python
from govulnscanner import Scanner

# Initialize scanner with optimized settings
scanner = Scanner()
scanner.set_threads(10)
scanner.set_timeout(30)
scanner.set_verbose(True)

# Execute scan against multiple targets
targets = ['https://example.com', 'https://api.target.com']
results = scanner.scan_targets(targets)

# Process and export critical findings
results.filter_by_severity(['high', 'critical'])
results.export_to_json('vulnerabilities.json')
```

#### Custom Template Scan
```python
from govulnscanner import Scanner, Template

# Load custom vulnerability templates
scanner = Scanner()
scanner.load_templates_from_directory('./templates')
scanner.set_threads(20)

# Execute targeted scan with custom detection rules
targets = ['https://webapp.target.com']
results = scanner.scan_targets(targets)

# Generate executive summary report
results.generate_report('scan_report.html')
```
