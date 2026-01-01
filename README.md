# WebVAPT - Professional Web Vulnerability Assessment & Penetration Testing Tool

## Expert-Grade Web Security Auditing Platform for Security Researchers

WebVAPT is a sophisticated, high-performance vulnerability assessment and penetration testing (VAPT) framework purpose-built for professional security researchers, ethical hackers, and penetration testers. Engineered with production-grade reliability, it delivers comprehensive web application vulnerability detection with advanced reporting, compliance mapping, and real-time threat intelligence integration.

## Key Features for Security Researchers

### 🎯 Comprehensive Web Vulnerability Detection
- **Multi-protocol Support**: HTTP/HTTPS, DNS, TCP, SSL/TLS, and WebSocket assessments
- **Template-Based Detection Engine**: YAML-driven custom vulnerability signatures with multi-stage matching
- **Advanced Payload Mutation**: Intelligent payload transformation, encoding chains, and variable interpolation
- **Protocol-Specific Modules**: Specialized detectors for REST APIs, GraphQL, SOAP, and binary protocols

### ⚡ High-Performance Scanning Architecture
- **Concurrent Scanning**: Goroutine-based parallelization achieving 10,000+ requests/second
- **Adaptive Resource Management**: Dynamic worker pools with intelligent scheduling
- **Memory-Efficient**: ~150MB footprint with configurable concurrency limits
- **Connection Pooling**: Persistent HTTP/HTTPS reuse with keep-alive optimization

### 📊 Enterprise-Grade Reporting
- **Multi-Format Output**: JSON, XML, HTML, PDF, SARIF, Markdown
- **Compliance Mapping**: OWASP Top 10, CWE, PCI DSS, NIST CSF, CVSS 3.1 scoring
- **Executive Summaries**: Risk heatmaps, vulnerability trends, actionable remediation paths
- **Evidence Documentation**: Full request/response capture with proof-of-concept details

### 🔍 Advanced Reconnaissance Features
- **Service Enumeration**: Port scanning, service detection, version fingerprinting
- **Technology Stack Detection**: Web frameworks, databases, CDNs, third-party services
- **API Discovery**: Endpoint mapping, parameter fuzzing, documentation extraction
- **SSL/TLS Analysis**: Certificate validation, protocol version assessment, cipher strength evaluation

### 🛡️ Security-First Architecture
- **Credential Management**: Integration with HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- **TLS 1.3 Enforcement**: All API communications encrypted and authenticated
- **Audit Logging**: Comprehensive tamper-evident audit trails for compliance
- **Least Privilege Execution**: Containerized deployment with minimal permissions

### 📈 Scalable Assessment Infrastructure
- **Distributed Scanning**: Multi-machine coordination with load balancing
- **Kubernetes Native**: Enterprise-ready K8s manifests and Helm charts
- **Docker Support**: Multi-stage builds, minimal image sizes
- **Cloud-Native**: AWS, Azure, GCP deployment templates

## Installation

### Quick Start (Linux/macOS)
```bash
go install github.com/Shanmukhasrisai/web-vuln-scan@latest
webvAPT server --host 0.0.0.0 --port 8080
```

### Docker Deployment
```bash
docker build -t webvapt .
docker run -p 8080:8080 \
  -e API_KEY="your-key" \
  -v $(pwd)/templates:/root/templates \
  webvapt
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/deployment.yaml
kubectl port-forward svc/webvapt 8080:8080 -n security-tools
```

## Core Architecture

### Scanning Engine
- **Goroutine-Based Concurrency**: Parallel processing across multiple targets and payloads
- **Adaptive Threading**: Dynamic worker allocation based on system resources
- **Rate Limiting**: Configurable per-target, per-host, and global rate limits
- **Timeout Management**: Intelligent timeout handling with exponential backoff

### Detection Framework
- **Template System**: YAML-based vulnerability signatures with variable support
- **Matchers**: Status codes, regex patterns, word matches, JSON/XML extraction
- **Extractors**: Dynamic variable extraction for multi-stage attack chains
- **Conditional Logic**: Complex AND/OR matching conditions

## API Reference

### REST Endpoints

#### Scan Management
```
POST   /api/v1/scans              # Create new assessment
GET    /api/v1/scans/{id}         # Retrieve scan status
GET    /api/v1/scans/{id}/results # Fetch vulnerability findings
DELETE /api/v1/scans/{id}         # Terminate scan
GET    /api/v1/scans/status       # List active scans
```

#### Template Management
```
GET    /api/v1/templates          # List available templates
POST   /api/v1/templates          # Upload custom template
GET    /api/v1/templates/{id}     # Retrieve template
DELETE /api/v1/templates/{id}     # Remove template
```

#### System Operations
```
GET    /api/v1/health             # System health check
GET    /api/v1/metrics            # Performance metrics
GET    /api/v1/config             # Current configuration
```

### Authentication
- JWT-based token authentication with role-based access control (RBAC)
- API key management with granular permission scoping
- OAuth 2.0 integration for enterprise identity providers
- Rate limiting: 1000 requests/minute per API key

### Webhook Integration
```json
{
  "scan_id": "scan_123",
  "timestamp": "2026-01-01T12:00:00Z",
  "vulnerability_id": "cve-2024-xxxxx",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "target": "https://example.com",
  "evidence": "Full HTTP request/response",
  "remediation": "Recommended fixes"
}
```

## Configuration Profiles

### Aggressive Scanning
```yaml
profile: aggressive
threads: 100
timeout: 30s
retries: 3
rate_limit: 1000/s
```

### Stealth Mode
```yaml
profile: stealth
threads: 5
timeout: 60s
retries: 1
rate_limit: 10/s
random_agent: true
```

### Production Assessment
```yaml
profile: production
threads: 25
timeout: 45s
retries: 2
rate_limit: 100/s
safe_mode: true
```

## Vulnerability Template Example

```yaml
id: sql-injection-auth
info:
  name: SQL Injection in Login Form
  severity: critical
  cvss-score: 9.8
  cve-id: CVE-2024-xxxxx

http:
  - method: POST
    path: "{{BaseURL}}/login"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "username=admin'--&password=test"

matchers-condition: and
matchers:
  - type: status
    status: [200, 500]
  - type: word
    words:
      - "Welcome"
      - "error"
    condition: or
  - type: regex
    regex:
      - '(?i)mysql|sql|oracle|postgres'

extractors:
  - type: regex
    name: db_version
    regex: 'version\s*:\s*([\d.]+)'
```

## Performance Benchmarks

| Metric | Value | Conditions |
|--------|-------|------------|
| Scan Throughput | 10,000+ req/sec | 100 concurrent workers |
| Memory Footprint | ~150MB | Base runtime, 1000 templates |
| CPU Efficiency | 80-90% | Multi-core optimization |
| Template Processing | <1ms | Average per template |
| API Response Time | <50ms | 95th percentile latency |
| Concurrent Scans | 100+ | Per instance |

## Security Considerations

### Operational Security
- Run in isolated network environments during assessments
- Use VPN/proxy for external target scanning
- Implement strict access controls on API keys
- Regular security audits of configuration
- Encrypted storage of credentials and results

### Data Protection
- End-to-end encryption for sensitive findings
- Secure deletion of cached responses
- GDPR-compliant data handling
- Audit logging with non-repudiation

## Use Cases for Security Researchers

1. **Authorized Penetration Testing**: Systematic vulnerability assessment with comprehensive documentation
2. **Bug Bounty Programs**: Large-scale vulnerability discovery with evidence collection
3. **Security Code Review**: Automated detection of known vulnerability patterns
4. **Compliance Assessment**: Regulatory scanning (PCI DSS, HIPAA, SOC 2)
5. **Red Team Operations**: Attack surface enumeration and exploitation support
6. **Vulnerability Research**: Custom template development for new attack vectors
7. **Security Training**: Hands-on lab environment for vulnerability identification

## Advanced Features

### Custom Payloads
- Fuzzing integration for parameter discovery
- Wordlist-based payload generation
- Dynamic payload encoding (URL, Base64, Hex, Unicode)
- Conditional payload mutation based on responses

### Reporting & Analytics
- Comparison reports between assessments
- Trend analysis and risk scoring
- SLA tracking for remediation
- Integration with JIRA, Azure DevOps, GitHub Issues

### Threat Intelligence
- NVD/MITRE database synchronization
- Zero-day exploit information tracking
- Vendor advisory monitoring
- STIX 2.1/TAXII compatible feeds

## Integration Capabilities

- **SIEM**: Splunk, ELK, ArcSight (CEF/Syslog)
- **Ticketing**: JIRA, Azure DevOps, ServiceNow
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins
- **Asset Management**: ServiceNow, CMDB integration
- **Webhooks**: Custom integration endpoints

## Contributing

Security researchers and developers are welcome to contribute:
1. Fork the repository
2. Create a feature branch
3. Submit comprehensive pull requests with tests
4. Follow security disclosure guidelines for vulnerabilities

## Security Disclosure

For responsible disclosure of security vulnerabilities, email: security@webvapt-project.io
Please do not publicly disclose security issues until they have been addressed.

## License

MIT License - See LICENSE file for details

## Support & Professional Services

For enterprise support, custom development, and consulting services:
- Email: support@webvapt-project.io
- Consulting: Schedule a security assessment with our team
- Training: Secure the training programs for development teams

## Disclaimer

**LEGAL WARNING**: This tool is intended ONLY for authorized security testing, penetration testing, and vulnerability assessment on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. Users are responsible for ensuring all testing is conducted legally and ethically.

---

**WebVAPT** - Empowering security researchers with professional-grade vulnerability assessment tools.
