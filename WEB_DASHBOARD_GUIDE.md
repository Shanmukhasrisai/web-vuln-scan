# WebVAPT Web Dashboard & UI Guide

## 🌐 Modern Enterprise Web Interface

WebVAPT includes a powerful, intuitive web dashboard for managing vulnerability assessments, scanning operations, and security reporting.

---

## Dashboard Access & Authentication

### Default Access
```bash
URL: https://localhost:8443/dashboard
Default Admin: admin@webvapt.local
Default Password: (Set during setup)
```

### Authentication Methods
- Local user accounts with MFA
- SAML 2.0 / OAuth 2.0
- LDAP / Active Directory
- API Keys for programmatic access

---

## Core Dashboard Sections

### 1. 📊 Main Dashboard

**Key Metrics Overview**
```
┌─────────────────────────────────────────────────────┐
│           WebVAPT Enterprise Dashboard              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Active Scans: 12  │ Pending: 8  │ Failed: 2     │
│  Total Vulnerabilities: 2,847  │ Fixed: 1,254  │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │ Risk Score Trend (Last 30 days)             │  │
│  │ [Graph showing risk score trajectory]       │  │
│  └─────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────┐  ┌──────────────────┐      │
│  │ CRITICAL: 45     │  │ HIGH: 128        │      │
│  │ MEDIUM: 234      │  │ LOW: 892         │      │
│  └──────────────────┘  └──────────────────┘      │
│                                                     │
│  Top 5 Vulnerabilities This Week                 │
│  1. SQL Injection - Login Form (12 instances)    │
│  2. XSS in Search (8 instances)                  │
│  3. Missing Security Headers (15 apps)           │
│  4. Weak TLS Configuration (3 APIs)              │
│  5. Exposed API Keys (2 instances)               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Dashboard Widgets (Customizable)**
- Active scans progress
- Vulnerability severity distribution
- Risk score trends
- Remediation status
- Scan schedule calendar
- Team activity feed

### 2. 🔍 Vulnerability Management

**Vulnerability List View**
- Advanced filtering (severity, status, asset, date)
- Bulk operations (assign, close, export)
- Sort by CVSS score, date, status
- Quick view of POC and remediation

**Vulnerability Details**
```
CVE-2024-XXXXX
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: Critical SQL Injection Vulnerability
Severity: CRITICAL (CVSS 9.8)
Affected: 3 targets
Found: 2024-01-01
Status: Open → In Progress

Description:
[Detailed vulnerability description]

Proof of Concept:
[Request/Response examples]

Remediation:
1. Implement parameterized queries
2. Input validation
3. WAF rules

References:
- CVE: https://nvd.nist.gov/...
- CWE-89: SQL Injection
```

**Workflow Management**
- Status transitions: Open → Assigned → In Progress → Fixed → Verified → Closed
- Assignment to team members
- Add comments and notes
- Attach evidence/screenshots
- Link to JIRA/Azure DevOps

### 3. 📅 Scan Management

**Scan Creation Wizard**
1. Select targets (URL, IP range, API endpoint)
2. Choose scan profile (Quick, Standard, Deep, Compliance)
3. Select templates (200+ CVE templates)
4. Set schedule (immediate, scheduled, recurring)
5. Configure notifications
6. Review and launch

**Active Scan Monitoring**
- Real-time progress bars
- Current requests/sec
- Templates tested
- Time elapsed/remaining
- Stop/Pause/Resume controls

**Scan History**
- Previous scan results
- Comparison between scans
- Result trends
- Export historical data

### 4. 📈 Reports & Analytics

**Report Builder**
- Executive summary
- Technical details
- Compliance mapping
- Risk assessment
- Custom sections

**Report Formats**
- PDF (Professional, colored)
- DOCX (Editable)
- HTML (Interactive)
- JSON/XML (API integration)
- CSV (Data analysis)

**Compliance Dashboards**
- PCI DSS 4.0 Coverage
- HIPAA Requirements
- GDPR Controls
- OWASP Top 10
- NIST Mapping

### 5. 👥 Team Management

**User Management**
- Create/edit user accounts
- Assign roles (Admin, Manager, Analyst, Viewer)
- MFA enrollment
- API key generation
- Activity audit log

**Role-Based Access Control**
```
Admin: Full system access, user management
Manager: Team oversight, report approval
Analyst: Create scans, manage vulnerabilities
Viewer: Read-only access to reports
```

**Team Collaboration**
- Comments on vulnerabilities
- @mentions for notifications
- Approval workflows
- Activity timeline

### 6. ⚙️ Settings & Configuration

**General Settings**
- Organization name/logo
- Default scan profiles
- Notification settings
- Report templates

**Integrations**
- JIRA API configuration
- Slack webhooks
- Email server settings
- Custom webhook endpoints

**Threat Intelligence**
- NVD sync schedule
- MITRE feed settings
- Vendor advisory feeds
- Custom threat feeds

**Security Settings**
- Password policy
- Session timeout
- IP whitelist
- API rate limiting

---

## Advanced Features

### 📊 Custom Dashboards
```javascript
// Create custom metric dashboard
{
  "name": "Executive Risk Dashboard",
  "widgets": [
    {
      "type": "risk_score",
      "period": "30days",
      "title": "Current Risk Posture"
    },
    {
      "type": "critical_count",
      "filters": {"status": "open"}
    },
    {
      "type": "remediation_progress",
      "timeline": "quarterly"
    }
  ]
}
```

### 🔔 Smart Notifications
- Critical vulnerability alerts
- Scan completion notifications
- SLA breach warnings
- Team task assignments
- Integration with Slack/Email

### 📱 Mobile Responsive
- Full functionality on tablets
- Optimized for mobile viewing
- Quick actions on smartphone
- Offline capability for read-only

### 🎨 Customization
- Theme (Light/Dark mode)
- Custom branding
- Widget arrangement
- Color schemes
- Font sizes

---

## API Integration Examples

### Start Scan via API
```bash
curl -X POST https://api.webvapt.local/v1/scans \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "profile": "standard",
    "templates": ["sql-injection", "xss-*"],
    "callback": "https://your-system.local/webhook"
  }'
```

### Get Vulnerability Data
```bash
curl https://api.webvapt.local/v1/vulnerabilities \
  -H "Authorization: Bearer TOKEN" \
  -d 'filter[severity]=critical&filter[status]=open'
```

---

## Keyboard Shortcuts

```
G + D     Go to Dashboard
G + S     Go to Scans
G + V     Go to Vulnerabilities
G + R     Go to Reports
S         Start new scan
/         Search vulnerabilities
C         Create comment
L         Toggle light/dark theme
```

---

## Performance Tips

1. **Data Loading**: Use filters to limit displayed data
2. **Dashboard**: Customize widgets for relevant metrics
3. **Reports**: Schedule generation during off-hours
4. **Exports**: Use CSV for large dataset analysis
5. **API**: Implement pagination for bulk data retrieval

---

## Troubleshooting

### Dashboard not loading
- Clear browser cache
- Check JavaScript console for errors
- Verify API connectivity
- Check authentication token validity

### Reports not generating
- Check available disk space
- Verify PDF generation service running
- Check database connectivity
- Review application logs

### Performance issues
- Reduce date range in filters
- Disable real-time updates temporarily
- Check browser resource usage
- Review server logs

---

## Best Practices

✅ Regular backups of vulnerability data  
✅ Use RBAC for access control  
✅ Enable MFA for all accounts  
✅ Review audit logs periodically  
✅ Update threat intelligence feeds  
✅ Schedule scans during off-peak hours  
✅ Archive old scan results  
✅ Test integrations regularly  

---

For support: support@webvapt-enterprise.io
