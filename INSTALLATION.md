# WebVAPT - Super Easy Installation Guide

## ROCKET Quick Start - Installation for Everyone

Choose your preferred installation method. **We've made installation SUPER EASY!**

---

## Option 1: Linux/macOS - 5 Minutes (SIMPLEST)

Fastest way to install WebVAPT on Linux or macOS.

### Step 1: Open Terminal
Copy-paste the commands below into your terminal.

### Step 2: Install Go
```bash
# On macOS
brew install go

# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install golang-go

# On Fedora/CentOS
sudo dnf install golang
```

### Step 3: Clone Repository
```bash
git clone https://github.com/Shanmukhasrisai/web-vuln-scan.git
cd web-vuln-scan
```

### Step 4: Build
```bash
go build -o webvapt main.go
```

### Step 5: Run
```bash
# Start the web dashboard
./webvapt server --host 0.0.0.0 --port 8080
```

**DONE! OPEN http://localhost:8080/dashboard in browser**

---

## Option 2: Docker - 3 Minutes (RECOMMENDED)

Easiest if you have Docker installed.

### Step 1: Install Docker
- **Windows/macOS**: Download from https://www.docker.com/products/docker-desktop
- **Linux**: `sudo apt-get install docker.io`

### Step 2: Clone & Build
```bash
git clone https://github.com/Shanmukhasrisai/web-vuln-scan.git
cd web-vuln-scan
docker build -t webvapt:latest .
```

### Step 3: Run Container
```bash
docker run -d -p 8080:8080 \
  -e API_KEY="your-secret-key" \
  --name webvapt \
  webvapt:latest
```

### Step 4: Access Dashboard
**OPEN http://localhost:8080/dashboard in browser**

---

## Option 3: Windows - GUI Installation

For Windows users.

### Step 1: Download Go
1. Visit https://go.dev/dl/
2. Download `go1.21.windows-amd64.msi`
3. Double-click installer (next > next > finish)

### Step 2: Download Git
1. Visit https://git-scm.com/download/win
2. Download and install

### Step 3: Clone
Open Command Prompt:
```bash
git clone https://github.com/Shanmukhasrisai/web-vuln-scan.git
cd web-vuln-scan
```

### Step 4: Build & Run
```bash
go build -o webvapt.exe main.go
webvapt.exe server --host 0.0.0.0 --port 8080
```

### Step 5: Access Dashboard
**OPEN http://localhost:8080/dashboard in browser**

---

## Option 4: Kubernetes (ENTERPRISE)

For organizations with Kubernetes.

### Step 1: Clone
```bash
git clone https://github.com/Shanmukhasrisai/web-vuln-scan.git
cd web-vuln-scan
```

### Step 2: Deploy
```bash
kubectl create namespace webvapt
kubectl create secret generic webvapt-secrets \
  --from-literal=api-key=your-key -n webvapt
kubectl apply -f k8s/deployment.yaml -n webvapt
kubectl expose deployment webvapt --type=LoadBalancer --port=8080 -n webvapt
```

### Step 3: Get URL
```bash
kubectl get svc -n webvapt
# Use the EXTERNAL-IP:8080/dashboard
```

---

## VERIFY Installation

### Check if running:
```bash
# Linux/macOS/Windows
curl http://localhost:8080/api/v1/health

# Expected response:
# {"status": "healthy", "version": "1.0.0"}
```

---

## COMMON PROBLEMS & SOLUTIONS

### Problem: "go: command not found"
**FIX:** Install Go from https://go.dev/dl/

### Problem: "Port 8080 already in use"
**FIX:** Use different port
```bash
./webvapt server --port 8081
# Then access: http://localhost:8081/dashboard
```

### Problem: "Permission denied"
**FIX (Linux/macOS):**
```bash
chmod +x webvapt
./webvapt server
```

### Problem: "Docker not found"
**FIX:** Install Docker from https://www.docker.com/products/docker-desktop

### Problem: "Can't access dashboard"
**FIX:** Check if service running
```bash
# Check if running
ps aux | grep webvapt

# Check port
netstat -tlnp | grep 8080
```

---

## FIRST SCAN - Quick Start

### Via Dashboard:
1. Open http://localhost:8080/dashboard
2. Click "Create New Scan"
3. Enter target: https://example.com
4. Select "Quick Scan"
5. Click "Start Scan"
6. Wait 30 seconds - 5 minutes
7. View results
8. Download PDF report

### Via Command Line:
```bash
# Quick scan
./webvapt scan --target https://example.com

# Full scan with templates
./webvapt scan \
  --target https://example.com \
  --templates sql-injection,xss-* \
  --profile standard \
  --output results.json
```

---

## NEXT STEPS

1. Open dashboard: http://localhost:8080/dashboard
2. Read guides:
   - ENTERPRISE_FEATURES.md
   - WEB_DASHBOARD_GUIDE.md  
   - README.md
3. Run first scan
4. Create user accounts
5. Configure integrations

---

## SYSTEM REQUIREMENTS

### Minimum
- CPU: 2 cores
- RAM: 2 GB  
- Disk: 10 GB

### Recommended
- CPU: 8+ cores
- RAM: 16+ GB
- Disk: 100+ GB
- Linux (Ubuntu 20.04+)

---

## CONFIGURATION (Optional)

Create `config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8080
  tls: false

scanning:
  threads: 50
  timeout: 30
  retries: 3

integrations:
  jira:
    enabled: true
    url: https://jira.company.com
    api_key: your_key
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/...
```

Run with config:
```bash
./webvapt server --config config.yaml
```

---

## SUCCESS!

You have installed WebVAPT! 

### What's Next?
- OPEN http://localhost:8080/dashboard
- Start your first scan
- View vulnerabilities
- Generate reports
- Invite team members

### Need Help?
- Troubleshooting section above
- Check ENTERPRISE_FEATURES.md
- Email: support@webvapt-project.io

---

**HAPPY SCANNING!**
