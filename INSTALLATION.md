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

## About API_KEY

**What is API_KEY?**
API_KEY is a security token that authenticates your requests to WebVAPT. It's like a password for the API.

**How to Generate an API Key?**

You can generate one using any of these methods:

### Method 1: Simple Secure Key (Recommended for beginners)
```bash
# On Linux/macOS/Windows PowerShell:
echo "webvapt_$(date +%s)_$(openssl rand -hex 16)" | base64

# Or simpler: just use this format
webvapt_YOUR_SECRET_KEY_HERE
```

### Method 2: Using OpenSSL (Most Secure)
```bash
openssl rand -hex 32
# Example output: 4a7f3c9d2e1b8f6a5c9d2e1b8f6a5c9d2e1b8f6a5c9d2e1b8f6a5c9d2e1b
```

### Method 3: Using Python
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Method 4: Just Use a Simple Key
```
Your_Secure_API_Key_12345
```

**Example Docker Commands with API Keys:**

### Simple Example (For Testing)
```bash
docker run -d -p 8080:8080 \
  -e API_KEY="mySecureKey123" \
  --name webvapt \
  webvapt:latest
```

### Secure Example (For Production)
```bash
# Generate a secure key
API_KEY=$(openssl rand -hex 32)

# Run with secure key
docker run -d -p 8080:8080 \
  -e API_KEY="$API_KEY" \
  -v $(pwd)/data:/root/data \
  --name webvapt \
  webvapt:latest

# Save the key for later use
echo "API Key: $API_KEY" > .webvapt-api-key
```

**Using API Key in Requests:**

```bash
# Start a scan with API key
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "profile": "quick"
  }'
```

**Important Security Tips:**

1. **Never share your API key** - Keep it secret like a password
2. **Rotate keys regularly** - Change them every few months
3. **Use strong keys** - Use the OpenSSL method for security
4. **Store securely** - Don't put keys in code or commit to git
5. **Environment variables** - Store in .env file (don't commit)

**Example .env file:**
```
API_KEY=4a7f3c9d2e1b8f6a5c9d2e1b8f6a5c9d
DOCKER_IMAGE=webvapt:latest
PORT=8080
```

**Load from .env file:**
```bash
source .env
docker run -d -p $PORT:8080 \
  -e API_KEY="$API_KEY" \
  --name webvapt \
  $DOCKER_IMAGE
```

---
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
