import requests
import sys
import argparse

class WebVulnScanner:
    COMMON_PATHS = ["/admin", "/login", "/.git", "/.env", "/config", "/phpinfo.php", "/test", "/backup", "/.DS_Store"]

    def __init__(self, target):
        self.target = target.rstrip('/')

    def check_path_exposure(self):
        print(f"[+] Checking for common sensitive paths on {self.target}")
        for path in self.COMMON_PATHS:
            url = f"{self.target}{path}"
            try:
                resp = requests.get(url, timeout=7)
                if resp.status_code == 200:
                    print(f"[!] {url} is exposed!")
            except Exception as e:
                print(f"[-] Error checking {url}: {e}")

    def run(self):
        self.check_path_exposure()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner (Python)")
    parser.add_argument("target", help="Base URL of the target (e.g., https://example.com)")
    args = parser.parse_args()

    scanner = WebVulnScanner(args.target)
    scanner.run()
