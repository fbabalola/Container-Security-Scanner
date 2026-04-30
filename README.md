# Container Security Scanner

Automated container image vulnerability scanning and security assessment using Trivy, with reporting and CI/CD integration capabilities.

## Overview

This tool automates the process of scanning Docker container images for:
- **CVE vulnerabilities** (Critical, High, Medium, Low)
- **Misconfigurations** in Dockerfiles
- **Secret exposure** in image layers
- **Compliance violations** against CIS Docker Benchmarks

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Image Scanning** | Scan multiple images in batch |
| **CVSS Filtering** | Filter results by severity threshold |
| **JSON/HTML Reports** | Generate machine-readable and human-readable reports |
| **CI/CD Integration** | Exit codes for pipeline integration |
| **Baseline Comparison** | Compare against previous scans to track drift |

## Prerequisites

```bash
# Install Trivy (macOS)
brew install aquasecurity/trivy/trivy

# Install Trivy (Linux)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
trivy --version
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/fbabalola/Container-Security-Scanner.git
cd Container-Security-Scanner

# Install Python dependencies
pip install -r requirements.txt

# Scan a single image
python scanner.py --image nginx:latest

# Scan with severity filter (only CRITICAL and HIGH)
python scanner.py --image python:3.9 --severity CRITICAL,HIGH

# Scan multiple images from file
python scanner.py --file images.txt --output report.html
```

## Usage Examples

### Basic Scan
```bash
python scanner.py --image alpine:3.18
```

### Scan with JSON Output
```bash
python scanner.py --image ubuntu:22.04 --format json --output results.json
```

### CI/CD Pipeline Integration
```bash
# Returns exit code 1 if CRITICAL vulnerabilities found
python scanner.py --image myapp:latest --severity CRITICAL --fail-on-vuln
```

### Batch Scanning
```bash
# Create images.txt with one image per line
echo "nginx:latest" > images.txt
echo "python:3.9" >> images.txt
echo "node:18" >> images.txt

# Scan all images
python scanner.py --file images.txt --output batch_report.html
```

## Output Example

```
================================================================================
CONTAINER SECURITY SCAN REPORT
Image: nginx:latest
Scan Date: 2026-04-29 14:30:00
================================================================================

VULNERABILITY SUMMARY
---------------------
CRITICAL: 0
HIGH: 3
MEDIUM: 12
LOW: 8

HIGH SEVERITY FINDINGS
----------------------
[HIGH] CVE-2024-1234 - openssl 1.1.1k
  Description: Buffer overflow in SSL handshake
  Fixed Version: 1.1.1l
  CVSS Score: 7.5

[HIGH] CVE-2024-5678 - curl 7.74.0
  Description: HTTP/2 memory leak
  Fixed Version: 7.75.0
  CVSS Score: 7.1
```

## Project Structure

```
Container-Security-Scanner/
├── README.md
├── requirements.txt
├── scanner.py              # Main vulnerability scanner (Trivy wrapper)
├── cis_check.py            # CIS Docker Benchmark validation
└── examples/
    ├── images.txt          # Example image list for batch scanning
    └── Dockerfile.hardened # Secure Dockerfile template with comments
```

## CIS Docker Benchmark Checks

Beyond CVE scanning, this repo includes a script to check containers against CIS Docker Benchmark:

```bash
# Check a Dockerfile
python cis_check.py --dockerfile ./Dockerfile

# Check a running container
python cis_check.py --container my_container_name

# Example output:
# [4.1] Ensure a user for the container has been created
#   Status: ✅ PASS
#   Details: Found non-root USER directive
```

## Hardened Dockerfile Template

Check `examples/Dockerfile.hardened` for a commented example showing:
- Non-root user creation
- Minimal base images
- Layer caching optimization
- Security-focused runtime flags
- HEALTHCHECK configuration

## CI/CD Integration

### GitHub Actions
```yaml
- name: Container Security Scan
  run: |
    pip install -r requirements.txt
    python scanner.py --image ${{ env.IMAGE_NAME }} --severity CRITICAL,HIGH --fail-on-vuln
```

### GitLab CI
```yaml
container_scan:
  script:
    - pip install -r requirements.txt
    - python scanner.py --image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA --fail-on-vuln
```

## Security Frameworks

This tool supports compliance checking against:
- **CIS Docker Benchmark** - Container hardening standards
- **NIST 800-190** - Application container security guide
- **DISA STIG** - Docker Enterprise container platform requirements

## Author

**Firebami Babalola**  
Security Operations Analyst | SC-200 | Security+

## License

MIT License
