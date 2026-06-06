# InfoLeakHunter

**Automated Information Disclosure Vulnerability Scanner**

InfoLeakHunter is a defensive-only security tool designed for authorized penetration testers and security researchers to identify information disclosure vulnerabilities in web applications. It scans for exposed sensitive files, secrets, configuration data, metadata, and other information leakage vectors.

> **⚠️ LEGAL & ETHICAL USE ONLY**
> This tool is for authorized security assessments only. Unauthorized scanning of systems you do not own or have explicit written permission to test is illegal.

## Features

### Scanner Modules (12)
| Module | Description |
|---|---|
| **Sensitive File Discovery** | `.env`, `config.php`, `.git/`, `backup.zip`, `robots.txt`, and 70+ paths |
| **HTTP Header Disclosure** | Server, X-Powered-By, X-AspNet-Version, Via, and 20+ leaking headers |
| **Source Code Disclosure** | HTML comments, TODO/FIXME, internal URLs, emails, API endpoints |
| **JavaScript Analysis** | Downloads & analyzes JS files for secrets, tokens, JWTs, endpoints |
| **Secret Detection** | Regex + entropy analysis for AWS, Azure, GCP, GitHub, Stripe, and 30+ types |
| **Error Disclosure** | PHP traces, Python tracebacks, Java exceptions, ASP.NET errors, and more |
| **Directory Listing** | Detects Apache/Nginx directory listings and browsable storage |
| **API Documentation** | Swagger UI, OpenAPI JSON, GraphQL Playground, GraphiQL, Redoc |
| **Git Exposure** | .git/config, HEAD, index files, metadata, branch references |
| **Cloud Exposure** | AWS S3, Azure Storage, GCP buckets, CloudFront, and cloud references |
| **Metadata Extraction** | PDF, DOCX, XLSX, PPTX author/creator/path disclosure |
| **DNS Leakage** | TXT records, SPF, DKIM, DMARC, subdomain enumeration, PTR records |

### Reporting
- JSON, CSV, HTML, Markdown formats
- Rich terminal UI with progress bars and live statistics
- CWE/OWASP mapping with CVSS estimation
- Severity engine (Critical/High/Medium/Low/Informational)
- Confidence scoring (Certain/High/Medium/Low/Speculative)
- Duplicate finding suppression via fingerprinting
- Remediation guidance for each finding type

### Performance
- Asynchronous engine with `asyncio` + `aiohttp`
- 1000+ concurrent URL scanning
- Connection pooling with retry logic
- Smart rate limiting
- User-Agent rotation
- Configurable timeouts and SSL controls

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/infoleakhunter.git
cd infoleakhunter

# Install dependencies
pip install -r requirements.txt

# Verify installation
python infoleakhunter.py --version
```

### System Requirements
- Python 3.10+
- Linux (primary target), macOS, Windows
- Network connectivity to target(s)
- **dnspython** for DNS analysis (installed via requirements.txt)

## Usage

### Basic Scanning

```bash
# Scan a single URL
python infoleakhunter.py -u https://example.com

# Scan multiple URLs from a file
python infoleakhunter.py -l urls.txt

# Scan with verbose output
python infoleakhunter.py -u https://example.com -v
```

### Generating Reports

```bash
# JSON report
python infoleakhunter.py -u https://example.com --json report.json

# HTML dashboard
python infoleakhunter.py -u https://example.com --html report.html

# CSV report
python infoleakhunter.py -u https://example.com --csv report.csv

# Markdown report
python infoleakhunter.py -u https://example.com --md report.md

# Multiple reports at once
python infoleakhunter.py -u https://example.com --json report.json --html report.html --md report.md
```

### Advanced Usage

```bash
# High concurrency scanning (500 threads)
python infoleakhunter.py -l urls.txt --threads 500

# Custom configuration
python infoleakhunter.py -u https://example.com --config custom_config.yaml

# Disable specific checks
python infoleakhunter.py -u https://example.com --no-dns --no-js --no-metadata

# Disable SSL verification (for internal/testing targets)
python infoleakhunter.py -u https://internal.example.com --no-verify-ssl

# Quiet mode (no console output)
python infoleakhunter.py -u https://example.com --html report.html -q
```

## Configuration

Edit `config.yaml` to customize:

- **Request settings**: timeout, retries, rate limiting, concurrency
- **HTTP headers**: custom headers and User-Agent rotation
- **Sensitive file paths**: add custom paths to scan
- **Secrets detection**: entropy thresholds and enabled checks
- **Scan options**: DNS lookups, JS analysis, metadata extraction

## Output

### Severity Levels
| Severity | Description |
|---|---|
| **Critical** | Exposed credentials, secrets, private keys, git repos |
| **High** | Sensitive files, cloud identifiers, stack traces |
| **Medium** | Headers, directory listings, API docs, internal URLs |
| **Low** | Metadata, DNS info, comment disclosure |
| **Informational** | robots.txt, sitemap.xml, security.txt |

### Finding Structure
```json
{
  "target": "https://example.com",
  "module": "secrets",
  "title": "AWS Access Key ID discovered",
  "severity": "Critical",
  "confidence": "Certain",
  "evidence": "...AKIAIOSFODNN7EXAMPLE...",
  "cwe": "CWE-798",
  "owasp": "OWASP:API8",
  "recommendation": "Immediately revoke and rotate exposed credentials...",
  "url": "https://example.com/.env",
  "cvss_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C"
}
```

## Project Structure

```
InfoLeakHunter/
├── infoleakhunter.py          # Entry point
├── config.yaml                # Default configuration
├── requirements.txt           # Dependencies
├── README.md                  # Documentation
├── infoleakhunter/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # CLI argument parser
│   ├── engine.py              # Scanning engine
│   ├── config.py              # Configuration loader
│   ├── exceptions.py          # Custom exceptions
│   ├── models/
│   │   └── finding.py         # Finding data model
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── base.py            # Base scanner class
│   │   ├── sensitive_files.py # 70+ sensitive paths
│   │   ├── http_headers.py    # 25+ disclosure headers
│   │   ├── source_code.py     # Comments, URLs, emails
│   │   ├── javascript.py      # JS file analysis
│   │   ├── secrets.py         # 30+ secret patterns
│   │   ├── errors.py          # 18 error patterns
│   │   ├── directory_listing.py
│   │   ├── api_docs.py        # Swagger, GraphQL, Redoc
│   │   ├── git_exposure.py    # 17 git paths
│   │   ├── cloud_exposure.py  # 25 cloud patterns
│   │   ├── metadata.py        # PDF, Office docs
│   │   └── dns.py             # TXT, MX, CNAME, SPF
│   ├── reporter/
│   │   ├── json_reporter.py
│   │   ├── csv_reporter.py
│   │   ├── html_reporter.py
│   │   ├── markdown_reporter.py
│   │   └── console_reporter.py
│   ├── utils/
│   │   ├── http_client.py     # Async HTTP client
│   │   ├── entropy.py         # Shannon entropy
│   │   ├── progress.py        # Rich progress bars
│   │   ├── fingerprints.py    # Tech detection
│   │   └── severity.py        # Scoring engine
│   └── tests/
│       ├── test_finding.py
│       ├── test_entropy.py
│       ├── test_severity.py
│       ├── test_scanners.py
│       └── test_reporters.py
└── sample_reports/
    ├── report.json
    ├── report.csv
    ├── report.html
    └── report.md
```

## Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest infoleakhunter/tests/ -v

# Run specific test file
pytest infoleakhunter/tests/test_finding.py -v
```

## Defense Recommendations

If findings are identified:

1. **Immediately** revoke and rotate exposed credentials/secrets
2. **Remove** sensitive files from web-accessible directories
3. **Disable** directory listing on web servers
4. **Configure** servers to suppress version headers
5. **Disable** debug mode in production environments
6. **Restrict** access to API documentation endpoints
7. **Remove** .git directories from production deployments
8. **Sanitize** document metadata before publishing
9. **Implement** CSP headers to limit JS-based exfiltration
10. **Use** secret scanning tools in CI/CD pipelines

## License

This tool is provided for authorized security testing only. Users are responsible for compliance with applicable laws.

## Disclaimer

The authors assume no liability for any damage caused by misuse of this tool. Use responsibly and only on systems you own or have explicit permission to test.
