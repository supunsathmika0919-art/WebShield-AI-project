# 🛡️ WebShield AI

### An Open-Source Web Application Security Scanner Built with Python

WebShield AI is a Python-based command-line security scanner designed to help developers assess the security configuration of web applications they own or are explicitly authorized to test.

It provides security-header analysis, TLS checks, bounded web crawling, authentication support, basic SQL injection indicators, passive reflected-input checks, and structured security reports.

> **Disclaimer:** WebShield AI is intended for authorized defensive security testing only. Always obtain permission before scanning a target.

## ✨ Features

- **Security Header Analysis** — Checks for important HTTP security headers and reports missing configurations.
- **TLS Checks** — Examines TLS-related security configuration.
- **Scoped Scanning** — Supports explicit host and path restrictions.
- **Authentication Support** — Supports configured same-origin HTML form authentication for authorized applications.
- **Web Crawling** — Discovers same-origin pages within configured crawl limits.
- **SQL Injection Indicators** — Identifies selected database error indicators; these do not independently confirm SQL injection vulnerabilities.
- **XSS Indicators** — Performs passive reflected-input checks; reflection alone does not confirm executable XSS.
- **Finding Prioritization** — Organizes findings by severity using rule-based analysis.
- **Multiple Report Formats** — Generates JSON, HTML and PDF reports.
- **Secret Redaction** — Designed to prevent sensitive authentication values from appearing in scan output and reports.
- **Automated Tests** — Includes tests for important scanner components and safety controls.

Feature availability and coverage depend on the current implementation and target application. See the limitations section below.

## 🧰 Technology Stack

- Python
- Requests
- HTML parsing libraries used by the project
- ReportLab for PDF reporting
- Python unittest for automated tests

## 📋 Requirements

- Python 3.12 or a compatible version supported by the project
- Git
- Windows PowerShell or Kali Linux
- Network access to the explicitly authorized target

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/supunsathmika0919-art/WebShield-AI-project.git
cd WebShield-AI-project
```

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Kali Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

If editable installation is not supported by the current package configuration, install the documented dependencies using `requirements.txt`.

## 🖥️ Usage

### View available commands

```bash
python -m webshield.cli --help
```

### View scan options

```bash
python -m webshield.cli scan --help
```

### Scan an authorized local application

The following example scans a local application on loopback. Run it only when you own or are authorized to test the target.

```powershell
python -m webshield.cli scan `
  http://127.0.0.1/event-registration/ `
  --allow-host 127.0.0.1 `
  --confirm-authorized `
  --allow-local `
  --allowed-path /event-registration/ `
  --format json html pdf `
  --output-dir reports/local-test
```

This example assumes the application is available at that URL. Adjust the URL and allowed path to match your local test application.

### Optional bounded crawling

Use the crawl option only for an explicitly authorized local/private target:

```powershell
python -m webshield.cli scan `
  http://127.0.0.1/event-registration/ `
  --allow-host 127.0.0.1 `
  --confirm-authorized `
  --allow-local `
  --allowed-path /event-registration/ `
  --crawl `
  --max-pages 10 `
  --max-depth 2 `
  --format json html pdf `
  --output-dir reports/crawl-test
```

### Report formats

WebShield AI supports these output formats:

- `json` — Structured machine-readable findings.
- `html` — Browser-readable report.
- `pdf` — Portable report document.

Reports are written to the selected output directory.

## 🧪 Testing

Run the automated tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

Tests should be run locally. Test results may change as the project evolves. A passing test suite does not guarantee that every vulnerability can be detected in a real application.

## 📊 Security Findings

Depending on the implementation and scan configuration, findings may include:

- Missing HTTP security headers
- TLS configuration concerns
- Server information disclosure
- SQL database error indicators
- Reflected input and output-encoding concerns
- Cookie security configuration issues
- Redirect and authentication verification limitations

Findings are indicators for further investigation, not a guarantee that a vulnerability is exploitable.

## 🔐 Safety and Authorization

WebShield AI is designed for defensive security assessment.

- Scan only systems you own or have explicit permission to test.
- Keep scans within the configured hostname and path scope.
- Use conservative crawl limits and request intervals.
- Avoid destructive actions and state-changing form submissions.
- Never commit credentials, API keys, cookies, tokens or private scan reports.
- Review scan evidence before treating a finding as confirmed.
- Do not use the scanner to access accounts or data without authorization.

## ⚠️ Current Limitations

- Detection coverage is limited to implemented checks.
- A missing security header does not automatically mean a site is exploitable.
- SQL error indicators alone do not prove SQL injection.
- Reflected input alone does not prove cross-site scripting.
- Authentication behavior depends on the target application's login form and configuration.
- Redirects, session expiration and login failures may prevent protected pages from being scanned.
- Business-logic flaws and vulnerabilities requiring manual testing may not be detected.
- Rule-based prioritization is not the same as a trained AI/ML model.
- HTTPS-specific controls must be assessed in an appropriate HTTPS environment.

## 🗺️ Roadmap

- [x] Command-line scanning foundation
- [x] Security-header checks
- [x] JSON, HTML and PDF reporting
- [x] Host and path scope controls
- [x] Automated unit tests for core components
- [ ] Improve authenticated scan verification
- [ ] Improve crawler coverage and diagnostics
- [ ] Expand safe vulnerability indicators
- [ ] Improve false-positive evaluation
- [ ] Add reproducible local integration tests
- [ ] Evaluate a genuine ML-based analysis module

Roadmap items should be marked complete only after implementation and testing.

## 🤝 Contributing

Contributions, bug reports, testing feedback and documentation improvements are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make a focused change.
4. Add or update tests.
5. Run the test suite.
6. Submit a pull request with a clear description.

Please do not include real credentials, private target information or sensitive scan reports in issues or pull requests.

## 📄 License

See the [LICENSE](LICENSE) file for the applicable license terms.

## 👨‍💻 Author

**Supun Sathmika**

GitHub: [@supunsathmika0919-art](https://github.com/supunsathmika0919-art)

---

⭐ If you find WebShield AI useful, consider starring the repository and contributing improvements.

**Built for learning, defensive security testing, and safer web applications.**