# WebShield AI

WebShield AI is a conservative, local-first command-line tool for authorized web application checks. Its checks and finding prioritizer are deterministic rules; despite the project name, it does **not** use an AI or machine-learning model.

## Scope and limitations

- The base scan checks one explicitly authorized path. Optional local/private-only features provide same-origin GET-only crawling, standard HTML form authentication, and harmless SQL-error/reflected-input indicators.
- It does not follow redirects. A `Location` value is reported for manual review.
- Public targets must use HTTPS on port 443. A local/private target requires the separate `--allow-local` development flag.
- The hostname must exactly match `--allow-host`. DNS is resolved once, all returned addresses are checked against the selected network policy, and the connection uses a vetted resolved address rather than resolving the hostname again.
- Responses are bounded to 64 KiB and request timeouts are enforced. Page content, credentials, cookies, CSRF tokens, authorization values, and query values are not included in reports.
- Crawling, authentication, and SQL/XSS indicator checks are restricted to validated localhost/private targets. Crawling and checks are constrained to explicitly approved path scopes.
- Header recommendations depend on application design. Missing headers are not proof of an exploitable vulnerability.
- SQL-error and reflected-input checks are indicators, not proof. They cannot detect every SQL injection or XSS issue; stored/DOM XSS and POST/body parameters are not tested.
- A passing result does not prove a website is secure. This tool is not a substitute for a professional assessment.
- Authorization flags are safeguards, not permission and not a complete sandbox. Obtain explicit permission before every scan.

## Features

- Certificate validity, issuer, subject, expiration, and negotiated TLS version.
- Checks for HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and clickjacking framing policy.
- Stable finding IDs, evidence, severity, explanations, remediation guidance, and public documentation references.
- JSON, escaped HTML, and PDF reports.
- Optional authenticated scans with same-origin POST-based HTML form login, in-memory session cookies, hidden credential prompts/environment variables, and configurable CSRF/success/failure indicators.
- A bounded same-origin crawler with page/depth/time/rate limits, path allowlists, route exclusions, form inspection, and no form submission.
- Local/private-only SQL error and reflected-XSS indicators limited to configured GET endpoints and input fields; no active script payloads or destructive SQL.
- A transparent severity/status rule-based prioritizer. Confidence is not calibrated and no model prediction is used.
- Explicit authorization confirmation, exact-host matching, DNS/IP scope checks, timeouts, response-size limits, and no redirect following.

## Architecture

- `webshield/scanner.py`: URL authorization, DNS address vetting/pinning, and single-request scanner.
- `webshield/auth.py`: same-origin HTML form authentication using a pinned `requests` session; TLS verification remains enabled.
- `webshield/crawler.py`: bounded local/private same-origin discovery and inspection-only forms.
- `webshield/input_checks.py`: explicitly configured benign SQL error/reflection indicators.
- `webshield/sqli_checker.py` and `webshield/xss_checker.py`: separate quote-only SQL error and inert reflected-input checks.
- `webshield/scope.py` and `webshield/redaction.py`: path/origin scope enforcement and report sanitization.
- `webshield/tls_checker.py`: certificate and TLS metadata checks using system trust roots.
- `webshield/header_checker.py`: deterministic security-header rules.
- `webshield/analyzer.py`: finding assembly and explainable deterministic prioritization. There is no trained model or labeled dataset.
- `webshield/reporter.py`: JSON, HTML, and ReportLab PDF rendering.
- `webshield/cli.py`: argument validation, progress output, exit codes, and report handling.

No scan data is sent to an external analysis service. TLS certificate validation is never disabled. Authentication and input indicator checks do not operate on public targets.

## Requirements and installation

Python 3.10 or newer is supported. Python 3.12 is suitable for development. Runtime dependencies are Requests for maintained session/cookie handling and ReportLab for PDF output.

### Windows 11 / PowerShell

From the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m webshield.cli --help
```

If PowerShell blocks activation, invoke the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m webshield.cli --help
```

### Kali Linux

From the project directory:

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m webshield.cli --help
```

Normal scans do not require root privileges. If your Kali environment enforces externally managed Python packages, keep using the project virtual environment rather than installing into system Python.

## Usage

Only scan targets you own or have explicit authorization to test. Replace the example hostname with the exact authorized hostname:

```powershell
python -m webshield.cli scan https://AUTHORIZED-HOSTNAME/ `
  --allow-host AUTHORIZED-HOSTNAME `
  --confirm-authorized `
  --format json html pdf
```

Bash equivalent:

```bash
python -m webshield.cli scan https://AUTHORIZED-HOSTNAME/ \
  --allow-host AUTHORIZED-HOSTNAME \
  --confirm-authorized \
  --format json html pdf
```

Formats are `json`, `html`, and `pdf`; if omitted, only JSON is produced. To choose a report directory, add `--output-dir PATH`. Use `python -m webshield.cli scan --help` for all options. The original script remains a compatibility entry point and accepts the same scan arguments:

```bash
python webshield.py https://AUTHORIZED-HOSTNAME/ --allow-host AUTHORIZED-HOSTNAME --confirm-authorized
```

### Locally owned development server

Start a local HTTP server that you own, then authorize its exact hostname and port. This development-only option also allows HTTP and nonstandard ports; it does not change the exact-host or address checks:

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

In a second terminal:

```powershell
python -m webshield.cli scan http://localhost:8000/ `
  --allow-host localhost `
  --confirm-authorized `
  --allow-local `
  --format json html
```

The scanner warns when local mode is enabled. The HTTP test server is not a TLS test; its TLS state is reported as not checked.

### Windows XAMPP/PHP

Start Apache in the XAMPP Control Panel and use the application route you own. The exact starting path is authorized; a trailing-slash `--allowed-path` additionally authorizes descendants for crawling:

```powershell
python -m webshield.cli scan http://localhost/event-registration/admin/dashboard.php `
  --allow-host localhost `
  --confirm-authorized `
  --allow-local `
  --allowed-path /event-registration/admin/ `
  --crawl --max-pages 10 --max-depth 2 `
  --format json html
```

The crawler only requests pages within the allowed path and excludes common logout, delete, payment, registration, settings, and administrative action routes. It inspects forms but never submits them. A GET endpoint can still have side effects in a poorly designed application, so use a disposable local dataset.

### Optional standard HTML form authentication

Create a local JSON file such as `auth-config.json`. It contains configuration only—not credentials:

```json
{
  "login_url": "http://localhost/event-registration/login.php",
  "username_field": "username",
  "password_field": "password",
  "csrf_field": "csrf_token",
  "success_indicator": "Welcome",
  "failure_indicator": "Invalid credentials",
  "username_env": "WEBSHIELD_USERNAME",
  "password_env": "WEBSHIELD_PASSWORD"
}
```

Set only the username environment variable if you prefer a hidden password prompt; omit both to be prompted for both credentials:

```powershell
$env:WEBSHIELD_USERNAME = Read-Host "Test account username"
python -m webshield.cli scan http://localhost/event-registration/admin/dashboard.php `
  --allow-host localhost --confirm-authorized --allow-local `
  --allowed-path /event-registration/admin/ --auth-config .\auth-config.json
```

The login URL and form action must be on the exact validated origin, the first form must use POST, and redirects are never followed. A configured success marker must appear in the response body or same-origin redirect destination; a failure marker stops scanning. Hidden inputs are sent as form fields to support CSRF tokens but are never stored in reports. Custom JavaScript login flows may need application-specific configuration and are not automated. CAPTCHA/MFA bypass and access-control bypass are not supported.

### Safe SQL/XSS indicators (local/private targets only)

The local JSON configuration names only approved GET paths and parameter names; do not put secrets or values in it:

```json
{
  "endpoints": [
    {
      "path": "/event-registration/search.php",
      "parameters": ["q"]
    }
  ]
}
```

Run only against your local/private training application and explicitly allow the endpoint path:

```powershell
python -m webshield.cli scan http://localhost/event-registration/search.php `
  --allow-host localhost --confirm-authorized --allow-local `
  --allowed-path /event-registration/ --probe-config .\probe-config.json `
  --check-sqli --check-xss
```

The SQL check compares a benign baseline with a quote-only input and looks for common database error text. The reflected-input check sends an inert marker containing markup delimiters; it never sends script/event-handler payloads or executes page content. Results are marked potential/informational and must be manually verified. Stored XSS, DOM XSS, POST/body fields, and unconfigured inputs are skipped. At most 10 endpoints and 10 fields are accepted; one field can generate at most three bounded GET requests across both checks, with a one-second minimum interval.

### Kali Linux VM networking

For an XAMPP host and Kali guest, prefer a host-only/private VM network. Determine the Windows host-only adapter address and authorize that exact private address with `--allow-host`; bind Apache/firewall access only as needed for the isolated test. Use `--allow-local` for the private address, and explicitly allow the application path. Avoid exposing Apache on a bridged/public interface. The extra authenticated, crawler, and SQL/XSS indicator features reject public targets even when the base scanner permits an HTTPS public scan.

## Reports

By default, timestamped reports are written to the workspace's `reports/` directory. Use `--output-dir` to select another directory. Generated reports are excluded from version control by `.gitignore`. JSON, HTML, and PDF reports include target origin, approved paths, timestamp/version, checks performed/skipped, errors, prioritized findings, status, confidence limitations, evidence, remediation, and known limitations. URLs are sanitized and query values are redacted; response bodies, credentials, cookies, authorization headers, and CSRF values are not reported.

## Exit status

- `0`: homepage request completed and requested reports were written (findings may still exist).
- `1`: homepage request failed; the failure is reported and no successful scan is claimed.
- `2`: invalid invocation/authorization or report generation failure.

## Troubleshooting

- **Permission confirmation required:** include `--confirm-authorized` only when you have permission.
- **Hostname does not match:** `--allow-host` must be the exact URL hostname; subdomains are not implicitly included.
- **Local/private targets are blocked:** use `--allow-local` only for a target you own or are authorized to test.
- **Public HTTP/nonstandard port rejected:** public scans require HTTPS on port 443.
- **DNS or connection error:** confirm DNS and network access. The scan does not retry by resolving the name again.
- **PDF dependency error:** install dependencies in the active virtual environment with `python -m pip install -r requirements.txt`.
- **Certificate validation error:** inspect the target certificate and local trust store. WebShield does not offer an option to disable certificate verification.

## Legal and ethical use

You are responsible for obtaining written authorization and complying with applicable laws, contracts, and rules of engagement. The confirmation flags do not grant permission and cannot enforce a complete isolation boundary. Do not scan systems without authorization. For a production engagement, define the hostname, allowed request rate, timing, and scope with the system owner first.

## Development and tests

```powershell
python -m unittest discover -v
python -m pip check
python -m webshield.cli --help
python -m webshield.cli scan --help
```

Tests use mocks and local-only mock/training HTTP servers. They do not scan public websites. The rule-based prioritizer is not ML and has no measured precision, recall, F1, or accuracy; confidence labels are explicitly uncalibrated.#   W e b S h i e l d - A I - p r o j e c t  
 