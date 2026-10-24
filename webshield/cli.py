"""Command-line interface for WebShield AI."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import Sequence

from webshield.auth import (
    AuthenticationError,
    authenticate,
    load_auth_config,
    resolve_credentials,
    session_cookie_header,
)
from webshield.analyzer import prioritize_findings
from webshield.crawler import crawl
from webshield.input_checks import (
    ProbeConfigError,
    load_probe_config,
    run_input_checks,
    validate_probe_scope,
)
from webshield.reporter import write_reports
from webshield.scanner import (
    TargetResolutionError,
    TargetValidationError,
    scan,
    authentication_failure_report,
    validate_target,
)

DEFAULT_REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webshield",
        description=(
            "Conservative checks for explicitly authorized web paths. This is not a "
            "complete security assessment."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Scan an explicitly authorized URL path")
    scan_parser.add_argument("url", help="Authorized target URL, for example https://example.org/")
    scan_parser.add_argument(
        "--allow-host", required=True,
        help="Exact hostname you own or are explicitly authorized to scan",
    )
    scan_parser.add_argument(
        "--confirm-authorized", action="store_true",
        help="Confirm you have permission to scan this exact target",
    )
    scan_parser.add_argument(
        "--allow-local", action="store_true",
        help="Permit explicitly authorized localhost/private targets; never scans public scope",
    )
    scan_parser.add_argument(
        "--auth-config", type=Path,
        help="Local JSON config for a same-origin HTML form login; credentials are read from env or a hidden prompt",
    )
    scan_parser.add_argument(
        "--allowed-path", action="append",
        help="Explicit approved URL path (repeatable; trailing slash includes descendants)",
    )
    scan_parser.add_argument(
        "--crawl", action="store_true",
        help="Discover same-origin pages and forms with bounded GET-only requests (local/private targets only)",
    )
    scan_parser.add_argument("--max-pages", type=int, help="Maximum crawler pages (1-100; default: 25)")
    scan_parser.add_argument("--max-depth", type=int, help="Maximum crawler link depth (0-5; default: 2)")
    scan_parser.add_argument(
        "--request-timeout", type=float,
        help="Crawler per-request timeout in seconds (0-15; default: 8)",
    )
    scan_parser.add_argument(
        "--request-interval", type=float,
        help="Minimum seconds between crawler requests (0.5-30; default: 1)",
    )
    scan_parser.add_argument(
        "--exclude-path", action="append",
        help="Additional excluded URL path (repeatable)",
    )
    scan_parser.add_argument(
        "--probe-config", type=Path,
        help="JSON configuration listing explicitly approved GET endpoints and input field names",
    )
    scan_parser.add_argument("--check-sqli", action="store_true", help="Check for SQL error indicators only")
    scan_parser.add_argument("--check-xss", action="store_true", help="Check reflected input encoding without active payloads")
    scan_parser.add_argument(
        "--format", nargs="+", choices=("json", "html", "pdf"), default=("json",),
        help="Report formats to create (default: json)",
    )
    scan_parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_REPORT_DIR,
        help="Report directory (default: workspace reports/)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.check_sqli or args.check_xss) and not args.probe_config:
        parser.error("--check-sqli and --check-xss require --probe-config.")
    if args.probe_config and not (args.check_sqli or args.check_xss):
        parser.error("--probe-config requires --check-sqli and/or --check-xss.")
    if not args.crawl and any(
        value is not None
        for value in (
            args.max_pages,
            args.max_depth,
            args.request_timeout,
            args.request_interval,
            args.exclude_path,
        )
    ):
        parser.error("Crawler limits and --exclude-path require --crawl.")
    if args.crawl and (
        (args.max_pages is not None and not 1 <= args.max_pages <= 100)
        or (args.max_depth is not None and not 0 <= args.max_depth <= 5)
        or (args.request_timeout is not None and not 0 < args.request_timeout <= 15)
        or (args.request_interval is not None and not 0.5 <= args.request_interval <= 30)
    ):
        parser.error("Crawler limits are outside their safe configured ranges.")
    if not args.confirm_authorized:
        parser.error(
            "A scan requires --confirm-authorized. The flag is a safeguard, not "
            "a substitute for permission or a sandbox."
        )
    try:
        target = validate_target(
            args.url,
            args.allow_host,
            args.allow_local,
            allowed_paths=args.allowed_path,
        )
    except (TargetValidationError, TargetResolutionError) as error:
        parser.error(str(error))

    if args.allow_local:
        print("WARNING: local/private target mode is enabled; verify the exact target and permission.")
    is_public_target = ipaddress.ip_address(target.resolved_ip).is_global
    if args.crawl and is_public_target:
        parser.error("Crawling is restricted to validated localhost/private targets.")
    if args.auth_config and is_public_target:
        parser.error("Authenticated scanning is restricted to validated localhost/private targets.")
    probe_config = None
    if args.probe_config:
        if is_public_target:
            parser.error("SQL/XSS indicator checks are restricted to validated localhost/private targets.")
        try:
            probe_config = load_probe_config(args.probe_config)
            validate_probe_scope(target, probe_config)
        except ProbeConfigError as error:
            parser.error(str(error))
    print(f"Scanning {target.origin}{target.path} (authorized path scope; redirects are not followed).")
    cookie_header: str | None = None
    if args.auth_config:
        try:
            auth_config = load_auth_config(args.auth_config)
            username, password = resolve_credentials(
                auth_config,
                interactive=sys.stdin.isatty(),
            )
            session = authenticate(target, auth_config, username, password)
            cookie_header = session_cookie_header(session, target)
            session.close()
            del session
            del username, password
        except AuthenticationError as error:
            print(f"ERROR: {error}")
            report = authentication_failure_report(target, str(error))
            try:
                paths = write_reports(report, list(dict.fromkeys(args.format)), args.output_dir)
            except (OSError, RuntimeError, ValueError) as report_error:
                print(f"ERROR: failure report generation failed: {report_error}")
                return 2
            for path in paths:
                print(f"Report saved: {path}")
            return 1
    crawl_result = None
    if args.crawl:
        try:
            crawl_result = crawl(
                target,
                allowed_paths=args.allowed_path,
                max_pages=args.max_pages if args.max_pages is not None else 25,
                max_depth=args.max_depth if args.max_depth is not None else 2,
                request_timeout=args.request_timeout if args.request_timeout is not None else 8,
                min_interval_seconds=(
                    args.request_interval if args.request_interval is not None else 1
                ),
                excluded_paths=args.exclude_path or (),
                cookie_header=cookie_header,
            )
        except ValueError as error:
            parser.error(str(error))
    report = scan(
        target,
        cookie_header,
        crawl_result["root_response"] if crawl_result else None,
    )
    if args.auth_config:
        report["checks_performed"].append("Configured HTML form authentication")
        report["checks_skipped"] = [
            check for check in report["checks_skipped"]
            if check != "Authentication and protected-page checks"
        ]
    if probe_config is not None:
        try:
            input_result = run_input_checks(
                target,
                probe_config,
                check_sqli=args.check_sqli,
                check_xss=args.check_xss,
                cookie_header=cookie_header,
            )
        except ProbeConfigError as error:
            parser.error(str(error))
        report["findings"].extend(input_result["findings"])
        report["checks_performed"].extend(input_result["checks_performed"])
        report["checks_skipped"] = [
            check for check in report["checks_skipped"]
            if check not in {
                "SQL injection and XSS indicators",
            }
        ] + input_result["checks_skipped"]
        report["errors"].extend(input_result["errors"])
    if crawl_result:
        report["crawl"] = {
            key: value for key, value in crawl_result.items()
            if key not in {"findings", "root_response"}
        }
        root_resource = f"{target.origin}{target.path}"
        report["findings"].extend(
            finding for finding in crawl_result["findings"]
            if finding.get("affected_resource") != root_resource
        )
        report["checks_performed"].append("Bounded same-origin page and form discovery")
        report["checks_skipped"] = [
            check for check in report["checks_skipped"]
            if check != "Crawling and form inspection"
        ]
        report["errors"].extend(crawl_result["errors"])
    report["severity_counts"] = {
        severity: sum(
            1 for finding in report["findings"] if finding["severity"] == severity
        )
        for severity in ("Critical", "High", "Medium", "Low", "Informational")
    }
    report["findings"] = prioritize_findings(report["findings"])
    try:
        paths = write_reports(report, list(dict.fromkeys(args.format)), args.output_dir)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: report generation failed: {error}")
        return 2

    print(f"Scan status: {report['status']}; HTTP status: {report['http_status'] or 'unavailable'}")
    if report["findings"]:
        for finding in report["findings"]:
            print(f"[{finding['severity']}] {finding['title']} ({finding['id']})")
            print(f"  Remediation: {finding['remediation']}")
    else:
        print("No findings were reported.")
    for path in paths:
        print(f"Report saved: {path}")
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
