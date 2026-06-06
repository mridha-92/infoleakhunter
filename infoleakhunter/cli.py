from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any

from infoleakhunter import __version__


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def validate_file(path: str) -> bool:
    if not os.path.exists(path):
        print(f"Error: File not found: {path}")
        return False
    if not os.path.isfile(path):
        print(f"Error: Not a file: {path}")
        return False
    return True


def read_urls_from_file(path: str) -> list[str]:
    urls = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line.rstrip("/"))
    return urls


def validate_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="infoleakhunter",
        description="InfoLeakHunter - Automated Information Disclosure Vulnerability Scanner",
        epilog="Example: python infoleakhunter.py -u https://target.com --json report.json --html report.html",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-u", "--url",
        help="Single target URL to scan",
    )
    target_group.add_argument(
        "-l", "--list",
        help="File containing list of URLs to scan (one per line)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads/connections (default: 100)",
    )
    parser.add_argument(
        "--config",
        help="Path to custom configuration file",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=True,
        help="Verify SSL certificates (default: True)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        dest="verify_ssl",
        action="store_false",
        help="Skip SSL certificate verification",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress console output",
    )

    report_group = parser.add_argument_group("Report Output")
    report_group.add_argument(
        "--json",
        metavar="FILE",
        help="Output results in JSON format to specified file",
    )
    report_group.add_argument(
        "--csv",
        metavar="FILE",
        help="Output results in CSV format to specified file",
    )
    report_group.add_argument(
        "--html",
        metavar="FILE",
        help="Generate HTML report to specified file",
    )
    report_group.add_argument(
        "--md",
        metavar="FILE",
        help="Generate Markdown report to specified file",
    )

    scan_group = parser.add_argument_group("Scan Controls")
    scan_group.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS information leakage checks",
    )
    scan_group.add_argument(
        "--no-js",
        action="store_true",
        help="Skip JavaScript analysis",
    )
    scan_group.add_argument(
        "--no-metadata",
        action="store_true",
        help="Skip metadata extraction",
    )
    scan_group.add_argument(
        "--no-secrets",
        action="store_true",
        help="Skip secret detection",
    )

    version_group = parser.add_argument_group("Version")
    version_group.add_argument(
        "--version",
        action="version",
        version=f"InfoLeakHunter v{__version__}",
    )

    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.quiet:
        console_output = False
    else:
        console_output = not args.quiet

    targets: list[str] = []
    if args.url:
        try:
            url = validate_url(args.url)
            targets.append(url)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.list:
        if not validate_file(args.list):
            sys.exit(1)
        try:
            targets = read_urls_from_file(args.list)
            if not targets:
                print("Error: No valid URLs found in file")
                sys.exit(1)
            targets = [validate_url(u) for u in targets]
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    options: dict[str, Any] = {
        "threads": args.threads,
        "timeout": args.timeout,
        "verify_ssl": args.verify_ssl,
        "console": console_output,
        "config": args.config,
        "no_dns": args.no_dns,
        "no_js": args.no_js,
        "no_metadata": args.no_metadata,
        "no_secrets": args.no_secrets,
    }

    if args.json:
        options["json"] = True
        options["json_file"] = args.json
    if args.csv:
        options["csv"] = True
        options["csv_file"] = args.csv
    if args.html:
        options["html"] = True
        options["html_file"] = args.html
    if args.md:
        options["markdown"] = True
        options["markdown_file"] = args.md

    from infoleakhunter.engine import run_scan
    findings = run_scan(targets, options)

    exit_code = 0
    sev_counts = findings.severity_counts()
    if sev_counts.get("Critical", 0) > 0 or sev_counts.get("High", 0) > 0:
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
