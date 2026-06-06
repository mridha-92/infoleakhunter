#!/usr/bin/env python3
"""
InfoLeakHunter - Automated Information Disclosure Vulnerability Scanner

Usage:
    python infoleakhunter.py -u https://target.com
    python infoleakhunter.py -l urls.txt
    python infoleakhunter.py -u https://target.com --json report.json --html report.html
    python infoleakhunter.py -l urls.txt --threads 500

For authorized security testing only.
"""

import sys
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

from infoleakhunter.cli import main

if __name__ == "__main__":
    main()
