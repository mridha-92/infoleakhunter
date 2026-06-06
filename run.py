#!/usr/bin/env python3
"""
InfoLeakHunter - Automated Information Disclosure Vulnerability Scanner

Usage:
    python run.py -u https://target.com
    python run.py -l urls.txt
    python -m infoleakhunter -u https://target.com
    python run.py -u https://target.com --json report.json --html report.html
    python run.py -l urls.txt --threads 500

For authorized security testing only.
"""

import sys
import os
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from infoleakhunter.cli import main

if __name__ == "__main__":
    main()
