#!/usr/bin/env python3
"""Sales behavior discovery program - main entry"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from detector import Detector
from browser import fetch_page
from reporter import Reporter


def main():
    parser = argparse.ArgumentParser(
        description="Sales Behavior Detection - Identify fraudulent financial sales content impersonating institutions"
    )
    parser.add_argument("url", help="Target webpage URL")
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=30000,
        help="Page load timeout in milliseconds, default 30000"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Configuration directory path"
    )

    args = parser.parse_args()

    url = args.url.strip()

    print(f"Fetching page: {url}")
    print(f"Waiting for render complete...")

    try:
        text = fetch_page(url, timeout=args.timeout)
        print(f"Page fetch successful, got {len(text)} characters")
    except Exception as e:
        print(f"Page fetch failed: {e}")
        sys.exit(1)

    detector = Detector(config_dir=args.config)
    result = detector.detect(url, text)

    report = Reporter.generate(result)
    print("\n" + report)


if __name__ == "__main__":
    main()