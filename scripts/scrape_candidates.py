"""
Scrape Tomcat security pages and output cve_candidates.json.

Fetches security-10.html and security-11.html, extracts CVEs from 2023
onwards, deduplicates by CVE ID, and skips any CVE that already has a
fixes/ markdown file.

Usage:
    python scripts/scrape_candidates.py [--fixes-dir fixes] [--out cve_candidates.json]
"""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

PAGES = [
    ("https://tomcat.apache.org/security-11.html", "11"),
    ("https://tomcat.apache.org/security-10.html", "10"),
]
CUTOFF_YEAR = 2023
SEVERITY_MAP = {"Important": "High"}  # Apache uses Important; we use High


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; appsecai-scraper/1.0)"})
    return urlopen(req, timeout=20).read().decode("utf-8")


def parse_page(html: str, tomcat_version: str) -> list[dict]:
    """Extract CVE entries from a single security page."""
    cves = []

    # Split into release sections. Both pages use <h3> for release dates.
    # security-11: <h3>2026-05-05 Fixed in ...</h3>
    # security-10: <h3>...<span ...>2026-03-23</span> Fixed in ...</h3>
    sections = re.split(r'<h3[^>]*>', html)

    for section in sections[1:]:  # first chunk is pre-header nav
        # Extract year from section — look for a 4-digit year >= 2000
        year_m = re.search(r'\b(20\d{2})\b', section)
        if not year_m:
            continue
        year = int(year_m.group(1))
        if year < CUTOFF_YEAR:
            continue

        # Find all <p> blocks in this section
        for p_m in re.finditer(r'<p>(.*?)</p>', section, re.DOTALL):
            p_html = p_m.group(1)

            # CVE header paragraph: <strong>Severity: Description</strong> ... CVE-XXXX-XXXXX
            strong_m = re.search(
                r'<strong>(Low|Moderate|Important|Critical):\s*(.*?)</strong>',
                p_html, re.DOTALL
            )
            cve_m = re.search(r'\b(CVE-\d{4}-\d+)\b', p_html)

            if not strong_m or not cve_m:
                continue

            severity_raw = strong_m.group(1)
            description = re.sub(r'<[^>]+>', '', strong_m.group(2))
            description = re.sub(r'\s+', ' ', description).strip()
            cve_id = cve_m.group(1)
            severity = SEVERITY_MAP.get(severity_raw, severity_raw)

            # Scan forward from this <p> to the next CVE <strong> or </h3>
            # to scope commit link extraction.
            pos_after_p = p_m.end()
            next_cve = re.search(r'<strong>(?:Low|Moderate|Important|Critical):', section[pos_after_p:])
            window_end = pos_after_p + (next_cve.start() if next_cve else 3000)
            window = section[pos_after_p:window_end]

            # Extract full commit SHAs from GitHub links
            commit_shas = re.findall(
                r'https://github\.com/apache/tomcat/commit/([0-9a-f]{40})',
                window
            )

            cves.append({
                "cve_id": cve_id,
                "severity": severity,
                "short_description": description,
                "fix_commits": commit_shas,
                "fix_year": year,
                "tomcat_version": tomcat_version,
            })

    return cves


def main(fixes_dir: Path, out_path: Path) -> None:
    existing = {p.stem.split("_")[0] for p in fixes_dir.glob("CVE-*_before_after.md")}
    print(f"Existing CVEs (will skip): {sorted(existing)}")

    all_cves: dict[str, dict] = {}  # keyed by CVE ID for dedup

    for url, version in PAGES:
        print(f"Fetching {url} ...")
        html = fetch(url)
        found = parse_page(html, version)
        print(f"  Found {len(found)} CVEs on security-{version}.html (year >= {CUTOFF_YEAR})")

        for entry in found:
            cid = entry["cve_id"]
            if cid in all_cves:
                # Merge commit SHAs from both pages (backport commits differ)
                existing_commits = all_cves[cid]["fix_commits"]
                for sha in entry["fix_commits"]:
                    if sha not in existing_commits:
                        existing_commits.append(sha)
                # Keep a record that this CVE appears on both major versions
                all_cves[cid].setdefault("also_tomcat_version", []).append(version)
            else:
                all_cves[cid] = entry

    candidates = []
    skipped = []
    for cve_id, entry in sorted(all_cves.items()):
        if cve_id in existing:
            skipped.append(cve_id)
            continue
        if not entry["fix_commits"]:
            print(f"  WARN: {cve_id} has no commit links — skipping")
            continue
        candidates.append(entry)

    print(f"\nSkipped (already have fixes/): {skipped}")
    print(f"New candidates: {len(candidates)}")

    out_path.write_text(json.dumps(candidates, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--out", type=Path, default=Path("cve_candidates.json"))
    args = parser.parse_args()
    main(args.fixes_dir, args.out)
