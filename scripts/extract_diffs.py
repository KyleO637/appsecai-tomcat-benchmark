"""
For each candidate in cve_candidates.json, run git show in the local
tomcat/ clone and extract diff metadata. Outputs cve_diffs.json and
prints a review table for the pause checkpoint.

Clean = <= 2 Java files changed AND <= 200 Java lines changed.
Complex CVEs are included as scaffold-only entries.

Usage:
    python scripts/extract_diffs.py [--candidates cve_candidates.json]
                                     [--tomcat-dir tomcat]
                                     [--out cve_diffs.json]
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


D1_THRESHOLDS = [10, 50, 200, 500]  # lines → scores 1-5


def d1_score(lines_changed: int) -> int:
    for i, threshold in enumerate(D1_THRESHOLDS, start=1):
        if lines_changed <= threshold:
            return i
    return 5


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=30
    )
    return result.returncode, result.stdout


def commit_in_repo(sha: str, tomcat_dir: Path) -> bool:
    rc, _ = run(["git", "cat-file", "-t", sha], tomcat_dir)
    return rc == 0


def get_diff(sha: str, tomcat_dir: Path) -> str:
    _, out = run(["git", "show", "--diff-filter=M", sha], tomcat_dir)
    return out


def parse_diff(diff_text: str) -> dict:
    """
    Returns:
        java_files: list of changed .java file paths (repo-relative)
        lines_added: int
        lines_removed: int
        has_new_files: bool  (diff --git a/... b/... with 'new file mode')
        is_merge_commit: bool
    """
    java_files = []
    lines_added = 0
    lines_removed = 0
    has_new_files = False
    is_merge_commit = False

    in_java_file = False

    for line in diff_text.splitlines():
        if line.startswith("Merge:"):
            is_merge_commit = True
        elif line.startswith("diff --git"):
            m = re.search(r'b/(.+\.java)$', line)
            in_java_file = bool(m)
            if m:
                path = m.group(1)
                if path not in java_files:
                    java_files.append(path)
        elif line.startswith("new file mode"):
            has_new_files = True
        elif in_java_file:
            if line.startswith("+") and not line.startswith("+++"):
                lines_added += 1
            elif line.startswith("-") and not line.startswith("---"):
                lines_removed += 1

    return {
        "java_files": java_files,
        "lines_added": lines_added,
        "lines_removed": lines_removed,
        "has_new_files": has_new_files,
        "is_merge_commit": is_merge_commit,
    }


def get_file_at_commit(sha: str, file_path: str, tomcat_dir: Path) -> str | None:
    """Return file content at a given commit, or None on failure."""
    rc, out = run(["git", "show", f"{sha}:{file_path}"], tomcat_dir)
    return out if rc == 0 else None


def get_file_before_commit(sha: str, file_path: str, tomcat_dir: Path) -> str | None:
    """Return file content at the parent commit (before the fix)."""
    # Try first parent
    rc, out = run(["git", "show", f"{sha}^:{file_path}"], tomcat_dir)
    return out if rc == 0 else None


def process_candidate(entry: dict, tomcat_dir: Path) -> dict:
    cve_id = entry["cve_id"]
    commits = entry["fix_commits"]
    primary_sha = commits[0]

    result = {
        "cve_id": cve_id,
        "severity": entry["severity"],
        "short_description": entry["short_description"],
        "fix_year": entry["fix_year"],
        "tomcat_version": entry["tomcat_version"],
        "primary_commit": primary_sha,
        "all_commits": commits,
        "commit_in_repo": False,
        "java_files_changed": [],
        "lines_added": 0,
        "lines_removed": 0,
        "total_java_lines_changed": 0,
        "d1_score": 0,
        "has_new_files": False,
        "is_merge_commit": False,
        "is_clean": False,
        "scaffold_only": False,
        "scaffold_reason": "",
        "diff_text": "",
    }

    if not commit_in_repo(primary_sha, tomcat_dir):
        result["scaffold_only"] = True
        result["scaffold_reason"] = "commit not in local repo"
        return result

    result["commit_in_repo"] = True
    diff = get_diff(primary_sha, tomcat_dir)
    result["diff_text"] = diff

    parsed = parse_diff(diff)
    result.update({
        "java_files_changed": parsed["java_files"],
        "lines_added": parsed["lines_added"],
        "lines_removed": parsed["lines_removed"],
        "has_new_files": parsed["has_new_files"],
        "is_merge_commit": parsed["is_merge_commit"],
        "total_java_lines_changed": parsed["lines_added"] + parsed["lines_removed"],
    })
    result["d1_score"] = d1_score(result["total_java_lines_changed"])

    # Determine scaffold_only reasons
    reasons = []
    if parsed["is_merge_commit"]:
        reasons.append("merge commit")
    if parsed["has_new_files"]:
        reasons.append("adds new files")
    if not parsed["java_files"]:
        reasons.append("no Java files changed")

    if reasons:
        result["scaffold_only"] = True
        result["scaffold_reason"] = ", ".join(reasons)
    else:
        java_count = len(parsed["java_files"])
        java_lines = result["total_java_lines_changed"]
        result["is_clean"] = java_count <= 2 and java_lines <= 200
        if not result["is_clean"]:
            result["scaffold_only"] = True
            result["scaffold_reason"] = f"{java_count} Java files, {java_lines} lines changed"

    return result


def print_review_table(results: list[dict]) -> None:
    clean = [r for r in results if r["is_clean"]]
    scaffold = [r for r in results if r["scaffold_only"]]
    missing = [r for r in results if not r["commit_in_repo"]]

    print(f"\n{'='*90}")
    print(f"  CANDIDATE REVIEW — {len(results)} CVEs total  |  "
          f"{len(clean)} clean  |  {len(scaffold)} scaffold  |  {len(missing)} commit missing")
    print(f"{'='*90}")

    header = f"{'CVE ID':<18} {'Sev':<10} {'D1':<4} {'Files':<6} {'Lines':<7} {'Status':<12} Note"
    print(header)
    print("-" * 90)

    for r in sorted(results, key=lambda x: x["cve_id"]):
        status = "CLEAN" if r["is_clean"] else ("SCAFFOLD" if r["scaffold_only"] else "?")
        note = r["scaffold_reason"] if r["scaffold_only"] else ", ".join(r["java_files_changed"][:1])
        if r["java_files_changed"]:
            note = Path(r["java_files_changed"][0]).name
            if r["scaffold_reason"]:
                note += f" ({r['scaffold_reason']})"
        elif r["scaffold_reason"]:
            note = r["scaffold_reason"]
        d1 = str(r["d1_score"]) if r["d1_score"] else "-"
        files = str(len(r["java_files_changed"])) if r["java_files_changed"] else "-"
        lines = str(r["total_java_lines_changed"]) if r["total_java_lines_changed"] else "-"
        print(f"{r['cve_id']:<18} {r['severity']:<10} {d1:<4} {files:<6} {lines:<7} {status:<12} {note}")

    print(f"{'='*90}")
    print(f"\nReview complete. Run the Claude batch pass when ready:")
    print(f"  python scripts/generate_markdown.py  (or ask Claude to process cve_diffs.json)")


def main(candidates_path: Path, tomcat_dir: Path, out_path: Path) -> None:
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    print(f"Processing {len(candidates)} candidates from {candidates_path} ...")

    results = []
    for entry in candidates:
        cve_id = entry["cve_id"]
        sys.stdout.write(f"  {cve_id} ... ")
        sys.stdout.flush()
        result = process_candidate(entry, tomcat_dir)
        status = "clean" if result["is_clean"] else ("scaffold" if result["scaffold_only"] else "ok")
        print(status)
        results.append(result)

    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote {out_path}")

    print_review_table(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, default=Path("cve_candidates.json"))
    parser.add_argument("--tomcat-dir", type=Path, default=Path("tomcat"))
    parser.add_argument("--out", type=Path, default=Path("cve_diffs.json"))
    args = parser.parse_args()
    main(args.candidates, args.tomcat_dir, args.out)
