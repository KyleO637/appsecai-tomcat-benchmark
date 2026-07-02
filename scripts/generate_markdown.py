"""
Generate a CVE fix markdown by calling the Claude API with the raw git diff.

Usage:
    python scripts/generate_markdown.py --cve-id CVE-XXXX-XXXXX \
        [--candidates pipeline_data/cve_candidates.json] \
        [--fixes-dir fixes] \
        [--tomcat-repo https://github.com/apache/tomcat.git]
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import anthropic


D1_THRESHOLDS = [10, 50, 200, 500]


def d1_score(lines_changed: int) -> int:
    for i, threshold in enumerate(D1_THRESHOLDS, start=1):
        if lines_changed <= threshold:
            return i
    return 5


def fetch_diff(sha: str, tomcat_repo: str) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir) / "tomcat"
        tmp.mkdir()
        subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
        subprocess.run(
            ["git", "remote", "add", "origin", tomcat_repo],
            cwd=tmp, check=True, capture_output=True,
        )
        result = subprocess.run(
            ["git", "fetch", "--depth=2", "origin", sha],
            cwd=tmp, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git fetch failed for {sha}:\n{result.stderr}")

        result = subprocess.run(
            ["git", "show", "--diff-filter=M", sha],
            cwd=tmp, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git show failed for {sha}:\n{result.stderr}")
        return result.stdout


def count_java_lines(diff_text: str) -> int:
    in_java = False
    added = removed = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            in_java = bool(re.search(r'b/.+\.java$', line))
        elif in_java:
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
    return added + removed


PROMPT_TEMPLATE = """\
You are a security engineer writing a CVE fix documentation file for a benchmark.

## CVE Metadata
- CVE ID: {cve_id}
- Severity: {severity}
- Description: {short_description}
- Fix commit: {fix_commit}
- D1 Score: {d1_score} ({lines_changed} Java lines changed)

## Raw Git Diff
```diff
{diff_text}
```

## Task
Write a `fixes/{cve_id}_before_after.md` file that documents this vulnerability and its fix.
The file MUST follow this EXACT structure (sarif_generator.py parses it):

```
# {cve_id} — Before/After Fix

| Field | Value |
|---|---|
| **CVE ID** | {cve_id} |
| **CWE** | CWE-NNN (Short CWE name) |
| **Severity** | {severity} |
| **Affected Component** | `FileName.java` → `methodName()` |
| **Fix Commit** | `{fix_commit}` |
| **D1 Score** | {d1_score} ({lines_changed} Java lines changed) |
| **Fix Complexity Notes** | One or two sentences about what makes this fix tricky for an AI. |

---

## Before (Vulnerable)

`java/path/to/FileName.java`

```java
    // The vulnerable method or block, as it appeared before the fix.
    // Include enough context (full method body) to be self-contained.
```

---

## After (Patched)

`java/path/to/FileName.java`

```java
    // The fixed method or block.
```

---

## Explanation

Two or three paragraphs explaining: what the vulnerability was, how it could be exploited,
and exactly what the fix does and why it works.
```

## Rules
- Identify the CWE from the nature of the vulnerability (e.g. CWE-193 for off-by-one, CWE-79 for XSS, CWE-400 for resource exhaustion).
- **Affected Component** must be: `` `FileName.java` → `methodName()` `` (method-level) or `` `FileName.java` → `ClassName.method()` `` (if the method is on an inner/named class).
- The file path in `## Before` and `## After` must start with `java/` (matching the repo's java/ directory).
- The Before block must show the vulnerable code exactly as it was (from `-` lines in the diff, with context).
- The After block must show the fixed code (from `+` lines, with context).
- Do not include diff markers (`+`, `-`) in the code blocks — show clean Java.
- Output ONLY the markdown file content, nothing else. No preamble, no explanation outside the markdown.
"""


def call_claude(prompt: str) -> str:
    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def main(
    cve_id: str,
    candidates_path: Path,
    fixes_dir: Path,
    tomcat_repo: str,
) -> None:
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    entry = next((c for c in candidates if c["cve_id"] == cve_id), None)
    if entry is None:
        print(f"ERROR: {cve_id} not found in {candidates_path}", file=sys.stderr)
        sys.exit(1)

    sha = entry["fix_commits"][0]
    print(f"Fetching diff for {cve_id} @ {sha[:8]} ...")
    diff_text = fetch_diff(sha, tomcat_repo)

    lines_changed = count_java_lines(diff_text)
    score = d1_score(lines_changed)
    print(f"  {lines_changed} Java lines changed, D1={score}")

    prompt = PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        severity=entry["severity"],
        short_description=entry["short_description"],
        fix_commit=sha[:8],
        d1_score=score,
        lines_changed=lines_changed,
        diff_text=diff_text[:12000],  # cap at ~12k chars to stay within context
    )

    print("Calling Claude API ...")
    markdown = call_claude(prompt)

    fixes_dir.mkdir(parents=True, exist_ok=True)
    out_path = fixes_dir / f"{cve_id}_before_after.md"
    out_path.write_text(markdown, encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--candidates", type=Path, default=Path("pipeline_data/cve_candidates.json"))
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--tomcat-repo", default="https://github.com/apache/tomcat.git")
    args = parser.parse_args()
    main(args.cve_id, args.candidates, args.fixes_dir, args.tomcat_repo)
