import re
import json
import argparse
from pathlib import Path


LEVEL_MAP = {"Low": "note", "Moderate": "warning", "High": "error"}


def _parse_affected_component(raw: str) -> dict:
    raw = re.sub(r'`', '', raw)
    parts = re.split(r'\s*→\s*', raw, maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Affected Component has no → separator: {raw!r}")

    rhs = parts[1].strip()
    all_methods = [t.strip() for t in rhs.split(',')]

    first = all_methods[0].rstrip('()')
    if '.' in first:
        class_name = first.split('.')[0]
        return {"grep_term": class_name, "is_class": True, "all_methods": all_methods}
    else:
        return {"grep_term": first, "is_class": False, "all_methods": all_methods}


def parse_markdown(path: Path) -> dict:
    data = {}
    state = "SCANNING_TABLE"
    before_lines = []
    before_file_path = None
    after_file_path = None
    done = False

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if state == "SCANNING_TABLE":
                m = re.match(r'\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|', line)
                if m:
                    field, value = m.group(1), m.group(2)
                    if field == "CVE ID":
                        data["cve_id"] = value
                    elif field == "CWE":
                        cwe_m = re.search(r'CWE-\d+', value)
                        desc_m = re.search(r'\((.+?)\)', value)
                        data["cwe_id"] = cwe_m.group(0) if cwe_m else value
                        data["cwe_description"] = desc_m.group(1) if desc_m else ""
                    elif field == "Severity":
                        data["severity"] = value
                    elif field == "D1 Score":
                        d1_m = re.match(r'(\d+)', value)
                        data["d1_score"] = int(d1_m.group(1)) if d1_m else 0
                    elif field == "Affected Component":
                        data.update(_parse_affected_component(value))
                elif line.startswith("## Before"):
                    state = "SCANNING_BEFORE"

            elif state == "SCANNING_BEFORE":
                m = re.match(r'`(java/.+?)`', line)
                if m:
                    before_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_BEFORE_CODE"

            elif state == "IN_BEFORE_CODE":
                if line.strip() == "```":
                    state = "SCANNING_AFTER"
                else:
                    before_lines.append(line)

            elif state == "SCANNING_AFTER":
                m = re.match(r'`(java/.+?)`', line)
                if m:
                    after_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_AFTER_CODE"

            elif state == "IN_AFTER_CODE":
                if line.strip() == "```":
                    done = True
                    break

    if not done:
        raise ValueError(f"{path.name}: did not reach end of After code block")

    data["before_lines"] = before_lines
    data["before_file_path"] = before_file_path
    paths = {p for p in [before_file_path, after_file_path] if p}
    data["files_touched"] = len(paths)

    for key in ["cve_id", "cwe_id", "severity", "d1_score"]:
        if key not in data:
            raise ValueError(f"{path.name}: missing field '{key}'")

    return data


def find_declaration_line(src_file: Path, grep_term: str, is_class: bool) -> int | None:
    raise NotImplementedError


def build_sarif(cve_data: dict, start_line: int, end_line: int) -> dict:
    raise NotImplementedError


def main(fixes_dir: Path, sarif_dir: Path, tomcat_dir: Path) -> None:
    raise NotImplementedError


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF 2.1.0 files from CVE markdown")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--sarif-dir", type=Path, default=Path("sarif"))
    parser.add_argument("--tomcat-dir", type=Path, default=Path("tomcat"))
    args = parser.parse_args()
    main(args.fixes_dir, args.sarif_dir, args.tomcat_dir)
