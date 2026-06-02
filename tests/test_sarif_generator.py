import json
from pathlib import Path
import pytest
from sarif_generator import parse_markdown, find_declaration_line, build_sarif, main

# All tests must run from workspace root: /Users/shivani/appsecai-internship/
# Run with: pytest tests/ -v


def test_parse_markdown_table_fields():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["cve_id"] == "CVE-2023-41080"
    assert data["cwe_id"] == "CWE-601"
    assert data["cwe_description"] == "URL Redirection to Untrusted Site — Open Redirect"
    assert data["severity"] == "Moderate"
    assert data["d1_score"] == 1


def test_parse_markdown_before_block():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["before_file_path"] == "java/org/apache/catalina/authenticator/FormAuthenticator.java"
    assert data["files_touched"] == 1
    assert len(data["before_lines"]) > 0
    joined = "\n".join(data["before_lines"])
    assert "protected String savedRequestURL(Session session)" in joined


def test_parse_markdown_affected_component_simple():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["grep_term"] == "savedRequestURL"
    assert data["is_class"] is False
    assert data["all_methods"] == ["savedRequestURL()"]


def test_parse_markdown_affected_component_dotted():
    data = parse_markdown(Path("fixes/CVE-2026-34483_before_after.md"))
    assert data["grep_term"] == "RequestElement"
    assert data["is_class"] is True
    assert data["all_methods"] == ["RequestElement.addElement()", "RequestURIElement.addElement()"]


def test_parse_markdown_low_severity():
    data = parse_markdown(Path("fixes/CVE-2026-24880_before_after.md"))
    assert data["severity"] == "Low"
    assert data["d1_score"] == 3
    assert data["grep_term"] == "parseChunkHeader"
    assert data["is_class"] is False
