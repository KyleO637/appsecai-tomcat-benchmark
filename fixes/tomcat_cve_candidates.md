# Apache Tomcat 11 — CVE Candidates for Benchmarking Pipeline

Sourced from: https://tomcat.apache.org/security-11.html  
Selection criteria: Low/Moderate severity, clean GitHub commit, variety in vulnerability class.

---

## CVE-2026-24880 — Request Smuggling

| Field | Value |
|---|---|
| **CVE ID** | CVE-2026-24880 |
| **Severity** | Low |
| **Vulnerability Class** | Request Smuggling |
| **Affected Component** | HTTP Connector (chunked transfer encoding parser) |
| **Affected Versions** | 11.0.0-M1 to 11.0.18 |
| **Fixed In** | 11.0.20 |
| **GitHub Commit(s)** | [`fde1a823`](https://github.com/apache/tomcat/commit/fde1a8235fb73125217bd41e162aa0a113f33552), [`2cb06c34`](https://github.com/apache/tomcat/commit/2cb06c34f661ca42f7570bbcc21e99806184bcc5) |

**Description:** Invalid chunk extensions in HTTP/1.1 chunked requests were not rejected, allowing a crafted request to desynchronize the request pipeline and potentially smuggle a second request past an intermediary proxy.

**Why a good candidate:** Classic, well-understood HTTP parsing bug. The fix is isolated to the chunked-body parser, making before/after diffs clean and self-contained.

---

## CVE-2026-34483 — Information Disclosure (Log Injection)

| Field | Value |
|---|---|
| **CVE ID** | CVE-2026-34483 |
| **Severity** | Low |
| **Vulnerability Class** | Information Disclosure / Log Injection |
| **Affected Component** | `AccessLogValve` (JSON access log formatter) |
| **Affected Versions** | 11.0.0-M1 to 11.0.20 |
| **Fixed In** | 11.0.21 |
| **GitHub Commit** | [`f9ddc24f`](https://github.com/apache/tomcat/commit/f9ddc24fcfcdfaea4a6953198d8636aca3e957bc) |

**Description:** The JSON access log pattern did not fully escape all special characters in user-controlled request fields (e.g. User-Agent, URI). An attacker could inject crafted log entries, corrupt log structure, or leak adjacent log data when the logs are parsed downstream.

**Why a good candidate:** Single-commit fix, tightly scoped to one class. Good example of an output-encoding class of bug — contrasts well with the parsing bug above.

---

## CVE-2023-41080 — Open Redirect

| Field | Value |
|---|---|
| **CVE ID** | CVE-2023-41080 |
| **Severity** | Moderate |
| **Vulnerability Class** | Open Redirect |
| **Affected Component** | `FormAuthenticator` (FORM-based authentication redirect handling) |
| **Affected Versions** | 11.0.0-M1 to 11.0.0-M10 |
| **Fixed In** | 11.0.0-M11 |
| **GitHub Commit** | [`e3703c9a`](https://github.com/apache/tomcat/commit/e3703c9abb8fe0d5602f6ba8a8f11d4b6940815a) |

**Description:** The `j_security_check` redirect target was not validated against the server's own origin. A crafted login URL could redirect an authenticated user to an arbitrary external domain, enabling phishing attacks.

**Why a good candidate:** Moderate severity with a small, readable diff. Open redirect is a distinct vulnerability class (CWE-601) that rounds out the set alongside smuggling and log injection.

---

## Summary

| CVE | Severity | Class | Component | Primary Commit |
|---|---|---|---|---|
| CVE-2026-24880 | Low | Request Smuggling | HTTP Connector | `fde1a823` |
| CVE-2026-34483 | Low | Information Disclosure / Log Injection | AccessLogValve | `f9ddc24f` |
| CVE-2023-41080 | Moderate | Open Redirect | FormAuthenticator | `e3703c9a` |
