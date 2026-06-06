# InfoLeakHunter Scan Report

**Generated:** 2026-06-06 12:00:00 UTC
**Tool:** InfoLeakHunter v1.0.0

## Executive Summary

- **Total URLs Scanned:** 1/1
- **Failed URLs:** 0
- **Total Findings:** 3
- **Scan Duration:** 12.5s

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Informational | 0 |

## Detailed Findings

---

### 1. 🔴 AWS Access Key ID discovered

| Field | Value |
|-------|-------|
| **Target** | `https://example.com` |
| **Module** | secrets |
| **Severity** | **Critical** |
| **Confidence** | Certain |
| **CWE** | CWE-798 |
| **OWASP** | OWASP:API8 |
| **URL** | `https://example.com/js/app.bundle.js` |
| **CVSS** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C` |
| **Description** | AWS Access Key ID discovered in JavaScript |
| **Recommendation** | Immediately revoke and rotate exposed credentials. Use a vault solution. |

---

### 2. 🟠 Sensitive file exposed: .env

| Field | Value |
|-------|-------|
| **Target** | `https://example.com` |
| **Module** | sensitive_file |
| **Severity** | **High** |
| **Confidence** | Certain |
| **CWE** | CWE-530 |
| **OWASP** | OWASP:API8 |
| **URL** | `https://example.com/.env` |
| **Recommendation** | Remove sensitive files from the web root. Store configuration and credentials outside the document root. |

---

### 3. 🟡 Information disclosure via Server header

| Field | Value |
|-------|-------|
| **Target** | `https://example.com` |
| **Module** | http_header |
| **Severity** | **Medium** |
| **Confidence** | Certain |
| **CWE** | CWE-200 |
| **OWASP** | OWASP:API4 |
| **URL** | `https://example.com/` |
| **Recommendation** | Configure the web server to suppress verbose headers. |

---
