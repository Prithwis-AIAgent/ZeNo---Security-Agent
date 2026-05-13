# SecureAgent Security Audit Report — Template
# This file documents the expected report structure.
# The actual report is generated programmatically by agents/report_writer.py

# 🔐 SecureAgent Security Audit Report

**Target**: `{{ target }}`  
**Scan Date**: `{{ timestamp }}`  
**Files Scanned**: {{ scanned_files }}  
**Packages Audited**: {{ scanned_packages }}  

---

## Executive Summary

| Severity | Count |
|---|---|
| 🔴 Critical | {{ critical }} |
| 🟠 High | {{ high }} |
| 🟡 Medium | {{ medium }} |
| 🔵 Low | {{ low }} |
| **Total** | **{{ total }}** |

---

## 🔴 Critical

### Code Issues

#### {{ vuln_name }}

| Field | Value |
|---|---|
| **File** | `{{ file }}` |
| **Line** | {{ line }} |
| **Category** | {{ category }} |

**What it is**: {{ vuln_name }}

**Why it's dangerous**: {{ description }}

**How to fix it**: {{ fix }}

**Matched code**:
```
{{ matched_text }}
```

### Dependency CVEs

#### {{ package }} — `{{ cve_id }}`

| Field | Value |
|---|---|
| **Package** | `{{ package }}=={{ version }}` |
| **CVE** | `{{ cve_id }}` |
| **Severity** | {{ severity }} |

**Description**: {{ description }}

**How to fix it**: Upgrade `{{ package }}` to a patched version.

**References**: {{ references }}

---

## 🟠 High

<!-- Same structure as Critical -->

---

## 🟡 Medium

<!-- Same structure as Critical -->

---

## 🔵 Low

<!-- Same structure as Critical -->

---

> ⚠️ **Disclaimer**: SecureAgent is an automated tool and may produce false positives.
> All findings should be reviewed by a qualified security engineer before remediation.
> This tool is intended for auditing code you own or have explicit permission to test.
