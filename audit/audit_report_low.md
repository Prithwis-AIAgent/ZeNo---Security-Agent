# ð SecureAgent Security Audit Report

**Target**: `https://github.com/Prithwis-AIAgent/AI-Agents-for-Medical-Diagnostics`  
**Scan Date**: 2026-05-13 07:20 UTC  
**Files Scanned**: 3  
**Packages Audited**: 1  

---

## Executive Summary

| Severity | Count |
|---|---|
| ð´ Critical | 2 |
| ð  High | 0 |
| ð¡ Medium | 0 |
| ðµ Low | 60 |
| **Total** | **62** |

---

## ð´ Critical

### Code Issues (2)

#### Hardcoded API Key / Token

| Field | Value |
|---|---|
| **File** | `Main.py` |
| **Line** | 10 |
| **Category** | secrets |

**What it is**: Hardcoded API Key / Token  

**Why it's dangerous**: Hardcoded credentials in source code can be extracted by anyone with repository access and exploited to impersonate the service or owner.  

**How to fix it**: Move secrets to environment variables and use a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).  

**Matched code**:
```
load_dotenv(dotenv_path='apikey.env')
```

#### Hardcoded API Key / Token

| Field | Value |
|---|---|
| **File** | `apikey.env` |
| **Line** | 1 |
| **Category** | secrets |

**What it is**: Hardcoded API Key / Token  

**Why it's dangerous**: Hardcoded credentials in source code can be extracted by anyone with repository access and exploited to impersonate the service or owner.  

**How to fix it**: Move secrets to environment variables and use a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).  

**Matched code**:
```
OPENAI_API_KEY=""
```

## ðµ Low

### Dependency CVEs (60)

#### langchain â `GHSA-2qmj-7962-cjq8`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-2qmj-7962-cjq8` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-3hjh-jh2h-vrg6`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-3hjh-jh2h-vrg6` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-45pg-36p6-83v9`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-45pg-36p6-83v9` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-57fc-8q82-gfp3`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-57fc-8q82-gfp3` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-655w-fm8m-m478`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-655w-fm8m-m478` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-6643-h7h5-x9wh`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-6643-h7h5-x9wh` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-6h8p-4hx9-w66c`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-6h8p-4hx9-w66c` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-7gfq-f96f-g85j`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-7gfq-f96f-g85j` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-7q94-qpjr-xpgm`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-7q94-qpjr-xpgm` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-8h5w-f6q9-wg35`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-8h5w-f6q9-wg35` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-92j5-3459-qgp4`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-92j5-3459-qgp4` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-f73w-4m7g-ch9x`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-f73w-4m7g-ch9x` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-fj32-q626-pjjc`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-fj32-q626-pjjc` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-fprp-p869-w6q2`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-fprp-p869-w6q2` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-gwqq-6vq7-5j86`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-gwqq-6vq7-5j86` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-h59x-p739-982c`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-h59x-p739-982c` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-h9j7-5xvc-qhg5`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-h9j7-5xvc-qhg5` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-prgp-w7vf-ch62`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-prgp-w7vf-ch62` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-rgp8-pm28-3759`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-rgp8-pm28-3759` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `GHSA-x32c-59v5-h7fg`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `GHSA-x32c-59v5-h7fg` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-109`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-109` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-110`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-110` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-138`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-138` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-145`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-145` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-146`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-146` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-147`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-147` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-151`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-151` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-162`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-162` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-18`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-18` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-205`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-205` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-91`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-91` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-92`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-92` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2023-98`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2023-98` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2024-115`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2024-115` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2024-118`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2024-118` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain â `PYSEC-2024-43`

| Field | Value |
|---|---|
| **Package** | `langchain==` |
| **CVE** | `PYSEC-2024-43` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-3hjh-jh2h-vrg6`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-3hjh-jh2h-vrg6` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-45pg-36p6-83v9`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-45pg-36p6-83v9` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-f2jm-rw3h-6phg`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-f2jm-rw3h-6phg` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-h5gc-rm8j-5gpr`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-h5gc-rm8j-5gpr` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-pc6w-59fv-rh23`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-pc6w-59fv-rh23` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `GHSA-q25c-c977-4cmh`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `GHSA-q25c-c977-4cmh` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `PYSEC-2024-115`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `PYSEC-2024-115` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-community â `PYSEC-2025-70`

| Field | Value |
|---|---|
| **Package** | `langchain-community==` |
| **CVE** | `PYSEC-2025-70` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-community` to a patched version.  

**References**: None  

#### langchain-openai â `GHSA-r7w7-9xr2-qq2r`

| Field | Value |
|---|---|
| **Package** | `langchain-openai==` |
| **CVE** | `GHSA-r7w7-9xr2-qq2r` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-openai` to a patched version.  

**References**: None  

#### langchain-experimental â `GHSA-cgcg-p68q-3w7v`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `GHSA-cgcg-p68q-3w7v` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `GHSA-gjjr-63x4-v8cq`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `GHSA-gjjr-63x4-v8cq` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `GHSA-p2qj-r53j-h3xj`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `GHSA-p2qj-r53j-h3xj` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `GHSA-v8vj-cv27-hjv8`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `GHSA-v8vj-cv27-hjv8` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `GHSA-wmvm-9vqv-5qpp`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `GHSA-wmvm-9vqv-5qpp` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `PYSEC-2023-194`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `PYSEC-2023-194` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `PYSEC-2024-53`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `PYSEC-2024-53` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### langchain-experimental â `PYSEC-2024-62`

| Field | Value |
|---|---|
| **Package** | `langchain-experimental==` |
| **CVE** | `PYSEC-2024-62` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `langchain-experimental` to a patched version.  

**References**: None  

#### python-dotenv â `GHSA-mf9w-mj56-hr94`

| Field | Value |
|---|---|
| **Package** | `python-dotenv==` |
| **CVE** | `GHSA-mf9w-mj56-hr94` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `python-dotenv` to a patched version.  

**References**: None  

#### reportlab â `GHSA-9q9m-c65c-37pq`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `GHSA-9q9m-c65c-37pq` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

#### reportlab â `GHSA-mpvw-25mg-59vx`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `GHSA-mpvw-25mg-59vx` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

#### reportlab â `GHSA-pj98-2xf6-cff5`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `GHSA-pj98-2xf6-cff5` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

#### reportlab â `GHSA-qpg2-vx7j-3869`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `GHSA-qpg2-vx7j-3869` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

#### reportlab â `PYSEC-2019-117`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `PYSEC-2019-117` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

#### reportlab â `PYSEC-2021-146`

| Field | Value |
|---|---|
| **Package** | `reportlab==` |
| **CVE** | `PYSEC-2021-146` |
| **Severity** | UNKNOWN |

**Description**: No description available.  

**How to fix it**: Upgrade `reportlab` to a patched version.  

**References**: None  

---

> â ï¸ **Disclaimer**: SecureAgent is an automated tool and may produce false positives. All findings should be reviewed by a qualified security engineer before remediation. This tool is intended for auditing code you own or have explicit permission to test.

