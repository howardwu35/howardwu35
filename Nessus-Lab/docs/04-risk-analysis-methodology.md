# 04 · Risk Analysis & Prioritization Methodology

A scanner reports **severity**. An analyst determines **risk**. This document explains how scan output becomes a prioritized, defensible remediation plan.

## Step 1: Validate Findings
Before anything is reported, each Critical/High finding is triaged:

| Check | How |
|---|---|
| Is it real? | Read plugin output/evidence. Confirm version banners, re-test manually where safe (`nmap -sV -p <port>`, `nc`, `smbclient`). |
| Is it in scope? | Asset is on the inventory and owned by the system being assessed |
| Duplicate? | Same root cause across many plugins (e.g. one missing cumulative update → 20 CVEs) is **one** remediation action |
| False positive? | Backported patches (common on RHEL/Debian) can make version-based checks fire falsely. Verify package version (`dpkg -l`, `rpm -q`) against the vendor advisory. |

Every false positive is documented with evidence (in POA&M terms: *False Positive* with justification). It is never just deleted.

## Step 2: Score Contextual Risk
**Risk = Likelihood × Impact** (NIST SP 800-30). Scanner severity approximates *technical* impact/likelihood but knows nothing about the business.

| Factor | Source | Effect |
|---|---|---|
| Technical score | **VPR** if present, else **CVSSv3**, else CVSSv2 | Base (0–10) |
| Asset criticality | Asset inventory / FIPS 199 categorization | High +1.0 · Medium 0 · Low −1.0 |
| Exploit availability | Nessus `exploit_available`, Metasploit module | +0.5 |
| Active exploitation | **CISA KEV** catalog | +1.5, and never rated below High |
| Guardrail | | Rating moves at most **one level** from Nessus severity |

### Why VPR over CVSS when available?
CVSS base scores are static and ~60% of CVEs score High/Critical, which doesn't help prioritization. Tenable's **VPR** factors in threat intelligence (exploit maturity, recent threat activity) and changes over time. Example from testing: a CVSS 9.8 backdoor with a lower VPR drops to High, while MS17-010 (CVSS 8.1, VPR 9.7, on KEV) rises to Critical. That reorders the remediation queue toward what attackers actually use.

### Why the guardrail?
Unbounded multipliers let a CVSS 6.5 self-signed certificate become "Critical" just because it sits on an important server. That inflates the Critical count and erodes trust in the report. Context should *adjust* a rating, not override the technical evidence.

## Step 3: Assign SLA & Owner
| Contextual rating | SLA | Basis |
|---|---|---|
| Critical | 15 days | CISA BOD 19-02 (critical, internet-facing) |
| High | 30 days | CISA BOD 19-02 (high) |
| Medium | 90 days | Common org policy |
| Low | 180 days | Common org policy |
| KEV-listed | Per KEV due date | CISA BOD 22-01 (federal agencies) |

Configurable: `--sla Critical=7,High=30,Medium=60,Low=120`.

DoD/DISA equivalent: **CAT I** (≈ Critical/High), **CAT II** (≈ Medium), **CAT III** (≈ Low), with timelines set by the authorizing official / command policy.

## Step 4: Choose a Risk Response
| Response | When | Record |
|---|---|---|
| **Remediate** | Patch/config fix available and feasible | POA&M → Closed after validation scan |
| **Mitigate** | Fix not yet possible; compensating control reduces risk (segmentation, disable service, WAF) | POA&M with compensating control described |
| **Accept** | Residual risk within tolerance; business need | Risk acceptance signed by AO/system owner, with expiry date |
| **Transfer** | Vendor/contract responsibility, insurance | Vendor dependency noted in POA&M |
| **False positive** | Evidence shows not vulnerable | Justification + evidence attached |

## Step 5: Map to Controls
Each POA&M item is tagged with NIST 800-53 controls (heuristic in `nessus_report.py`, analyst-reviewed):

| Finding type | Controls |
|---|---|
| Missing patch / vulnerable version | SI-2, RA-5 |
| Default / weak credentials | IA-5, AC-2 |
| Backdoor / bind shell | SI-3, SI-4, CM-7 |
| Weak TLS / SSL / certificates | SC-8, SC-13, SC-23 |
| Unnecessary services (rexec, telnet, NFS) | CM-7, CM-6 |
| Unsupported software | SA-22, SI-2 |

## My Prioritization Decisions
> Fill in after analyzing your own scan: list your top 5, and note at least one place where you **disagreed with Nessus severity** and why.

| Rank | Finding | Host | Nessus severity | My rating | Rationale |
|---:|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |
