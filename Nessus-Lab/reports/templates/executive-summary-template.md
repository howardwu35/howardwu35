# Vulnerability Assessment: Executive Summary

| | |
|---|---|
| **System / Scope** | Lab network 192.168.56.0/24 (2 hosts) |
| **Assessment period** | YYYY-MM-DD to YYYY-MM-DD |
| **Prepared by** | Howard Wu |
| **Tool / Feed** | Tenable Nessus Essentials vX.Y, plugin set YYYYMMDDHHMM |
| **Scan types** | Uncredentialed + credentialed Basic Network Scan |

## Bottom Line Up Front
<!-- 2–3 sentences, no jargon. What is the risk, and what decision/action is needed? -->
_Example structure: "The assessment found N critical weaknesses that would allow a remote attacker to take full control of X of Y systems without credentials. N of these are actively exploited in the wild (CISA KEV). Remediating the top 5 items eliminates ~Z% of the measured risk and requires an estimated N hours of administrator effort."_

## Risk Overview
| Contextual risk | Count | SLA | Due by |
|---|---:|---|---|
| Critical | | 15 days | |
| High | | 30 days | |
| Medium | | 90 days | |
| Low | | 180 days | |

## Top Risks
| # | Risk (plain language) | Affected | Business impact | Recommended action | Owner |
|---:|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

## Systemic Issues (root causes)
<!-- Patterns, not individual findings. e.g. "No patch management process for legacy Linux", "Default credentials not changed at deployment", "Unneeded legacy services enabled by default" -->
1.
2.

## Recommendations
1. **Immediate (≤15 days):**
2. **Short term (≤30 days):**
3. **Program-level:** e.g. implement monthly credentialed scanning (RA-5), formal patch SLAs (SI-2), hardening baselines (CM-6)

## Remediation Status (after validation rescan)
| | Baseline | Rescan | Change |
|---|---:|---:|---:|
| Critical + High | | | |
| Aggregate risk score | | | |
