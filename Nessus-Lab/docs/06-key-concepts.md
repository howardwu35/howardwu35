# 06 · Key Concepts (Study Notes)

## Where vulnerability scanning fits in the RMF (NIST SP 800-37 Rev. 2)
**Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor**

- **Assess:** scan results are evidence for control assessments (RA-5, SI-2, CM-6).
- **Authorize:** the Authorizing Official (AO) reviews the **SAR** (Security Assessment Report) and **POA&M** to decide on an **ATO**. Open High/Critical items directly affect that decision.
- **Monitor:** recurring scans feed **continuous monitoring** (CA-7, ConMon). Monthly scans + POA&M updates are typical (e.g. FedRAMP ConMon).

## Key controls (NIST SP 800-53 Rev. 5)
| Control | Name | Relevance |
|---|---|---|
| RA-3 | Risk Assessment | Context for prioritizing findings |
| RA-5 | Vulnerability Monitoring and Scanning | Scan frequency, coverage, credentialed scanning (RA-5(5) privileged access) |
| SI-2 | Flaw Remediation | Patch within defined timelines |
| CA-5 | Plan of Action and Milestones | Track weaknesses to closure |
| CA-7 | Continuous Monitoring | Ongoing scanning and reporting |
| CM-6 / CM-7 | Configuration Settings / Least Functionality | Hardening, disabling unneeded services |
| CM-8 | System Component Inventory | Discovery scans validate the inventory |

## POA&M essentials
A POA&M item answers: **what** is wrong (weakness, source, plugin ID), **where** (asset identifiers), **who** owns it (POC), **how** it'll be fixed (remediation plan, resources), **when** (milestones, scheduled completion), and **status**. Deviations: *false positive*, *operational requirement*, *risk adjustment*, *vendor dependency*. Each needs justification and approval.

## ACAS
DoD's **Assured Compliance Assessment Solution**: Tenable **Security Center** managing **Nessus** scanners (plus the Nessus Network Monitor), used for vulnerability and STIG compliance scanning across DoD networks. Skills from this lab (policies, credentialed scans, plugin analysis, `.nessus` exports) map directly to ACAS work.

## Scoring
| Score | What it measures | Limitation |
|---|---|---|
| **CVSS v3.1 base** (0–10) | Intrinsic technical severity | Static; ignores threat activity and your environment |
| **CVSS environmental** | Base adjusted for your CIA requirements | Rarely filled in |
| **VPR** (Tenable, 0–10) | Technical impact + threat intel (exploit maturity, recent activity) | Proprietary; changes daily |
| **EPSS** (0–1) | Probability of exploitation in next 30 days | Probability, not impact |
| **CISA KEV** | Known exploited in the wild | Binary; not exhaustive |

## Credentialed vs. uncredentialed
| | Uncredentialed | Credentialed |
|---|---|---|
| Perspective | External attacker | Insider / patch auditor |
| Finds | Exposed services, banners, network-level vulns | Missing patches, local software, configs, registry |
| False positives | Higher (banner/version guessing) | Lower (reads installed versions) |
| Risk | Low | Requires managing a privileged scan account securely |

## Talking about risk to non-technical audiences
Lead with **business impact and decision needed**, not plugin IDs: *"Two systems can be fully taken over remotely with public, actively used exploits. Fixing them takes about 4 hours of admin time and a reboot window. Recommend approval this week."*
