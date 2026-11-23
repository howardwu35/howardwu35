#!/usr/bin/env python3
"""
nessus_report.py - Turn Nessus .nessus (v2 XML) exports into risk-analyst deliverables.

Subcommands
-----------
  report   Parse one scan and produce:
             findings.csv   - one row per host/plugin finding, with contextual risk score
             poam.csv       - Plan of Action & Milestones (NIST 800-53 / FedRAMP style)
             report.md      - executive summary + prioritized technical findings
  diff     Compare a baseline scan with a rescan and produce a remediation
           validation report (remediated / persisting / new findings).

Only the Python standard library is used, so it runs anywhere Python 3.8+ is installed.

Examples
--------
  python3 nessus_report.py report scans/baseline.nessus -o output/baseline \
      --assets assets.csv --kev known_exploited_vulnerabilities.csv

  python3 nessus_report.py diff scans/baseline.nessus scans/rescan.nessus -o output/diff
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Remediation SLAs in days. Critical/High follow the spirit of CISA BOD 19-02
# (15 / 30 days for internet-facing systems); Medium/Low are common internal
# policy values. Override with --sla.
DEFAULT_SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}

# Asset-criticality adjustments (additive) used for contextual risk scoring.
CRITICALITY_ADJUSTMENT = {"high": 1.0, "medium": 0.0, "low": -1.0}
RATING_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    host: str
    ip: str
    fqdn: str
    os: str
    port: str
    protocol: str
    service: str
    plugin_id: str
    plugin_name: str
    plugin_family: str
    severity: int
    severity_name: str
    cvss3: Optional[float]
    cvss2: Optional[float]
    vpr: Optional[float]
    cves: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_frameworks: List[str] = field(default_factory=list)
    synopsis: str = ""
    description: str = ""
    solution: str = ""
    plugin_output: str = ""
    see_also: str = ""
    # Enrichment
    asset_criticality: str = "medium"
    asset_owner: str = ""
    in_kev: bool = False
    risk_score: float = 0.0
    risk_rating: str = ""

    @property
    def key(self) -> Tuple[str, str, str, str]:
        """Identity of a finding across scans: host + plugin + port + protocol."""
        return (self.ip or self.host, self.plugin_id, self.port, self.protocol)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _float(text: Optional[str]) -> Optional[float]:
    try:
        return float(text) if text not in (None, "") else None
    except ValueError:
        return None


def _text(item: ET.Element, tag: str) -> str:
    el = item.find(tag)
    return (el.text or "").strip() if el is not None else ""


def parse_nessus(path: str, include_info: bool = False) -> Tuple[List[Finding], Dict[str, dict]]:
    """Parse a .nessus v2 file. Returns (findings, host_properties_by_host)."""
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "NessusClientData_v2":
        raise ValueError(f"{path}: not a NessusClientData_v2 file (root tag {root.tag!r})")

    findings: List[Finding] = []
    hosts: Dict[str, dict] = {}

    for rhost in root.iter("ReportHost"):
        name = rhost.get("name", "")
        props = {}
        hp = rhost.find("HostProperties")
        if hp is not None:
            for tag in hp.findall("tag"):
                props[tag.get("name", "")] = (tag.text or "").strip()
        hosts[name] = props
        ip = props.get("host-ip", name)
        fqdn = props.get("host-fqdn", props.get("netbios-name", ""))
        os_name = props.get("operating-system", "")

        for item in rhost.findall("ReportItem"):
            sev = int(item.get("severity", "0"))
            if sev == 0 and not include_info:
                continue
            frameworks = []
            for tag, label in (
                ("exploit_framework_metasploit", "Metasploit"),
                ("exploit_framework_core", "CORE Impact"),
                ("exploit_framework_canvas", "CANVAS"),
            ):
                if _text(item, tag).lower() == "true":
                    frameworks.append(label)
            findings.append(
                Finding(
                    host=name,
                    ip=ip,
                    fqdn=fqdn,
                    os=os_name,
                    port=item.get("port", "0"),
                    protocol=item.get("protocol", ""),
                    service=item.get("svc_name", ""),
                    plugin_id=item.get("pluginID", ""),
                    plugin_name=item.get("pluginName", ""),
                    plugin_family=item.get("pluginFamily", ""),
                    severity=sev,
                    severity_name=SEVERITY_NAMES.get(sev, str(sev)),
                    cvss3=_float(_text(item, "cvss3_base_score")),
                    cvss2=_float(_text(item, "cvss_base_score")),
                    vpr=_float(_text(item, "vpr_score")),
                    cves=[c.text.strip() for c in item.findall("cve") if c.text],
                    exploit_available=_text(item, "exploit_available").lower() == "true",
                    exploit_frameworks=frameworks,
                    synopsis=_text(item, "synopsis"),
                    description=_text(item, "description"),
                    solution=_text(item, "solution"),
                    plugin_output=_text(item, "plugin_output"),
                    see_also=_text(item, "see_also"),
                )
            )
    return findings, hosts


# --------------------------------------------------------------------------- #
# Enrichment & risk scoring
# --------------------------------------------------------------------------- #
def load_assets(path: Optional[str]) -> Dict[str, dict]:
    """assets.csv columns: ip,hostname,criticality,owner,description"""
    if not path:
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["ip"].strip(): row for row in csv.DictReader(fh) if row.get("ip")}


def load_kev(path: Optional[str]) -> Set[str]:
    """CISA KEV catalog CSV (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)."""
    if not path:
        return set()
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["cveID"].strip() for row in csv.DictReader(fh) if row.get("cveID")}


def base_score(f: Finding) -> float:
    """Best available 0-10 technical score: VPR > CVSSv3 > CVSSv2 > severity bucket."""
    for s in (f.vpr, f.cvss3, f.cvss2):
        if s is not None:
            return s
    return {4: 9.5, 3: 7.5, 2: 5.0, 1: 2.5, 0: 0.0}[f.severity]


def _rating_for(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low" if score > 0 else "Info"


def score_finding(f: Finding) -> None:
    """
    Contextual risk = technical score + asset context + threat context (0-10).

      technical score : VPR, else CVSSv3, else CVSSv2
      asset context   : +1.0 high-criticality asset / 0 medium / -1.0 low
      threat context  : +0.5 public exploit available, +1.5 CVE on CISA KEV
      guardrail       : the rating may move at most ONE level from the Nessus
                        severity, except KEV findings, which are always at
                        least High (actively exploited in the wild).
    """
    score = base_score(f) + CRITICALITY_ADJUSTMENT.get(f.asset_criticality.lower(), 0.0)
    if f.exploit_available:
        score += 0.5
    if f.in_kev:
        score += 1.5
    f.risk_score = round(max(0.0, min(score, 10.0)), 1)

    rating_idx = RATING_ORDER.index(_rating_for(f.risk_score))
    sev_idx = f.severity  # 0..4 lines up with RATING_ORDER
    lo, hi = max(1 if sev_idx else 0, sev_idx - 1), min(4, sev_idx + 1)
    rating_idx = min(max(rating_idx, lo), hi)
    if f.in_kev:
        rating_idx = max(rating_idx, RATING_ORDER.index("High"))
    f.risk_rating = RATING_ORDER[rating_idx]


def enrich(findings: Iterable[Finding], assets: Dict[str, dict], kev: Set[str]) -> None:
    for f in findings:
        a = assets.get(f.ip)
        if a:
            f.asset_criticality = (a.get("criticality") or "medium").strip().lower()
            f.asset_owner = (a.get("owner") or "").strip()
            if not f.fqdn:
                f.fqdn = (a.get("hostname") or "").strip()
        f.in_kev = any(c in kev for c in f.cves)
        score_finding(f)


# --------------------------------------------------------------------------- #
# NIST 800-53 control mapping (heuristic, for POA&M "Controls" column)
# --------------------------------------------------------------------------- #
def map_controls(f: Finding) -> str:
    name = f.plugin_name.lower()
    fam = f.plugin_family.lower()
    if any(k in name for k in ("default password", "password", "credentials", "anonymous", "null session")):
        return "IA-5, AC-2"
    if "backdoor" in name or "bind shell" in name:
        return "SI-3, SI-4, CM-7"
    if any(k in name for k in ("ssl", "tls", "certificate", "cipher", "sweet32", "poodle")):
        return "SC-8, SC-13, SC-23"
    if any(k in name for k in ("signing not required", "smb signing")):
        return "SC-8, CM-6"
    if any(k in name for k in ("unsupported", "end of life", "eol", "obsolete")):
        return "SA-22, SI-2"
    if any(k in name for k in ("service detection", "rlogin", "rsh", "rexec", "telnet", "nfs", "trace")):
        return "CM-7, CM-6"
    if "misc" in fam or "settings" in fam or "general" in fam:
        return "CM-6, SI-2"
    return "SI-2, RA-5"


# --------------------------------------------------------------------------- #
# Output: CSVs
# --------------------------------------------------------------------------- #
FINDING_COLUMNS = [
    "risk_rating", "risk_score", "severity_name", "cvss3", "vpr", "in_kev", "exploit_available",
    "ip", "fqdn", "os", "asset_criticality", "asset_owner", "port", "protocol", "service",
    "plugin_id", "plugin_name", "plugin_family", "cves", "synopsis", "solution",
]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-f.risk_score, -f.severity, f.ip, f.plugin_id))


def write_findings_csv(findings: List[Finding], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FINDING_COLUMNS)
        w.writeheader()
        for f in sort_findings(findings):
            row = {k: v for k, v in asdict(f).items() if k in FINDING_COLUMNS}
            row["cves"] = " ".join(f.cves)
            w.writerow(row)


POAM_COLUMNS = [
    "POA&M ID", "Controls", "Weakness Name", "Weakness Description", "Detector Source",
    "Source Identifier", "Asset Identifier", "Point of Contact", "Resources Required",
    "Remediation Plan", "Original Detection Date", "Scheduled Completion Date",
    "Milestones", "Status", "Original Risk Rating", "CVSSv3", "CVE", "Exploit Available",
    "CISA KEV", "Comments",
]


def group_for_poam(findings: List[Finding]) -> List[Tuple[str, List[Finding]]]:
    """One POA&M item per weakness (plugin), listing every affected asset."""
    groups: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.severity >= 1:
            groups[f.plugin_id].append(f)
    return sorted(groups.items(), key=lambda kv: -max(x.risk_score for x in kv[1]))


def write_poam_csv(findings: List[Finding], path: str, scan_date: dt.date,
                   sla: Dict[str, int]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=POAM_COLUMNS)
        w.writeheader()
        for i, (pid, group) in enumerate(group_for_poam(findings), start=1):
            top = max(group, key=lambda x: x.risk_score)
            rating = top.risk_rating if top.risk_rating != "Info" else "Low"
            due = scan_date + dt.timedelta(days=sla.get(rating, 180))
            assets = sorted({f"{g.ip}:{g.port}/{g.protocol}" for g in group})
            owners = sorted({g.asset_owner for g in group if g.asset_owner})
            w.writerow({
                "POA&M ID": f"V-{scan_date:%Y%m%d}-{i:03d}",
                "Controls": map_controls(top),
                "Weakness Name": top.plugin_name,
                "Weakness Description": top.synopsis or top.description[:300],
                "Detector Source": "Tenable Nessus",
                "Source Identifier": f"Plugin {pid}",
                "Asset Identifier": "; ".join(assets),
                "Point of Contact": "; ".join(owners) or "TBD",
                "Resources Required": "Sys admin time; change window",
                "Remediation Plan": top.solution,
                "Original Detection Date": scan_date.isoformat(),
                "Scheduled Completion Date": due.isoformat(),
                "Milestones": (f"1) Approve change by {(scan_date + dt.timedelta(days=max(1, sla.get(rating, 180)//3))).isoformat()}; "
                               f"2) Remediate; 3) Validate with credentialed rescan by {due.isoformat()}"),
                "Status": "Open",
                "Original Risk Rating": rating,
                "CVSSv3": top.cvss3 if top.cvss3 is not None else "",
                "CVE": " ".join(sorted({c for g in group for c in g.cves})),
                "Exploit Available": "Yes" if any(g.exploit_available for g in group) else "No",
                "CISA KEV": "Yes" if any(g.in_kev for g in group) else "No",
                "Comments": "",
            })


# --------------------------------------------------------------------------- #
# Output: Markdown report
# --------------------------------------------------------------------------- #
def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def scan_date_from(hosts: Dict[str, dict]) -> dt.date:
    for props in hosts.values():
        raw = props.get("HOST_START") or props.get("HOST_END")
        if raw:
            for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
                try:
                    return dt.datetime.strptime(raw, fmt).date()
                except ValueError:
                    continue
    return dt.date.today()


def credentialed_status(hosts: Dict[str, dict]) -> Dict[str, str]:
    out = {}
    for name, props in hosts.items():
        val = props.get("Credentialed_Scan", "").lower()
        out[name] = "Yes" if val == "true" else ("No" if val == "false" else "Unknown")
    return out


def write_markdown(findings: List[Finding], hosts: Dict[str, dict], path: str,
                   title: str, scan_date: dt.date, sla: Dict[str, int]) -> None:
    sev_counts = Counter(f.severity_name for f in findings)
    risk_counts = Counter(f.risk_rating for f in findings)
    by_host: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_host[f.ip].append(f)
    exploitable = [f for f in findings if f.exploit_available and f.severity >= 3]
    kev_hits = [f for f in findings if f.in_kev]
    ordered = sort_findings(findings)
    creds = credentialed_status(hosts)
    unique_plugins = {f.plugin_id for f in findings}

    L: List[str] = []
    L.append(f"# {title}\n")
    L.append(f"**Scan date:** {scan_date.isoformat()}  ")
    L.append(f"**Hosts assessed:** {len(hosts)}  ")
    L.append(f"**Findings (Low+):** {len(findings)} across {len(unique_plugins)} unique weaknesses  ")
    L.append(f"**Generated:** {dt.date.today().isoformat()} by `nessus_report.py`\n")

    L.append("## 1. Executive Summary\n")
    crit_high = risk_counts.get("Critical", 0) + risk_counts.get("High", 0)
    worst_host = max(by_host.items(), key=lambda kv: sum(x.risk_score for x in kv[1]))[0] if by_host else "n/a"
    L.append(
        f"The assessment identified **{crit_high} Critical/High contextual-risk findings**. "
        f"**{len(exploitable)}** High/Critical findings have a publicly available exploit"
        + (f", and **{len(kev_hits)}** map to CVEs on the CISA Known Exploited Vulnerabilities catalog" if kev_hits else "")
        + f". The highest aggregate risk is concentrated on **{worst_host}**. "
        "Recommended priority: remediate exploitable Critical findings first, then High findings "
        "within SLA, and validate every fix with a credentialed rescan.\n"
    )

    L.append("### Severity distribution (Nessus severity vs. contextual risk)\n")
    L.append("| Level | Nessus severity | Contextual risk | Remediation SLA |")
    L.append("|---|---:|---:|---|")
    for lvl in ("Critical", "High", "Medium", "Low"):
        L.append(f"| {lvl} | {sev_counts.get(lvl, 0)} | {risk_counts.get(lvl, 0)} | {sla.get(lvl, '-')} days |")
    L.append("")

    L.append("### Risk by host\n")
    L.append("| Host | OS | Criticality | Credentialed | Crit | High | Med | Low | Aggregate risk |")
    L.append("|---|---|---|---|---:|---:|---:|---:|---:|")
    for ip, fs in sorted(by_host.items(), key=lambda kv: -sum(x.risk_score for x in kv[1])):
        c = Counter(x.risk_rating for x in fs)
        hname = fs[0].host
        L.append(
            f"| {ip} {('(' + fs[0].fqdn + ')') if fs[0].fqdn else ''} | {_md_escape(fs[0].os[:40])} | "
            f"{fs[0].asset_criticality.title()} | {creds.get(hname, 'Unknown')} | {c.get('Critical', 0)} | "
            f"{c.get('High', 0)} | {c.get('Medium', 0)} | {c.get('Low', 0)} | "
            f"{round(sum(x.risk_score for x in fs), 1)} |"
        )
    L.append("")

    L.append("## 2. Top 10 Prioritized Findings\n")
    L.append("| # | Risk | Score | CVSSv3 | Host | Port | Finding | Exploit | KEV |")
    L.append("|---:|---|---:|---:|---|---|---|---|---|")
    for i, f in enumerate(ordered[:10], 1):
        L.append(
            f"| {i} | {f.risk_rating} | {f.risk_score} | {f.cvss3 if f.cvss3 is not None else '-'} | "
            f"{f.ip} | {f.port}/{f.protocol} | {_md_escape(f.plugin_name)} | "
            f"{'Yes' if f.exploit_available else 'No'} | {'Yes' if f.in_kev else 'No'} |"
        )
    L.append("")

    L.append("## 3. Detailed Findings (Critical & High)\n")
    seen = set()
    n = 0
    for f in ordered:
        if f.risk_rating not in ("Critical", "High") or f.plugin_id in seen:
            continue
        seen.add(f.plugin_id)
        n += 1
        affected = sorted({f"{x.ip}:{x.port}/{x.protocol}" for x in findings if x.plugin_id == f.plugin_id})
        L.append(f"### 3.{n} {f.plugin_name}\n")
        L.append(f"- **Contextual risk:** {f.risk_rating} ({f.risk_score}) | **Nessus severity:** {f.severity_name}"
                 f" | **CVSSv3:** {f.cvss3 if f.cvss3 is not None else 'n/a'} | **VPR:** {f.vpr if f.vpr is not None else 'n/a'}")
        L.append(f"- **Plugin ID:** {f.plugin_id} ({f.plugin_family})")
        if f.cves:
            L.append(f"- **CVE(s):** {', '.join(f.cves)}")
        L.append(f"- **Affected:** {', '.join(affected)}")
        L.append(f"- **Exploitability:** {'Public exploit available' if f.exploit_available else 'No public exploit known'}"
                 + (f" ({', '.join(f.exploit_frameworks)})" if f.exploit_frameworks else "")
                 + ("; **listed in CISA KEV**" if f.in_kev else ""))
        L.append(f"- **NIST 800-53 controls:** {map_controls(f)}\n")
        if f.synopsis:
            L.append(f"**Synopsis.** {f.synopsis}\n")
        if f.solution:
            L.append(f"**Remediation.** {f.solution}\n")
        if f.plugin_output:
            out = f.plugin_output.strip()
            L.append("**Evidence (plugin output):**\n")
            L.append("```\n" + (out[:800] + ("\n...[truncated]" if len(out) > 800 else "")) + "\n```\n")

    L.append("## 4. Methodology & Scoring\n")
    L.append(
        "Contextual risk = best available technical score (VPR → CVSSv3 → CVSSv2) + asset context "
        "(+1.0 High / 0 Medium / −1.0 Low criticality) + threat context (+0.5 public exploit, +1.5 CISA KEV), "
        "bounded 0–10. Ratings: ≥9 Critical, ≥7 High, ≥4 Medium, >0 Low. Guardrail: context may move a "
        "rating at most one level from the Nessus severity, except KEV findings, which are never below High. "
        "Informational plugins are excluded from counts.\n"
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


# --------------------------------------------------------------------------- #
# Diff (remediation validation)
# --------------------------------------------------------------------------- #
def diff_scans(base: List[Finding], new: List[Finding]):
    b = {f.key: f for f in base}
    n = {f.key: f for f in new}
    remediated = [b[k] for k in b.keys() - n.keys()]
    persisting = [n[k] for k in b.keys() & n.keys()]
    introduced = [n[k] for k in n.keys() - b.keys()]
    return sort_findings(remediated), sort_findings(persisting), sort_findings(introduced)


def write_diff_markdown(base: List[Finding], new: List[Finding], path: str,
                        base_date: dt.date, new_date: dt.date) -> None:
    remediated, persisting, introduced = diff_scans(base, new)

    def count(fs, lvl):
        return sum(1 for f in fs if f.severity_name == lvl)

    L = ["# Remediation Validation Report\n",
         f"**Baseline scan:** {base_date.isoformat()}  ",
         f"**Validation rescan:** {new_date.isoformat()}\n",
         "## Summary\n",
         "| Severity | Baseline | Rescan | Remediated | Persisting | New |",
         "|---|---:|---:|---:|---:|---:|"]
    for lvl in ("Critical", "High", "Medium", "Low"):
        L.append(f"| {lvl} | {count(base, lvl)} | {count(new, lvl)} | {count(remediated, lvl)} | "
                 f"{count(persisting, lvl)} | {count(introduced, lvl)} |")
    total_b = len(base) or 1
    L.append(f"\n**Risk reduction:** {len(remediated)} of {len(base)} findings closed "
             f"({round(100 * len(remediated) / total_b)}%). "
             f"Aggregate risk score {round(sum(f.risk_score for f in base), 1)} → "
             f"{round(sum(f.risk_score for f in new), 1)}.\n")

    for title, fs, status in (("Remediated (close POA&M items)", remediated, "Closed"),
                              ("Persisting (remediation failed or pending)", persisting, "Open"),
                              ("Newly introduced", introduced, "New")):
        L.append(f"## {title}\n")
        if not fs:
            L.append("_None._\n")
            continue
        L.append("| Severity | Host | Port | Plugin | Finding | Status |")
        L.append("|---|---|---|---|---|---|")
        for f in fs:
            L.append(f"| {f.severity_name} | {f.ip} | {f.port}/{f.protocol} | {f.plugin_id} | "
                     f"{_md_escape(f.plugin_name)} | {status} |")
        L.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_sla(s: Optional[str]) -> Dict[str, int]:
    sla = dict(DEFAULT_SLA_DAYS)
    if s:
        for part in s.split(","):
            k, v = part.split("=")
            sla[k.strip().title()] = int(v)
    return sla


def cmd_report(a) -> int:
    findings, hosts = parse_nessus(a.scan, include_info=a.include_info)
    enrich(findings, load_assets(a.assets), load_kev(a.kev))
    os.makedirs(a.output, exist_ok=True)
    sla = parse_sla(a.sla)
    date = scan_date_from(hosts)
    write_findings_csv(findings, os.path.join(a.output, "findings.csv"))
    write_poam_csv(findings, os.path.join(a.output, "poam.csv"), date, sla)
    write_markdown(findings, hosts, os.path.join(a.output, "report.md"), a.title, date, sla)
    c = Counter(f.severity_name for f in findings)
    print(f"[+] {len(hosts)} hosts, {len(findings)} findings "
          f"(C:{c['Critical']} H:{c['High']} M:{c['Medium']} L:{c['Low']}) -> {a.output}/")
    return 0


def cmd_diff(a) -> int:
    assets, kev = load_assets(a.assets), load_kev(a.kev)
    base, bh = parse_nessus(a.baseline)
    new, nh = parse_nessus(a.rescan)
    enrich(base, assets, kev)
    enrich(new, assets, kev)
    os.makedirs(a.output, exist_ok=True)
    out = os.path.join(a.output, "remediation_validation.md")
    write_diff_markdown(base, new, out, scan_date_from(bh), scan_date_from(nh))
    r, p, i = diff_scans(base, new)
    print(f"[+] remediated={len(r)} persisting={len(p)} new={len(i)} -> {out}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-o", "--output", default="output", help="output directory")
    common.add_argument("--assets", help="assets.csv (ip,hostname,criticality,owner,description)")
    common.add_argument("--kev", help="CISA KEV catalog CSV for exploited-in-the-wild enrichment")

    r = sub.add_parser("report", parents=[common], help="generate report, findings CSV and POA&M")
    r.add_argument("scan", help=".nessus file")
    r.add_argument("--title", default="Vulnerability Assessment Report")
    r.add_argument("--sla", help="override SLAs, e.g. Critical=7,High=30,Medium=60,Low=120")
    r.add_argument("--include-info", action="store_true", help="include informational (severity 0) plugins")
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("diff", parents=[common], help="compare baseline vs rescan")
    d.add_argument("baseline")
    d.add_argument("rescan")
    d.set_defaults(func=cmd_diff)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
