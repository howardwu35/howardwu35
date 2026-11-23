# 03 · Scan Execution & Export

## Run Order
1. Snapshot targets (`baseline-vulnerable`).
2. Host Discovery → confirm 2 live targets.
3. Uncredentialed Basic Network Scan.
4. Credentialed Basic Network Scan.
5. Export each scan: *Scan → Export → **Nessus*** (`.nessus` XML, the machine-readable source of truth). Optionally also export the built-in PDF/HTML report.
6. Save to `scans/`:
   ```
   scans/baseline-uncredentialed.nessus
   scans/baseline-credentialed.nessus
   ```

## Generate Deliverables
```bash
python3 scripts/nessus_report.py report scans/baseline-credentialed.nessus \
    -o reports/baseline --assets assets.example.csv \
    --kev known_exploited_vulnerabilities.csv \
    --title "Lab Vulnerability Assessment: Baseline"
```
Download the KEV CSV from CISA's *Known Exploited Vulnerabilities Catalog* page.

## Credentialed vs. Uncredentialed Comparison
Fill this in from your two scans (`findings.csv` counts or the Nessus dashboard):

| Host | Scan type | Critical | High | Medium | Low | Total |
|---|---|---:|---:|---:|---:|---:|
| 192.168.56.101 | Uncredentialed | | | | | |
| 192.168.56.101 | Credentialed | | | | | |
| 192.168.56.102 | Uncredentialed | | | | | |
| 192.168.56.102 | Credentialed | | | | | |

**Analysis prompts** (answer in 2–3 sentences each, from your own data):
- What *kinds* of findings appeared only in the credentialed scan? (Usually missing OS/app patches and local privilege escalation. These can't be seen over the network.)
- Did any network-exposed finding disappear or change in the credentialed scan? Why?
- Which view matters more for a risk decision, and why do mature programs run both?

## Scan Hygiene Notes
- Record start/end times, scanner IP, plugin feed version, and policy name for each scan. These go in the report's *Scope & Methodology* section and are needed for audit evidence (RA-5).
- Scans can disrupt fragile services. In production, schedule them in an approved window and notify system owners.

## Evidence to Capture
- [ ] Scan history page showing both scans completed
- [ ] Dashboard severity breakdown for each scan
- [ ] Your completed comparison table above
