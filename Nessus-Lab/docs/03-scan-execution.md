# 03 · Scan Execution & Export

## Run Order
1. Snapshot the Windows VM (`baseline-vulnerable`).
2. Host Discovery → confirm the target is live.
3. Uncredentialed Basic Network Scan.
4. Credentialed Basic Network Scan.
5. Export each: *Scan → Export → **Nessus*** (`.nessus` XML, the machine-readable source of truth).
6. Save to `scans/`:
   ```
   scans/baseline-uncredentialed.nessus
   scans/baseline-credentialed.nessus
   ```

📸 `screenshots/08-scan-history.png`: both scans completed
📸 `screenshots/09-uncredentialed-summary.png`: severity breakdown
📸 `screenshots/10-credentialed-summary.png`: severity breakdown
📸 `screenshots/11-vuln-detail.png`: a Critical/High finding's detail page (description, output, solution)

## Generate Deliverables
```bash
python3 scripts/nessus_report.py report scans/baseline-credentialed.nessus \
    -o reports/baseline --assets assets.example.csv \
    --kev known_exploited_vulnerabilities.csv \
    --title "Lab Vulnerability Assessment: Baseline"
```
Download the KEV CSV from CISA's *Known Exploited Vulnerabilities Catalog* page. Edit `assets.example.csv` so the IP matches your Windows VM.

## Credentialed vs. Uncredentialed Comparison

| Scan type | Critical | High | Medium | Low | Total |
|---|---:|---:|---:|---:|---:|
| Uncredentialed | | | | | |
| Credentialed | | | | | |

**Analysis** (2–3 sentences each, from your own data):
- What *kinds* of findings appeared only in the credentialed scan? (Expect missing Windows updates and outdated third-party apps. These are invisible over the network.)
- Which view matters more for a risk decision, and why do mature programs run both?

## Scan Hygiene
- Record start/end time, scanner IP, plugin feed version, and policy name for each scan. These go into the report's scope and methodology and serve as RA-5 audit evidence.
- In production, scan in an approved window and notify system owners. Scans can disrupt fragile services.
