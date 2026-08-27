# Palisade

**An offline scan-to-evidence compiler.**

Palisade is a single HTML file that reads Tenable vulnerability scan exports and compiles them
into the artifacts a security control assessment actually asks for: STIG applicability
matrices and compliance scoring, software listings, asset inventories, account audits,
port/protocol matrices, change records, unsupported-component findings, POA&M drafts, a
threat-informed remediation queue, and posture trend across assessment cycles.

**No network calls. No dependencies. No install. No build step.** Open the file in a browser,
drag in your scan exports, and everything is parsed client-side. It runs from a USB drive, a
file share, or an air-gapped workstation with equal success.

```
palisade.html  →  open in any modern browser  →  drag in .nessus / SCC results / checklists  →  export evidence
```

---

## Why it exists

Turning scan data into control evidence is mostly clerical work — pivoting host and software
rows into the shape a reviewer wants — and it is done by hand far more often than it should
be. The obvious shortcuts are worse: uploading scan exports to an online converter or pasting
host inventories into a web tool moves sensitive infrastructure data somewhere you do not
control.

Palisade does the compilation locally in a browser. The scan data never leaves the machine,
because the tool has no way to send it anywhere.

## Who it's for

Anyone who has Tenable scan output and has to produce control evidence from it:

- **NIST 800-53 / RMF programs** — the artifacts map to CM, RA, SA, SI, and SC controls, and
  every export carries its control mapping in the header
- **DoD assessments specifically** — eMASS-shaped hardware and software baselines, PPSM
  registry rows, and DISA STIG applicability are first-class outputs
- **Anyone doing asset and software inventory work** — CM-8 style inventories, approved
  software lists, end-of-support tracking, and drift detection between scan cycles
- **Vulnerability management teams** — findings grouped into the actions that close them
  and ranked by risk retired, threat-intel fusion that orders remediation by real-world
  exploitation rather than raw CVSS, eight pivoting analysis views, and remediation aging
  against configurable windows
- **Anyone holding SCAP or checklist results** — SCC XCCDF output and STIG Viewer
  checklists compile into per-rule compliance detail, scoring, and coverage
  reconciliation against the applicability matrix

You do not need to be in a DoD program to get value from it. The DoD-specific outputs are
individual exports you can ignore; the inventory, drift, and prioritization engine is
framework-agnostic.

## Input

Any of these, dragged onto the Overview tab. Multiple files merge into one picture.

| Input | Notes |
|---|---|
| `.nessus` XML | Preferred. Tenable Nessus, Nessus Professional, Tenable Security Center, or an ACAS deployment |
| Tenable CSV | Fallback. Must include the Plugin Output column, and the CVE column for intel fusion |
| Threat-intel sheets | `.xlsx` / `.csv` keyed by CVE. Detected and routed automatically |
| SCC results | XCCDF result `.xml`, or the `.zip` SCC produces — both recognized automatically |
| STIG Viewer checklists | `.ckl` (XML) and `.cklb` (STIG Viewer 3 JSON) — manual review answers live here |
| Prior session `.json` | For drift detection against a previous baseline, or trend backfill |

Every format is recognized by content, not file extension — a mislabeled file routes
correctly or reports why it did not.

Credentialed scans are required for software detection. Uncredentialed hosts are flagged
explicitly and fall back to OS inference — they are never silently treated as clean.

## What it produces

| Export | Supports |
|---|---|
| `STIG_Applicability.csv` | CM-6, CM-6(1), CM-2 |
| `Software_Listing.csv` | CM-8, CM-8(1), CM-10, SA-22 |
| `Approved_Software_Review.csv` | CM-2, CM-5, CM-7(4), CM-11 |
| `Asset_Inventory.csv` | CM-8, CM-8(1), PM-5 |
| `Asset_Reconciliation.csv` | CM-8, CM-8(3), RA-5 |
| `Change_Record.csv` | CM-3, CM-6(3), CM-11, SI-7 |
| `PPSM_Registry.txt` / `PPSM_WorkingCopy.csv` | CM-7, CM-7(1), SC-7 |
| `Unsupported_Components.csv` | SA-22, RA-5, SI-2 |
| `Prioritized_Vulnerabilities.csv` | RA-5, RA-5(2), SI-5, SI-2 |
| `OS_Package_Manifest.csv` | CM-8(1), SA-22 |
| `eMASS_Hardware_Baseline.csv` / `eMASS_Software_Baseline.csv` | CM-8 (eMASS import shape) |
| `Account_Audit.csv` | AC-2, AC-2(3), AC-6(5), IA-4 |
| `POAM_Draft.csv` / `POAM_Draft_STIG.csv` | CA-5 (evidence fields prefilled, decisions left blank) |
| `Remediation_Plan.csv` | RA-5, SI-2 — ranked actions, not raw findings |
| `Vulnerability_Detail.csv` / `IP_Summary.csv` | RA-5, SI-2 |
| `STIG_Compliance_Summary.csv` / `STIG_Open_Findings.csv` / `STIG_Coverage.csv` | CM-6, CM-6(1), CA-2, CA-7 |
| `Scan_Coverage.csv` | RA-5, RA-5(1), RA-5(5) — credentialed-scan verification |
| `Trend_Burndown.csv` | CA-7, PM-6 — posture direction across cycles |
| `Asset_Report_<host>.csv` | Everything known about one asset, as a hand-off artifact |
| `Control_Mapping.csv` | The mapping itself, as a reviewable artifact |

Control mappings are embedded in every export header, so each artifact states what it
demonstrates rather than relying on the reader to know.

## Features

- **Auto-discovering STIG catalog** — products found in scans activate their own matrix
  column; nothing silently falls through
- **Software consolidation** — folds duplicate rows where the same product is reported with a
  version on one host and without on another, and flags genuinely ambiguous duplicates rather
  than guessing
- **Approval workflow** — export a review sheet, have it filled in, import the decisions back
- **Change detection** — diffs against a prior session, tiered by severity; unapproved
  installs and removed security tooling escalate
- **Threat-intel fusion** — ingests CVE-keyed intel spreadsheets and joins them to scan
  findings so remediation order follows observed exploitation (see below)
- **Remediation planning** — findings resolved to the action that closes them (a vendor
  advisory, a Microsoft KB, or a version upgrade) and ranked by the risk each action
  retires, so fifty browser findings read as one upgrade. Grouping happens only on a real
  signal in the scan data; anything unrecognized is marked *unparsed* and kept separate
  rather than merged into a plausible-looking neighbour
- **Eight analysis views** — remediation plan, software summary, vulnerability summary, IP
  summary, detail list, port summary, plugin family, and subnet summary over one shared
  filter, with per-host drill-down
- **Account audit** — user accounts, group memberships, last-logon dates, and
  account-state flags parsed from credentialed scan enumeration; dormant, stale-password,
  and default-account exceptions surfaced per host, plus a per-user view showing which
  machines each account appears on and where it last logged on
- **Ingest integrity** — every report-host entry records the file it came from with its
  MAC, IP, and OS, and those identities are compared across sources. Two different
  machines sharing a short hostname merge onto one asset key silently in any other tool;
  here the mismatch is flagged
- **STIG compliance results** — SCC XCCDF and STIG Viewer checklist ingestion with
  per-rule detail, a stated scoring definition, and coverage reconciliation that surfaces
  STIGs applicable per the matrix but never assessed
- **Scan health** — each scan's own record of itself: credentialed-check status, policy,
  plugin feed age; hosts whose evidence cannot be trusted are flagged before anything
  built on that evidence is
- **Remediation aging** — finding age from patch publication against configurable
  remediation windows, carried into every relevant view and export
- **Asset detail drawer** — click any host name anywhere for everything known about that
  machine, with a one-click consolidated asset report
- **Trend & burndown** — one metrics point per assessment cycle; history rebuilds
  retroactively from saved session files
- **Leadership reports** — four decision-maker lenses with a self-contained HTML report,
  a plain-text executive summary, and an AI prompt package (see below)
- **End-of-support detection** — flags components past vendor lifecycle
- **Asset reconciliation** — coverage gaps and unaccounted hosts, in both directions
- **Session persistence** — save/load a JSON sidecar so partial work can be handed off
- **Live readiness meter** — a pre-delivery QC score in the top bar; green means the evidence
  is internally complete, amber flags what a reviewer will ask about first
- **Guided onboarding** — first-run wizard, plain-language help on every tab (what to do and
  what it proves), and a searchable glossary
- **Demo dataset** — six synthetic hosts that exercise the real engine, so you can explore
  every tab and export before you have scan data in hand
- **Environment profiles** — export settings and detection rules (never scan data) as a small
  JSON to standardize a whole team's setup

## Usage

1. Export scan results as `.nessus` (in Security Center: Scans → Scan Results → Download).
2. Open `palisade.html` in a browser.
3. Drag scan files onto the Overview tab — SCC results and checklists too, if you have
   them. New here? Click **Load demo data** first to explore with synthetic hosts.
4. Fill your site constants once under Settings.
5. Work through the tabs — the **Help** button explains each one — then take the readiness
   checklist to green and **Export All**.

Nothing is written to `localStorage` or any other browser storage. Close the tab and the state
is gone unless you explicitly saved a session file.

## Threat intelligence fusion

The Threat Intel tab ingests CVE-keyed intel spreadsheets and fuses them with the CVE-bearing
findings in your scans. `.xlsx` is read directly — a minimal ZIP reader plus the browser's
native decompression, still no libraries and no network — and CSV/TSV work too.

**Columns map by alias, not position.** Intel feeds vary wildly in shape, so headers are
matched case- and punctuation-insensitively against an alias table, longest phrase first
(`CVE Description` maps to the description, not the CVE). The header row is located by scoring
the first ten rows, so title banners above the header are handled. Cells holding several CVEs
split into separate records, Excel date serials become ISO dates, and unmapped columns are
retained as passthrough rather than dropped. If your feed names something unexpectedly, add
that header to `intelAliases` in Detection Config and re-load — no code edits.

Each CVE gets a transparent priority score (0–100) from CVSS, risk score, weaponization, actor
attribution, attack vector, privilege requirement, and host count — all weights editable in
`intelWeights`. Tiers: **P1** = weaponized *and* confirmed present on your network; P2/P3 by
score; P4 = confirmed but low signal. Intel CVEs with no scan match are listed separately
rather than counted as exposure.

**The driving score is selectable.** When a feed computes its own composite score that
downstream reporting expects to see used, the score selector lists every scoring source
discovered in the data — the built-in blend, mapped fields, and any unmapped numeric column
the sheet carried — so an unfamiliar feed's own scoring works without code changes. Scores on
arbitrary scales normalize to 0–100 for tiering, with the raw value preserved in the table and
the export. P1 stays *weaponized and on-network* regardless of the selected source.

The **software watchlist** runs the other direction: products in your Software Listing that
intel names as affected but no scan finding confirms. That gap usually means an uncredentialed
or stale scan rather than a clean host — exactly the thing worth catching before delivery.

Prioritization guides remediation order. It never downgrades a finding out of existence, and
the risk decision stays with whoever owns it.

## Leadership reports

The Reports tab cuts compiled evidence four ways for decision-makers, grouping repetitive
endpoint work instead of listing it host by host ("Windows 10 upgrade × 8 endpoints"):

- **Quick strikes** — weaponized and confirmed on the network; the do-it-this-week list,
  including unsupported components that are also weaponized (no patch exists, so the action is
  isolate or replace)
- **Low-hanging fruit** — single updates that clear many endpoints at once
- **Engineering campaigns** — OS upgrade waves and fleet migrations needing change control
- **Modernization & lifecycle** — unsupported components as budget line items, plus removal of
  denied software

Outputs: a **self-contained HTML report** with inline-SVG charts, banner-stamped and ready to
attach to an email; a **plain-text executive summary** for the message body; and an **AI prompt
package** — a briefing plus JSON digest to paste into whatever AI assistant your organization
has approved — for narrative game plans. The package withholds host names unless you
explicitly include them. The tool itself never makes a network call; carrying a file to an AI
assistant is a deliberate human act, and the handling banner is there to make you think about
it first.

## Configuration

The Detection Config tab holds the STIG catalog, vendor and type inference rules, hostname
device rules, noise filters, the end-of-support date table, and the threat-intel column
aliases and scoring weights — all editable JSON, no code changes needed.

The shipped rules are deliberately generic. **Keep site-specific configuration local**: export
your environment profile and store it outside the repository rather than committing internal
naming conventions, hostname prefixes, or system identifiers.

## Limitations

Read these before you rely on an export.

- **PPSM shows listening services only.** Required outbound flows (NTP upstream, syslog
  forwarding, scanner-to-target) do not appear and must be accounted for separately.
- **STIG versions are entered manually.** The tool tracks what you enter; the current DISA
  quarterly release is the source of truth. Version fields ship blank on purpose — a stale
  default passes every check while being wrong.
- **End-of-support dates need verification.** The bundled table is a starting point. LTSC/LTSB
  builds and ESU-covered systems differ from mainstream dates. Confirm against the vendor
  before citing a date.
- **Intel fusion needs CVE-bearing findings.** A `.nessus` export carries them; a Tenable CSV
  needs its CVE column. A product on the watchlist but absent from findings is an open
  question, not a clean bill of health.
- **Intel is only as current as the sheet.** Nothing is fetched — the feed is a point-in-time
  snapshot. Re-load it each cycle and treat weaponization flags as of that date.
- **The compliance score has a stated definition.** Not-a-Finding ÷ (Not-a-Finding +
  Open); Not Applicable and Not Reviewed are excluded from the denominator. Organizations
  compute this differently — the definition is printed on the tab and in every export so
  a number is never quoted without it.
- **SCC alone leaves manual rules Not Reviewed.** Manual review answers exist only in
  checklists. A host assessed by SCC but missing its `.ckl` legitimately shows those
  rules as unassessed — import the checklist rather than explaining the gap away.
- **Presence is not use.** An account existing on a machine is not evidence anyone worked
  there. The last-logon date is what supports that claim, and where a scan did not report
  one the field stays empty rather than being inferred. Logon dates require the
  user-information plugin families in the scan policy.
- **Remediation grouping is conservative by design.** An action merges findings only on a
  recognized signal. Under-merging costs a longer list; over-merging would tell an
  assessor that a patch closes findings it does not.
- **The tool flags; it does not decide.** Approval, risk acceptance, prioritization, and
  registration decisions belong to the humans who own them.

## Handling your data

Scan exports, session files, and generated artifacts contain hostnames, IP addresses, MAC
addresses, and software inventories for real systems. Handle them at whatever classification
or sensitivity level your organization assigns that data, and mark them accordingly — the
banner field at the top of the tool stamps every export.

The `.gitignore` in this repository excludes scan data, session files, and generated artifacts
by filename pattern. **Do not loosen it.** The tool itself ships with no host data; the only
hosts in the repository are the six synthetic ones in the demo dataset.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: single file, no dependencies, no
network calls, and never commit scan data.

## License

MIT — see [LICENSE](LICENSE).

