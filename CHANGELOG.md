# Changelog

*Versions 2.1–2.4 were developed on two parallel branches — one adding capability, one
preparing the public release — merged at 2.4, with the listing branch landing at 2.6 — the first public release. Entries
below are ordered by content.*

## 2.6 — first public release

- **HW/SW baseline listing ingestion.** Documented hardware and software listings
  (`.xlsx` / `.csv` / `.tsv`, combined or separate) are recognized alongside scan exports
  and merged into one dataset. Columns map by alias rather than position, the header row is
  located past title banners, duplicate headers merge, and the hardware/software type column
  is honored when named, detected from data values when unnamed, with a per-row heuristic as
  final fallback. Workbooks route per worksheet, so a file carrying both intel and a listing
  lands correctly.
- **Conservative merging with provenance.** Hardware rows enrich the Asset Inventory
  (manufacturer, model, serial, location, plus facility / CI-rack / drawing / interconnect);
  software rows join the Software Listing. Listings fill blanks and never overwrite scan
  evidence or manual edits — disagreements surface as flagged conflicts. Every row is tagged
  scan / listing / both / manual, carried through consolidation, sessions, and exports.
- **Software reconciliation** on the Reconciliation tab and in its export: version drift,
  detected-but-not-listed, listed-but-never-confirmed. Hardware that never scans feeds asset
  reconciliation automatically.
- **eMASS hardware baseline rewritten** to draw from the merged inventory rather than scan
  hosts alone, so non-scanning assets make the baseline. Both eMASS exports carry provenance.
- Listing software joins the threat-intel watchlist; four new readiness checks.
- Fixed: product names carrying a bare architecture suffix (`Wireshark 4.2.5 64-bit`) failed
  to match their listing entry, so an approval decision recorded against the listed name did
  not attach to the installed product. Bracketed suffixes were already handled; bare ones now
  are too.

## 2.5.1

- **Ingest integrity.** Each report-host entry now records its source file with the MAC,
  IP, and OS reported there, and those identities are compared across every source that
  contributed to an asset. Two machines sharing a short hostname merge onto one host key
  and interleave their evidence invisibly; this flags the mismatch, along with an IP
  appearing under more than one asset. Surfaced on Scan Health and gated in readiness.
- **Last-logon capture.** Logon dates are parsed from the user-information plugins and
  shown per account, with a per-user view showing which machines an account appears on
  and where it most recently logged on. Where a scan reports no date the field stays
  empty — presence on a machine is not evidence of use.
- Renamed to **Palisade**. The tool is not tied to any one scanner deployment or
  organization, and the old name implied both.
- Documentation rewritten for a general audience; DoD-specific outputs are described as
  individual exports rather than the framing of the whole tool.
- Session compatibility preserved: session files written by every prior version, under
  every prior tool name, still load — as sessions and as baselines.

## 2.5

- **Remediation Plan view**, now the default: findings resolved to the action that closes
  them — a vendor advisory, a Microsoft KB, or a version upgrade — and ranked by the risk
  each action retires rather than by row count. Fifty browser findings become one upgrade
  with the highest version any of them demands.
- **Software Summary view**: which products drive the exposure, with the fixes that clear
  each. A product showing several fixes genuinely needs several patches.
- Grouping happens only on a recognized signal in the scan data. Findings stating no fix
  are marked **unparsed** and kept separate rather than folded into a neighbouring action.
- `remedyWeights` and `productAliases` added to Detection Config.
- Leadership lenses: the low-hanging-fruit lens now populates from scan evidence alone,
  where previously it required a threat-intel sheet.

## 2.4

- Renamed to **Palisade**. The tool is not tied to any one scanner deployment or organization,
  and the old name implied both.
- Combines the 2.1–2.3.2 capability line with the public-release preparation: sanitization,
  generalized session-identifier matching, terminology (Tenable-first; ACAS retained where it
  correctly names the DoD program), and demo data moved to RFC 5737 documentation addresses.
- Session compatibility is preserved: session files written by every prior version, under
  every prior tool name, still load — as sessions and as baselines.
- Documentation rewritten for a general audience; DoD-specific outputs are now described as
  individual exports rather than the framing of the whole tool.

## 2.3.2

- Asset detail drawer: click any host name or IP anywhere for a consolidated view of that
  machine — identity, scan provenance, findings, STIG results, accounts, software, ports —
  plus a one-click asset report export.
- Trend & burndown: one metrics point per assessment cycle, with burndown charts, a movement
  table, and retroactive history rebuilt from previously saved session files.
- Setting a baseline records a trend point automatically.

## 2.3.1

- Detection patterns support regular expressions (`re:` prefix) alongside plain substrings.
  Fixes silent match failures for products scanners report with variable tokens mid-string —
  Red Hat Enterprise Linux, Windows Server, and ESXi were affected in both STIG applicability
  and end-of-support detection.

## 2.3

- SCC XCCDF result ingestion (namespace-tolerant), STIG Viewer `.ckl` and `.cklb` checklist
  ingestion, and `.zip` handling for both.
- STIG Compliance tab: per-host/per-STIG scoring with a stated definition, filterable rule
  detail, and coverage reconciliation against the applicability matrix — surfacing STIGs
  applicable but never assessed.
- Four new exports including a STIG POA&M draft grouped by weakness across hosts.

## 2.2

- Six analysis views over one shared filter: vulnerability summary, IP summary, detail list,
  port summary, plugin family, subnet summary; per-host drill-down.
- Remediation aging from patch publication against configurable windows.
- Scan Health tab: credentialed-check verification, scan policy, plugin feed age, per host —
  parsed from the scan's own record of itself.

## 2.1

- Account audit: users, groups, and account-state flags from credentialed enumeration, with
  dormant, stale-password, and default-account exceptions per host.
- Vulnerability capture widened to all severity-rated findings, not only CVE-bearing ones;
  POA&M draft export with evidence fields prefilled and decision fields left blank.
- Selectable threat-intel score source — the built-in blend, any mapped field, or any unmapped
  numeric column a sheet carried, discovered from the data rather than hardcoded.
- Leadership lens reports: quick strikes, low-hanging fruit, engineering campaigns, and
  modernization, with grouped actions, inline charts, a self-contained HTML report, a
  plain-text executive summary, and an AI prompt package.

## 2.0

- Refreshed UI, first-run onboarding wizard, per-tab plain-language help, searchable glossary
- Live readiness meter — a pre-delivery QC score with specific gaps called out
- Demo dataset: six synthetic hosts that exercise the real engine
- Threat-intel ingestion and fusion with scan findings for prioritization
- Environment profiles: export settings and detection config (never scan data)

## 1.7.1

- STIG version fields no longer ship pre-populated. They were stale defaults carried from an
  earlier build; a wrong version passes validation silently while a blank one is caught by the
  readiness gate. Fill from the current DISA quarterly release.

## 1.7

- Approval workflow: status, approver, date, reference per product; optional version pinning
- Approval round-trip via review sheet export and import
- Change findings tiered by severity; unapproved installs and removed security tooling escalate
- End-of-support detection with maintainable date table
- Control mappings embedded in export headers, plus a Control Mapping tab
- OS package manifest as a separate export

## 1.6

- Consolidates duplicate software rows (same product with and without a version)
- Flags ambiguous duplicates rather than guessing
- Parses RHEL `rpm -qa` output; OS packages typed separately and excluded by default
- Filters bare product GUIDs

## 1.5

- Asset Inventory tab with scan-derived and manual fields
- MAC address capture from scan data
- Manual entry for assets that exist but do not scan

## 1.4

- Fixed bullet-prefix duplication in software parsing
- Ephemeral port filter for PPSM
- Vendor, type, and device inference rules expanded
- eMASS-shaped baseline exports

## 1.3

- Change detection against a prior session baseline
- Asset reconciliation
- Pre-delivery readiness check
- Export All
- Fixed host key truncation for IP-only hosts; merge hosts by IP

## 1.2

- Software Listing tab

## 1.1

- Auto-activating STIG catalog
- Unmapped software review

## 1.0

- Initial release: STIG applicability matrix and PPSM matrix
