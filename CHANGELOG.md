# Changelog

*Versions 2.1–2.4 were developed on two parallel branches — one adding capability, one
preparing the public release — merged at 2.4, with the listing branch landing at 2.6 — the first public release. Entries
below are ordered by content.*

## 2.8 — security hardening

An adversarial review of 2.7 found two places where a scanned hostname was written into the page
as code rather than as text, and one where a handed-over session file could change the behaviour
of every object in the page. Those are fixed. The rest of this release is the work around them:
a policy the browser enforces rather than a claim the README makes, escaping and limits on the
way in, and neutralisation on the way out. Nothing was removed and no export changed shape.
Four behaviour changes are called out below.

- **Two injection sinks closed.** The PPSM and STIG tables built their per-row controls by
  pasting the host key straight into an HTML attribute. A hostname carrying a double quote — and
  a scan export can carry one — closed the attribute early, and everything after it was parsed as
  markup. Both now escape the key once into a `data-` attribute and read it back from the DOM.
  The idiom used elsewhere for the same job, `JSON.stringify(x).replace(/"/g,"&quot;")`, escaped
  the quote but not the backslash that produces one, and is gone from the file.
- **Prototype pollution from a session, baseline, profile or trend file.** `JSON.parse` hands a
  file's `__proto__` key back as a real own property. `buildAssets` enumerates its input with
  `for..in` and writes through what it finds, so reading that key returned `Object.prototype` and
  the write landed on it — for every object in the page, for the rest of the session. The damage
  was to evidence, not to the browser: once everything inherited `fromScan`, the test that marks
  an asset as *not* seen by this cycle's scan stopped firing, and the scan-detected versus
  inventory-only distinction — which feeds the asset inventory, reconciliation, and the readiness
  meter — silently inverted. All seven places the tool reads untrusted JSON now go through a
  parser that drops the key before it is ever attached to an object.
- **CSV and TSV exports neutralise spreadsheet formulas.** Excel and LibreOffice treat a cell
  beginning `=`, `@`, tab, or carriage return as a formula — DDE, `WEBSERVICE`, `HYPERLINK` — and
  scan text reaches an assessor's networked machine as a file. Those cells are now written with a
  leading apostrophe, so a hostname of `=CMD|'/C CALC'!A0` arrives as text. A leading `+` or `-`
  is neutralised only when what follows is not a plain number, so `-5`, `+5`, and `-5%` keep
  their numeric type and numeric columns still sum. **Behaviour change:** an affected cell carries
  a visible apostrophe on import. That is deliberate — it is not hidden the way a typed-in leading
  quote is, and a value that needed neutralising is worth seeing. No other cell changed.
- **Content Security Policy.** The file carries a policy the browser enforces. No origin, host,
  or scheme is named as a source for anything — `default-src`, `connect-src`, `img-src`,
  `font-src`, `frame-src`, and `object-src` are all `'none'` — so "no network calls" stops being
  a property you confirm by reading 8,000 lines and becomes one the browser refuses to let the
  page break. Script is permitted only by the SHA-256 of the single script block, which is also
  what makes injected markup inert: with a hash present the browser ignores `'unsafe-inline'`,
  so an `onclick` written into the page by hostile data cannot run. Getting there meant
  converting 191 of the file's 192 inline `on*` handlers to `data-click` / `data-change`
  attributes dispatched through one listener against an explicit list of allowed actions. Every
  control does what it did before. The one that remains is the print button written into the
  *downloaded* report, which is a separate document with its own policy. `style-src` is still
  `'unsafe-inline'`: the file sets 483 `style=` attributes, a hundred of them from runtime
  values. CSS cannot execute, and every channel that could send anything anywhere is `'none'`,
  so this is a narrower gap than it reads as — hashing the stylesheet elements is a later step.
- **The hash is a seal, not a checksum.** Any edit to the script block — one byte, including
  whitespace — invalidates it, and the browser then refuses to run the script at all: the page
  loads styled, complete, and completely inert, with the expected hash named in the console.
  That failure is loud on purpose. It is the property that lets an assessor treat the file in
  front of them as the file that was reviewed, and it is why `tools/seal.mjs --verify` runs
  before a release rather than after. What the policy does not cover: downloads, the clipboard,
  and printing are not governed by CSP and are unaffected.
- **The report preview runs sandboxed.** The preview iframe on the Reports tab is sandboxed
  without `allow-scripts`, so nothing in a generated document can execute while you are looking
  at it. **Behaviour change:** the preview no longer carries its own print button, because a
  sandboxed frame cannot run one. Use **Print preview** next to the export buttons; it prints the
  same frame from the parent page. An exported `.html` report opened on its own still prints from
  its own button, and now carries a policy of its own — as do the leadership report and the
  evidence package's `index.html`. All three are the same shape: no script may run in them at
  all, and they may not reach the network.
- **Limits on what will be ingested.** A single input file is capped at 1 GiB and refused before
  it is read rather than after. One inflated zip entry is capped at 256 MiB and a whole archive
  at 768 MiB, checked as the stream decompresses, so a decompression bomb stops at the limit
  instead of at the tab's memory ceiling. Worksheet extraction stops at Excel's own maximum of
  1,048,576 rows, which cannot truncate a legal worksheet. A detection pattern from a profile is
  rejected if it is longer than 512 characters or has the nested-quantifier shape that makes a
  regular expression hang; the check is conservative and is not a general guarantee.
- **A failed load no longer costs you the dataset.** Loading a session, baseline, or profile is
  transactional: the current state is restored if the file turns out to be malformed part-way
  through, instead of leaving a half-loaded dataset on screen.
- **The evidence package no longer includes the session file by default.** The session file is
  the complete raw dataset — every host, IP, software row, and enumerated account with its RID,
  groups, and admin flags — and packages get handed to people the enumerated accounts do not
  belong to. **Behaviour change:** tick *include resume session file in package* on the Reports
  tab to get the 2.7 behaviour. The package index says which of the two it is.
- **`.gitignore` was shipped as `gitignore.txt`,** which git does not read. Every rule in it was
  dead, including the block that exists to keep `*.nessus`, `session*.json`, `*.ckl`, XCCDF XML,
  and `Results_*.zip` out of the repository — so a contributor running `git add .` would have
  committed real scan data to a public repository, and `git status` would not have warned them.
  The file is now named `.gitignore` and the rules are in force. Confirm with
  `git check-ignore -v test.nessus`.
- **18 of 20 built-in product aliases never matched anything.** The `productAliases` patterns
  were written as double-quoted JavaScript string literals holding single backslashes, so
  `"re:^(google[\s-]*)?chrome"` reached `RegExp` as `^(google[s-]*)?chrome` — after `google` it
  would accept only the letter `s` or a hyphen, never a space. `\b` was worse: it resolved to
  U+0008 BACKSPACE, so `(java|jre|jdk)\b` could essentially never match. Every entry using `\s`
  or `\b` was dead — 18 of the 20. The aliases exist to merge the several ways scanners name one
  product (`firefox` from a RHEL check, `Mozilla Firefox` from the Windows plugin), so the
  Software Summary never merged them and a CM-8 software inventory over-counted distinct
  products while the consolidation under-reported — silently, with no error to notice. The
  backslashes are doubled and the intended patterns now compile. The catalog's `osPatterns` and
  the end-of-support table always escaped correctly and are untouched. **Behaviour change:** the
  Software Summary now consolidates product names it previously listed separately, so counts in
  that view drop for environments carrying several scanner spellings of one product. That is the
  corrected number, not a lost one. Scope is contained by design — the remediation plan keys on
  the un-aliased product, so an alias can never claim one patch covers two products that need
  different fixes.
- Fixed: session files were stamped `ver: "2.6"` in a 2.7 build, so every exported session
  misstated the tool version that produced it. The release check now compares all the places the
  version appears and fails if they disagree.
- The file opens with a provenance comment naming the source repository and the manifest that
  carries its hashes. It is still a single file with no build step, no dependency, no network
  call, and no browser storage; sealing is a release step run against the finished file, not a
  step that produces it.

## 2.7 — one report, and one package

Reporting was 29 separate exports of which exactly one was a document a person reads, and
`Export all artifacts` fired 22 downloads into an unordered heap. Both are addressed without
removing a single existing export.

- **Report builder.** The Reports tab now assembles one document from a registry of 20
  sections — scorecard, readiness, scan health, charts, leadership lenses, remediation plan,
  vulnerability rollup, combined POA&M, STIG compliance and coverage, applicability, software
  and asset baselines, PPSM, accounts, unsupported components, reconciliation, trend, control
  mapping, and a per-asset appendix. Every section calls the same pure data function the
  matching tab renders from, so a report cannot disagree with the screen.
- **Audience presets, and your own.** Five ship as starting points — Leadership brief,
  ISSM / assessor package, Engineering work order, Pre-delivery QC, Full record — but a preset
  is only a named list of sections. Tick what you want, **Save these as a preset**, and it
  lands in `settings.reportPresets`, which means it travels in the environment profile your
  team already shares. Reporting the way your organisation reports needs no code change.
- **Sections with no data drop out** of the finished document on their own, so a preset that
  asks for more than you have still reads clean. The builder greys them and says why.
- **Live preview** of the actual document, in the tab, before you export anything.
- **Print stylesheet tuned for PDF.** Each section starts on a fresh page, table headers repeat
  across page breaks, rows and charts never split, and the marking banner is stamped on every
  printed page — verified at 18 of 18 pages on the sample document.
- **Evidence package.** One `.zip` holding the report, every artifact, the session file, and an
  `index.html` front page listing each file with **who it is for**, what it demonstrates, its
  row count and size. Files are filed into `1-report` / `2-registration` / `3-findings` /
  `4-configuration` / `5-evidence-quality` / `6-session`. Written with a minimal ZIP writer over
  the browser's native `CompressionStream` — the mirror of the reader that already ingests
  zipped scan bundles, and still zero dependencies and zero network calls.
- `Export all artifacts` (22 separate downloads) is unchanged and still on the Overview tab.
  Host names stay withheld from the report unless you ask for them, as with the AI package.

## 2.6.1 — interface pass

Presentation only. No engine, parser, export, or detection logic was touched; every control,
export, and setting from 2.6 is still present and does the same thing.

- **Workflow rail.** The eighteen tabs moved from a wrapping two-row tab strip into a left
  sidebar grouped into the four stages the tool actually walks through — Set up, Evidence,
  Sustainment, Deliver — plus Advanced. Settings moved into stage 1 (it is step 2 of the
  documented workflow), and Scan Health leads the Evidence group, since every other artifact
  depends on whether the scan authenticated.
- **One obvious action per tab.** Toolbars that had grown to eleven buttons now show the
  primary export plus grouped dropdowns (More exports / Bring in data / Clean up). The buttons
  inside are unchanged; filters and view toggles moved to the right of the bar.
- **Tab headers.** Every tab opens with its name, a one-line plain-language description of
  what it is for, and a `?` that opens the existing help drawer on that topic.
- **Reference prose folded away.** The multi-paragraph explanations above each table are
  collapsed by default and expand on click. Text is unchanged; parse warnings stay visible.
- Glossary moved into the help drawer, and save/load session into a Session menu, taking the
  top bar from six controls to four.
- Status bar no longer grows to cover the page on a long message; it scrolls instead.

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
