# Palisade — Security Audit of v2.8 and Remediation in v2.9

| | Audited | Delivered |
|---|---|---|
| file | `palisade.html` v2.8 | `palisade.html` v2.9 |
| bytes | 521,771 | 572,143 |
| sha256 | `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` | `84ea3d3299d58bf4f0413d54c97b82772f80d19d460cad146d9815c524a32994` |
| script block | 438,777 bytes, `sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=` | 489,099 bytes, `sha256-rXLlUraYkQK0AWyOdItde6nM7Vp4Okl31uF8o7Q6XsQ=` |
| tooling | `tools/seal.mjs`, `tools/csp-lint.sh`, `baseline/harness.mjs`, `baseline/check-frozen.mjs`, `.github/workflows/verify.yml` | the same, hardened, plus `baseline/security-gate.mjs` |
| date | 2026-10-09 | 2026-10-09 |

This report supersedes, where they conflict, the v2.8 statements in `docs/SECURITY-ASSESSMENT.md`,
`docs/THREAT-MODEL.md`, `docs/MOBILE-CODE-DETERMINATION.md`, `docs/SSDF-MAPPING.md` and
`docs/SBOM.md`. Section 9 lists every statement in those documents that this audit found to be
wrong, and says which were corrected in place.

---

## 1. Summary

v2.8 was a serious hardening release, and much of it held up under attack: no path was found from
any input to script execution in the page or in an exported artifact. The CSP blocks every
injected script, handler attribute, `javascript:` URL, network request and image load. That
negative result covers 242 hypotheses, summarised in §8.

The audit still found real defects in three places the v2.8 package said were covered:

1. **Evidence integrity.** Several paths silently produce wrong evidence from ordinary or
   adversarial input. Examples:
   - A listing that says "Unapproved" is recorded as Approved.
   - A blank-identity checklist drops another host's Open CAT I.
   - A newer SCC run is ignored because the first file loaded wins.
   - Removing Defender from one host is reported as "No changes".
   - A "Microsoft STIG" result marks every applicable STIG as assessed.
   - A software name of `constructor` or a plugin ID of `__proto__` wedges every later ingest.

   For an evidence compiler these weigh the same as a code-execution bug. `SECURITY.md` says so.
2. **Markup injection without script.** The CSP stops script, but it does not stop markup:
   - Raw `protocol` attributes reach the host drawer.
   - Session-file values are interpolated raw at about a dozen renderer sites.
   - Two exported-report cells are unescaped.
   - A bare CR fabricates CSV rows in every export.

   These let a crafted scan or a colleague's session restyle or hide evidence. An injected
   `<meta http-equiv=refresh>` can also navigate the tab away and discard the working set.
3. **The integrity seal and the release chain.**
   - `seal.mjs --verify` passed a file whose policy had been commented out, moved into
     `<noscript>`, or widened with `script-src-elem`. The browser then ran injected code.
   - One NUL byte blinded `csp-lint.sh`.
   - The CI gate could not detect the regression of any v2.8 security fix.
   - The documented CI and attestation have never run.

Totals:

- **144 raw findings** from 20 lanes, which consolidate to **87 distinct issues**: 19 high, 34
  medium, 29 low, 5 informational. §4 lists them all.
- **81 issues are fixed in v2.9**, counting documentation corrections. Three are **partially
  fixed** (E8, E19, F12) and three are **residual** by design or platform limit (D6, E26, F15).
  §7 explains each one.
- Every fix with a behavioural effect is pinned by a check in the new
  `baseline/security-gate.mjs`. That gate runs 52 checks and passes on v2.9. Its first section
  proves the CSP is in force, so a pass cannot come from a page that lost its policy. Against v2.8
  it passes the four policy and start-up checks, then fails at the first prototype-key input with
  `TypeError … at rebuildPPSMFromHosts`, and the suite cannot continue (§10).
- The frozen evidence numbers from the demo dataset are **unchanged** (hosts 6, intel rows 6,
  meter 21 %, PPSM 19, STIG 8, software 24, assets 9). All five error counters are zero.

---

## 2. Scope and method

**In scope:**

- the single file;
- its release tooling;
- the CI workflow;
- the manifests and SBOMs;
- every measurable claim in the accreditor documents.

**Adversaries** are the ones in `docs/THREAT-MODEL.md`:

- a hostile host on the scanned network, which controls hostnames, banners, DisplayNames, account
  names, protocol and service attributes, and plugin output;
- a colleague's crafted or merely legacy JSON: session, baseline, profile, trend, approvals sheet
  or detection config;
- hostile values reaching a spreadsheet on the assessor's networked machine;
- archives and workbooks built to exhaust memory or time;
- anyone between the release and the operator.

**Out of scope**, per `SECURITY.md`:

- browser and OS bugs;
- `style-src 'unsafe-inline'` without a demonstrated impact;
- downloads, the clipboard and printing not being governed by CSP.

**Environment:**

- Linux container with Node 22 and Chromium 141.0.7390.37, headless, driven over the DevTools
  protocol.
- The real `file://` origin.
- `Page.setBypassCSP` never sent.

Before any audit work, the v2.8 file passed all of its own gates in this environment:

- `seal.mjs --verify`;
- `csp-lint.sh`;
- `harness.mjs` plus `check-frozen.mjs`, with the frozen numbers identical;
- `sha256sum -c` and `sha384sum -c`.

**How findings were produced:**

- **Lanes.** The file and tooling were divided into 20 lanes, each owning a territory (line ranges
  and functions) and a lens (the class of defect to hunt). Two of the lanes, L19 (a mechanical
  sweep of every `innerHTML`/attribute sink) and L20 (what the seal does and does not prove), were
  added after a coverage review of the first eighteen.
- **Reproduction.** Every finding was reproduced in the page against the sealed bytes, through
  the same entry points the UI calls: `ingestFiles`, `loadSession`, `loadBaseline`,
  `loadProfile`, `importApprovals`, and the export functions with downloads captured. Inputs were
  synthetic only: RFC 5737 addresses and invented hostnames.
- **Finder reproduction.** 143 of the 144 raw findings were reproduced by their finder. The 144th
  is a documentation-consistency finding with nothing to execute.
- **Independent verification.** Each finding was meant to get three verifiers: one reproducing it
  from scratch, one trying to refute it, and one adjudicating severity. That pass **completed for
  18 findings**: 18 of 18 were independently reproduced, 0 were refuted, and 16 of 16 adjudicated
  were judged real. The remaining verifier runs did not complete within the session's limits.
- **Mechanical re-run.** 70 of the finders' proof-of-concept scripts were re-run against a frozen
  copy of v2.8. 67 completed. The other 3 timed out, and all 3 are the hang findings: the sparse
  xlsx column, quadratic intel multi-values and the quadratic XCCDF parse.
- **Triage and gating.** For every finding not independently verified, the maintainer reading
  during the fix was the triage. Each fix was exercised against the finding's own reproduction, and
  every behavioural fix is now a regression check (§10).

Read the severities in §4 with that in mind. They are this report's adjudication, using the rubric
below, and not an independent panel's.

**Severity rubric** (evidence integrity is weighted like code execution, per `SECURITY.md`):

| | Meaning |
|---|---|
| High | Wrong, missing or forged evidence an accreditor would rely on, markup injection into the app or an export, or a failure of the seal or release chain. Reachable by a threat-model adversary with no operator error. |
| Medium | Loss of the working session from one file (hang, wedge), wrong evidence that needs unusual but legitimate input, or a document claim an accreditor would rely on that is false. |
| Low | Wrong output that is visible or conservative, cosmetic integrity, or a narrow precondition. |
| Info | Correctness of wording or counts, or defence in depth. |

---

### Provenance: how the work was run

This audit and remediation were directed by **Jacob Keith (@Cratioo)** and carried out with
Anthropic Claude models in organised swarms:

- **Finding.** Claude **Mythos** swarms did the vulnerability hunting. These are the "lanes,"
  "finders" and "verifiers" described above.
- **Fixing.** Claude **Opus 5.5** swarms made the v2.9 changes and wrote the regression checks.
- **Scale.** Roughly three swarms in each phase, each run as several waves with critique rounds
  between them. Findings were challenged and re-examined by later waves before they were fixed.

The work was done by **Keith Systems** (Jacob Keith, @Cratioo), a participant in Anthropic's
**Cyber Verification Program** (Defense Access tier), which provides access to Claude Mythos,
Claude Opus 5.5 and Claude Sonnet 5.5 for defensive security use.

This section records who did the work. It does not change the evidence limits stated above: the
independent three-verifier pass completed for 18 findings only, and §7 lists what remains
residual. The model attribution is as reported by the project owner and is not something this
repository can verify from its own contents.

---

## 3. What v2.8 got right (verified, not assumed)

- **No script execution from any input.** Injected `<script>`, `on*=` attributes,
  `javascript:` URLs and string timers are all refused under the shipped policy. The browser
  reports `script-src-elem` and `script-src-attr` violations.
- **No network and no storage.** These are confirmed by static inspection of the bytes and by the
  policy (`default-src`/`connect-src`/`img-src` are `'none'`). The `ping` and `prefetch` attempts
  that were probed were refused.
- **Every scan-derived string in the main renderers is escaped.** The holes were in
  session-derived values and two narrower sinks (§4).
- **The CSV formula neutraliser held** against leading whitespace, a BOM, fullwidth `＝`, signed
  numbers, joined multi-value cells and TSV quote tricks, as rendered by LibreOffice 24.2. The one
  real defect was quoting (bare CR), not neutralisation.
- **XML hardening held.** Internal entity expansion is refused, depth bombs are rejected by the
  parser, and no external entity resolves.
- **The delegated dispatcher could not be steered** by crafted `data-*` attributes.
- **The evidence package's zip writer** produced structurally valid archives with no
  data-derived entry names.

---

## 4. Findings

`ID` is this report's consolidated identifier. `Raw` lists the finder IDs it absorbs, and the
lane prefix gives its origin. `Gate` names the `security-gate.mjs` check that pins the fix, or
"—" where the fix is not behavioural or is covered only by the finder's reproduction.

### 4.1 Markup injection (CSP-proof, script-free)

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| A1 | High | The host drawer writes the port `protocol` raw. A `.nessus` or CSV protocol value injects a page-wide `<style>`, or a `<meta refresh>` that discards the working set on one click. The v2.8 fix only lower-cased the value. | L07-nessus-protocol-host-drawer, L15-proto-drawer-markup, L19-nessus-protocol-host-drawer | Fixed: `addPort` accepts only `[a-z0-9._-]{1,16}` and ports 1–65535; the drawer escapes both | protocol attribute: no markup in the asset drawer |
| A2 | High | Session-file *values* are interpolated raw at about a dozen sites: trend stats via `card()`/`renderTrend`, consolidation `hosts`, listing/intel file counters, intel raw score, `statusPill`, drawer ports. A colleague's session restyles or hides evidence and survives "Session restored". | L19-session-values-raw-into-app-dom, L05-trend-stats-raw-html, L06-card-unescaped-trend-stats, L06-consol-hosts-unescaped-persistent, L07-session-json-raw-sinks, L08-renderTrend-raw-stats-tab-navigation, L18-trend-stats-raw-markup, L03-renderlistings-raw-counts, L04-statuspill-raw-status | Fixed at every site (escape or `numOr`), and values are coerced at the JSON boundary (`normalizeSessionState`) | session values: no markup anywhere in the app |
| A3 | High | The exported report has two unescaped cells (PPSM port, trend first/last). A session-sourced `<meta refresh>` rides into the handed-over HTML. | L08-report-raw-session-cells, L19-exported-report-navigation | Fixed | session values: no markup in the exported report |
| A4 | High | `csvq()` does not quote a bare CR. A hostname or plugin name containing CR fabricates rows in every CSV export (POA&M, STIG, detail, IP summary). | L10-csvq-bare-CR-rowsplit, L13-csvq-bare-cr-row-split | Fixed: quotes on `[",\r\n]` | bare CR in a hostname cannot fabricate a CSV row |
| A5 | Low | The marking banner and the control header are written outside `csvq`/`tsvSafe` in the STIG CSV and the PPSM registry. A profile banner of `=1+1` becomes a live cell. | L10-banner-ctrlheader-raw, L11-banner-bypasses-csvq | Fixed | banner from a profile is neutralised… |
| A6 | Low | Newlines in a host-reported OS string fabricate bullets in the plain-text executive summary. | L09-email-newline-injection | Fixed: `oneLine()` per bullet | — |
| A7 | Info | Session and profile strings reach native `confirm()` text verbatim, newlines included. | L11-dialog-spoof | Fixed: `oneLine()` | — |

### 4.2 Prototype-named keys and the JSON boundary

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| B1 | High | Keys taken from files are used on plain objects. `__proto__` as a plugin ID, plugin name or family pollutes `Object.prototype`. `constructor`/`toString`/`hasOwnProperty` as a software DisplayName, intel product, rule id or catalog column throws mid-ingest, after `S` is mutated, so every later ingest aborts and the saved session is poisoned. `safeParse` guarded JSON keys only, while these keys come from XML and CSV. | L01-pluginid-proto-pollution, L13-proto-pollution-via-scan-strings, L01-swname-prototype-member-dos, L02-prototype-name-software-poisons-ingest, L05-proto-named-software-wedges-ingest, L06-swname-prototype-key-wedge, L03-prototype-named-software-poisons-session, L02-prototype-name-intel-product, L04-poam-prototype-key-crash, L03-constructor-host-key-session, L05-constructor-host-key, L06-stig-column-prototype-name, L11-catalog-name-in-operator | Fixed: every file-keyed map is a null-prototype `dataMap()`, lookups use `ownKey()`, and `pid` is coerced to a string | five checks: `pluginID / DisplayName '__proto__'`, `'constructor'`, ingest completes, later ingest works, session reloads |
| B2 | High | A session with `[]` where a map belongs loads, then *silently loses every edit and every scan host* on Save session, because `JSON.stringify` drops named properties on arrays. | L11-array-shaped-session-maps | Fixed: `normalizeSessionState` coerces every map | array-shaped maps: edits survive Save session |
| B3 | Medium | Session value types are not checked. `sev:"4"` and `cvss:"9.8"` under-count the Critical/High cards and crash the Detail view. A trend stat of `1e999` (Infinity) drives `rptTicks` into a 9 s, 3.9 GiB stall. | L13-session-type-confusion-sev-cvss, L18-trend-infinity-stall | Fixed: types coerced at load; `rptTicks` guards non-finite values and caps at 64 ticks | session values: types coerced (sev, cvss, approval, Infinity) |
| B4 | Medium | Profile and session settings are merged unchecked. A `boundaryDefaults` of the wrong length shifts every PPSM registry column. | L05-profile-settings-unvalidated, L10-ppsm-boundary-column-shift | Fixed: `normalizeSettings`; the registry always writes exactly `BOUNDARY_LABELS.length` cells | PPSM registry rows have exactly as many cells as the header |
| B5 | Low | A profile can silently redefine a built-in report preset, for example "ISSM / assessor package" with 2 of its 14 sections. | L08-profile-shadows-builtin-presets | Fixed: only `u_` keys outside the built-in set are accepted | a profile cannot redefine a built-in report preset |
| B6 | Low | A re-saved session inherits `meta.tool`/`meta.ver` from the file it was loaded from. | L05-session-meta-inherited | Fixed | a re-saved session states what produced it |
| B7 | Low | `saveProfile` serialises catalog `active` flags that scan evidence switched on, so a "no scan data" profile reveals which products the enclave runs. | L05-profile-carries-scan-derived-flags | Fixed: scan-activated columns are marked `autoActive` and stripped | environment profile does not record scan-activated columns |
| B8 | Info | Rejected `re:` patterns arriving in a *session* were only `console.warn`ed. | L12-session-rejection-not-reported | Fixed: reported in the status line | — |

### 4.3 Transactional loads and caches

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| C1 | High | `loadBaseline` replaces `S` and never restores it on a throw. The foreign file becomes the working set while the screen still shows the old one, and exports come from the foreign data. | L05-baseline-not-transactional, L07-loadBaseline-no-rollback, L18-baseline-load-not-transactional | Fixed: try/finally rollback | bad / legacy baseline never replaces the working dataset |
| C2 | Medium | The raw-snapshot branch stores an unvalidated object, and a 40-byte file breaks every later `renderAll`. | L05-baseline-snapshot-unvalidated, L18-raw-baseline-poisons-renderall | Fixed: `validSnapshot()` | malformed raw snapshot is refused, not stored |
| C3 | High | After "previous dataset restored", the threat-intel fusion cache from the *rejected* file is still served. The Threat Intel tab, Overview, readiness and the evidence package show the foreign data. | L05-fusion-cache-survives-rollback, L07-fusion-cache-survives-rollback | Fixed: the cache is bound to its state object and invalidated on every load and rollback | fusion cache is bound to its state object |
| C4 | Medium | `applyConfig` runs detection outside its try, and `migrateConfig` never backfills `deviceRules`. A config missing a key wedges the next ingest with no feedback. | L05-applyconfig-outside-try, L12-applyConfig-not-transactional | Fixed: transactional with rollback; `migrateConfig` backfills and filters | applyConfig: hostile config normalised or rolled back |
| C5 | Low | `_remedyCache` was never invalidated, so alias changes did not reach the remediation views. | L13-remedycache-stale-aliases | Fixed | — |
| C6 | Low | `clearAll()` leaves the inventory and e-mail textareas filled, and the stale inventory is applied to the next enclave. | L11-clearAll-dom-residue | Fixed | — |

### 4.4 Resource exhaustion from a file

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| D1 | Medium | One xlsx cell `r="MWLQKWU1"` makes every row loop walk 4.29 billion slots, so a 1.6 KB workbook hangs the tab. | L02-sparse-column-index-hang | Fixed: columns past XFD (16,384) are refused | xlsx: a column beyond XFD is refused, quickly |
| D2 | Medium | Stored and aliased central-directory entries bypass the per-archive cap: a 5.3 MB zip parses one XCCDF 65,535 times. | L02-stored-alias-entries-bypass-archive-cap | Fixed: entry cap, duplicate data offsets refused, local-header and name check, stored bytes counted | zip: two directory entries aliasing one data region are refused |
| D3 | Medium | Built-in parser regexes are super-linear on host-controlled lines: `parseSwLine`, `cleanProductName`, the account, plugin-19506 and logon parsers. A 10–20 KB line hangs the tab. | L01-parseswline-redos, L12-builtin-redos-parseSwLine, L13-cleanproductname-quadratic-redos, L14-redos-hardcoded-parse-regexes | Fixed: line-length bounds plus a linear rewrite of the bracket walk | ReDoS: built-in parsers finish under 4 s each |
| D4 | Medium | `unsafeRegexSource()` misses trivial re-spellings such as `(?:(.+))+$`. | L12-validator-bypass-nested-quantifier | Fixed: depth-aware group-stack scan; all 32 built-ins still accepted | regex validator rejects… / accepts every built-in |
| D5 | Medium | Quadratic algorithms: intel multi-value `includes` (49 s for one CVE × 50k rows), `applyListings` (28 s for 8k rows), XCCDF TestResults × Benchmark traversals, and `productExposure` (a minute per render). | L02-quadratic-multivalue-includes, L03-quadratic-applyListings, L04-xccdf-quadratic-hang, L09-productExposure-quadratic | Fixed: set-based dedupe, serial/base indexes, per-Benchmark metadata cache, CVE inverse index | — |
| D6 | Medium | The inflate caps bound bytes, not memory. A 34 KB xlsx that inflates to 32 MiB drives the renderer to 5.4 GB once the DOM is built. | L02-dom-memory-under-inflate-cap | **Residual** (§7); decode is now streaming, removing one copy | — |

### 4.5 Evidence integrity: ingest and identity

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| E1 | High | Every checklist with a blank asset identity lands on one host, `UNKNOWN`. The second host's rules are dropped, so an Open CAT I disappears. | L04-blank-asset-collision-unknown | Fixed: `UNIDENTIFIED-<FILE>` placeholders, with a warning | blank-identity checklists are kept apart |
| E2 | High | Re-ingesting a newer SCC run or an updated checklist is ignored, because the first writer wins. | L04-first-writer-wins-stale-results | Fixed: `mergeRule()` takes the newer result by its own date; a checklist (human decision) is never overridden by SCC | XCCDF: the newer result wins regardless of drop order |
| E3 | Medium | SCC and the assessor's checklist for the same rule count twice. | L04-xccdf-ckl-double-count | Fixed: rule identity is the SV stem | SCC + checklist for the same rule count once… |
| E4 | Medium | The XCCDF path reported the retired legacy V-ID. Separately, `\b` never matched inside `…_group_V-…` or `…_rule_SV-…` (the `_` is a word character), so DISA ids yielded no V-ID at all. | L04-legacy-vid-attribution | Fixed: V-ID taken from the Group, legacy idents ignored, boundary fixed | XCCDF: current V-ID from the Group |
| E5 | High | Coverage reconciliation counts a result whose title normalises to empty or one generic word ("Microsoft STIG", "Benchmark") as covering every applicable STIG. | L04-coverage-substring-fooled, L18-stig-coverage-empty-normalised-title | Fixed: token containment with a non-empty requirement | coverage: an empty or generic result title covers nothing |
| E6 | High | A checklist with a blank host and a scanned host's IP is orphaned by the IP fold: the real host shows "not assessed". A checklist naming a *new* host with another machine's IP absorbs that scan host. | L04-ip-only-checklist-orphaned, L04-xccdf-ip-claims-absorb-host | Fixed: checklist-supplied IPs are never merge targets; STIG results migrate with the fold | — (covered with E7) |
| E7 | Medium | The IP fold drops finding metadata (patch dates, ports, solution), accounts and scan info, and leaves a ghost asset marked "Scan Detected". | L01-ipfold-drops-meta, L01-ipfold-ghost-asset, L03-phantom-scan-asset-after-ip-merge | Fixed | IP-fold keeps finding metadata and leaves no phantom asset |
| E8 | High | A hostile host claiming a legitimate host's short name is merged into it unaudited. It overwrites the IP and can flip the victim's Administrator to disabled in the account audit. | L01-name-collision-unaudited, L14-netbios-merge-flips-flags | **Partially fixed**: Ingest integrity now raises an "IP mismatch" conflict. Name-keyed identity is by design (§7) | Ingest integrity flags two IPs under one host key |
| E9 | High | Listing approval words "Unapproved", "Disapproved", "Not Authorized", "Never approved" and "Non-approved" are recorded as **Approved**. | L03-approval-negation-inverted | Fixed: negations first, anchored positives, unknown wording becomes a conflict and is left Not Reviewed | listing approval wording… |
| E10 | High | A hardware listing whose identity column is "Device", "Host" or "Asset" is parsed as a Tenable CSV, so every row becomes a scan-detected host. | L03-listing-minted-as-scan-hosts | Fixed: a Tenable CSV must carry a plugin column | listing with no hostname column is not minted as scan hosts |
| E11 | High | Account enumeration drops any name with a legal Windows character outside `[\w.$@ .-]`, including a renamed built-in Administrator such as `O'BRIEN` or `ADMIN (MAINT)`. | L14-acct-names-dropped | Fixed: only control and markup characters are refused | accounts with legal Windows characters are kept |
| E12 | Medium | A Tenable CSV never parses plugin 19506 or auth-failure plugins and records no provenance, so an uncredentialed CSV dataset passes scan health. Credentialed status was also "last file dropped wins". | L14-csv-scan-health-blind, L14-cred-status-drop-order | Fixed: 19506 and auth-failure handled for CSV; newest scan start wins | — |
| E13 | Medium | A Tenable CSV whose plugin output contains `<TestResult` is routed to the XCCDF parser and refused. | L04-csv-sniff-misroute | Fixed: extension decides before content | — |
| E14 | Medium | `parseInventory` splits IPs on `.`, so the tool's own Seed → Apply round trip reports every IP-keyed host twice. | L03-inventory-ip-split | Fixed | inventory keeps dotted IPs whole |
| E15 | Medium | `clearListings()` leaves listing-filled values in place as provenance "scan", and deletes edited listing-only assets despite promising "your edits stay". | L03-clear-reload-keeps-stale-listing-values, L03-clearlistings-destroys-edits | Fixed | — |
| E16 | Medium | MAC and location disagreements between a listing and a scan are never flagged. In listing-first order the listing MAC wins. | L03-mac-silent-precedence | Fixed: conflict raised; the scan MAC wins | — |
| E17 | Medium | Host-chosen DisplayNames remove software from the inventory: "KB…" names are dropped, and a line "The following updates…" drops the rest of the list. | L12-silent-software-drop-sentinels | Fixed: sentinel only in header shape; KB drop limited to update-shaped lines | — |
| E18 | Medium | Only the first 8 worksheets were read, with no warning. | L02-silent-drop-after-8-sheets | Fixed: 64 sheets, with a warning beyond that | — |
| E19 | Medium | One hostile DisplayName that strings every product together takes over the attribution of every weaponized CVE in the leadership lenses. | L09-product-grouping-hijack | **Partially fixed**: the shortest inventory name wins and the weaponized flag is per CVE. Substring matching in the intel index remains (§7) | — |
| E20 | Low | Two hostname columns are joined into a phantom key. Serial-less hardware rows that differ only by IP, MAC or location are deduplicated away. | L03-duplicate-identity-headers-wrong-key, L03-dedupe-drops-distinct-rows | Fixed: first value plus a warning; the dedupe key includes IP, MAC and location | — |
| E21 | Low | A truncated Tenable CSV is half-ingested and reported as a whole-file failure. A `.cklb` with one malformed rule is half-ingested and reported as failed. | L01-csv-short-row-partial, L04-cklb-partial-ingest | Fixed: the short row is skipped with a warning; malformed `.cklb` entries are skipped with a warning | — |
| E22 | Low | A name beginning with `.` yields the empty host key. | L01-empty-hostkey | Fixed: first non-empty label, else the IP | empty host key cannot be minted from '.name' |
| E23 | Low | Future or malformed last-logon dates pass through the `YYYY/MM/DD` fallback. | L14-future-logon-fallback | Fixed | future last-logon dates are rejected |
| E24 | Low | Shared-string phonetic runs (`<rPh>`) are concatenated into cell text. | L02-sharedstrings-phonetic-runs | Fixed | — |
| E25 | Low | `vulnBySubnet` labels IPv6 addresses and hostnames as `/24` networks. | L13-subnet-bucket-mislabel | Fixed | — |
| E26 | Low | Accounts are keyed per host by upper-cased name, so a domain principal and a local account of the same name merge. | L14-same-name-principals-merged | **Residual** (§7) | — |

### 4.6 Evidence integrity: analysis, change record, readiness, reporting

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| F1 | High | Security tooling removed from *one* host, or moved between hosts, is not a change: "No changes detected against baseline". | L18-delta-per-host-removal-invisible | Fixed: per-host set diff; a security-tool loss is critical | delta: security tooling removed from ONE host is critical |
| F2 | Medium | A different machine answering to a baseline host name is invisible to the change record and the identity check. | L18-delta-host-identity-ignored | Fixed: MAC/OS-family changes are critical, an IP change is for review | — |
| F3 | Low | A routine security-tool upgrade is recorded as CRITICAL "removed from the enclave". | L18-sectool-version-bump-false-critical | Fixed: "Software version changed" (review) | delta: a security-tool version upgrade is not 'removed…' |
| F4 | Medium | Readiness passes when the evidence is absent: credentialed checks with no 19506 record or with an auth-failure, the remediation window with undated findings, and credentialed software from empty output. | L18-readiness-absence-as-pass, L14-gate-ignores-authissue | Fixed | readiness: a host with no scan record does not pass the credential check |
| F5 | Medium | A foreign session whose newest scan date equals a recorded cycle overwrites that cycle, and a future date becomes "now". | L18-trend-history-rewrite | Fixed: never overwrites; future dates rejected | — |
| F6 | Medium | A KB number cited in two unrelated solution texts merges the findings into one "Install KB" action with high confidence, hiding a Critical. | L13-kb-in-solution-overmerge | Fixed: solution-only KBs are keyed with the product, at medium confidence | KB cited only in solution text does not merge different products |
| F7 | Medium | `cmpVersion()` orders alphanumeric segments lexically (8u45 > 8u411), so the plan recommends the lower fix target. | L13-cmpversion-lexical-misorder | Fixed: digit and letter runs tokenised | version ordering… |
| F8 | Medium | The leadership report embeds every host name in `title=` attributes, although its own footer says host-level detail stays in the session. | L09-leadership-title-hostnames | Fixed | leadership report carries no host names |
| F9 | Low | A non-canonical approval status ("Authorized") is stored verbatim and counted as reviewed while the UI shows Not Reviewed. Names neutralised with an apostrophe cannot round-trip. | L05-approval-status-freeform, L06-approval-select-misrenders-noncanonical, L10-approvals-roundtrip-neutralised-name | Fixed: only canonical statuses; the apostrophe is stripped on import | approvals import: unknown status not applied / 'Authorized' is refused |
| F10 | Low | A shared profile whose noise pattern is a bare space hides every software row and turns readiness green. | L18-profile-noise-blanks-readiness | Fixed: patterns must be at least 3 characters after trimming | — |
| F11 | Low | On a scan-only dataset, the leadership artifacts assert "0 weaponized … confirmed". P1 CVEs are labelled as weaponized groups. | L09-scan-only-weaponized-zero, L09-p1-unit-mislabel | Fixed: the tile shows "n/a" without intel; units corrected | — |
| F12 | Low | Windows 10 IoT Enterprise LTSC 2019/2021 is reported unsupported from 2025-10-14. | L12-eol-table-false-expired | **Partially fixed**: IoT LTSC rows added. Matching is still a first-substring match over name and version (§7) | — |
| F13 | Low | Scan Health shows "undefinedd oldest plugin feed" when no host reports a feed. | L14-undefinedd-feed-card | Fixed | — |
| F14 | Info | The evidence-package index counts newlines, not CSV records. | L10-pkgindex-rows-counts-newlines | Fixed: `csvRows` | — |
| F15 | Info | The exported report's `'unsafe-hashes'` allowance is reachable by injected markup, but only `window.print()` can run. | L08-unsafe-hashes-reachable-by-injected-markup | **Residual**, accepted (§7) | — |

### 4.7 Seal, tooling and release chain

| ID | Sev | Issue | Raw | Status | Gate |
|---|---|---|---|---|---|
| G1 | High | `seal.mjs` verifies a policy string the browser never enforces. A meta tag that is commented out, wrapped in `<noscript>`, or placed after `<title>` or in the body still passes, and so do both documented hand recipes. With the policy neutralised and the script byte-identical, an added `<script>` runs. | L16-csp-verified-but-not-enforced, L20-seal-bypass-policy-neutralised | Fixed in the tool (see below). The inherent limit is stated in §7 | policy: exactly one CSP `<meta>`, inside `<head>`; enforced (string timer refused) |
| G2 | High | `seal.mjs` checks `script-src` and five directives by substring. `script-src-elem`/`-attr` (which override `script-src`), `connect-src 'none' *`, a duplicate weaker `default-src` or a widened `img-src` all passed. | L16-script-src-elem-attr-unchecked, L20-csp-directive-check-bypass | Fixed: the whole policy must equal the canonical 13 directives, and only the digest list varies | policy: default/connect/img/object/frame/base/form all 'none' |
| G3 | Medium | One NUL byte makes GNU grep treat the file as binary, so every `csp-lint.sh` counter reads 0 and the lint passes. | L16-csplint-nul-blinds-ratchet | Fixed: `grep -a`, a UTF-8 locale, NUL refused, and a read-sanity canary; `seal.mjs` refuses NUL and invalid UTF-8 | — |
| G4 | Medium | The committed gate asserts eight demo numbers and four counters. Every v2.8 security fix could be reverted with CI green, and the browser's own security log was ignored. | L16-gate-no-security-regression-coverage, L20-gate-ignores-browser-security-errors | Fixed: `baseline/security-gate.mjs` (52 checks, wired into CI); `check-frozen.mjs` adds error-level browser log entries | the whole gate |
| G5 | Medium | 15.9 % of the file, the static markup, is outside the CSP hash and holds the CUI opt-ins (`#pkgInclSession`, `#aiInclHosts`, `#rptHosts`) and `#rptCap`. Pre-ticking one silently ships the full session in every evidence package. | L20-static-body-defaults-unsealed | Fixed: the sealed script resets those controls at start-up; `MANIFEST.json` carries a separate digest of the markup outside the script | static body: CUI opt-ins unchecked at load |
| G6 | Medium | The `.gitignore` CUI block did not cover the evidence package `.zip`, the HTML report families, the AI digest or the compliance profile. | L16-gitignore-package-and-reports | Fixed | — |
| G7 | Medium | The release job uses `--clobber`, so a re-run silently replaces attested assets. The attestation did not cover `SHA256SUMS`, `MANIFEST.json` or the verification tools. Action references are mutable tags. | L16-release-clobber-mutable-pins | Fixed: an existing release fails the job, and all of those files are attested. **Residual**: action SHA pinning (§7) | — |
| G8 | Low | `seal.mjs` byte hygiene missed NUL and the script-data escaped states (`<!--` or `<script` inside the block), so `--seal` could write a hash the browser rejects. | L16-seal-reseal-divergence | Fixed | — |
| G9 | Low | With the head policy absent, `seal.mjs` matched the exported report's policy literal *inside the script* and reported a bogus mismatch. | L20-seal-misdiagnoses-missing-policy | Fixed: structure is read from the markup only, and the missing policy is named | — |

What the hardened `seal.mjs --verify` now enforces (each case tested by mutation; all fail, and a
legitimate edit plus `--seal` still passes and runs clean in Chromium):

- **One script, read the way the browser reads it.**
  - HTML comments are blanked before structure is read; an unterminated comment is refused.
  - There is exactly one `<script>`, matched case-insensitively, with no attributes.
  - The script body contains no `<!--`, `<script` or `</script`.
- **One policy, where the parser will honour it.**
  - Exactly one CSP `<meta>` appears outside comments and script.
  - No report-only policy is present.
  - Only `<!DOCTYPE html>`, `<html>`, `<head>` and plain `<meta>` tags may precede the policy.
- **The canonical policy.** It must have exactly the canonical 13 directives with no duplicates.
- **Clean bytes.** NUL bytes and invalid UTF-8 are refused, as before with CR and BOM.
- **Wider offline invariants.** `EventSource` and `new Image` are added to the invariant list,
  because the documents claim zero of each.

### 4.8 Documentation (accreditor-facing claims)

| ID | Sev | Issue | Raw | Status |
|---|---|---|---|---|
| H1 | Medium | README, SECURITY-ASSESSMENT and SBOM.md say the verify workflow runs on every push and that a release tag attests the bytes. The repository has 0 workflow runs, 0 tags and 0 releases (checked 2026-10-09), so `gh attestation verify` cannot succeed. | L17-ci-attestation-never-ran | Corrected in place (README, SBOM.md, SECURITY-ASSESSMENT) |
| H2 | Medium | Several sentences present the script hash as tamper evidence against someone who can edit the file. That person can re-seal, or neutralise the policy and leave the script untouched. The control for a copy is the out-of-band digest. | L20-docs-overclaims-tamper-evidence | Corrected in SECURITY.md, CONTRIBUTING, THREAT-MODEL §6.9 and MOBILE-CODE; noted in SSDF |
| H3 | Low | The CSP is described as refusing everything "before a packet exists" and as leaving no URL or CSS context. Navigation (`<meta refresh>`, a clicked link) and speculative connections (`dns-prefetch`, `preconnect`) are not governed by CSP in Chromium. | L15-csp-noncoverage-docs | Corrected in SECURITY-ASSESSMENT §4 |
| H4 | Low | "All twenty report builders are verified escaped" was false: two cells were raw (A3), and the review had considered session *keys*, not *values*. | L08-docs-claim-all-builders-escaped, L19-docs-escaping-claims | Corrected in SECURITY-ASSESSMENT §8/§9 and THREAT-MODEL §7.5 |
| H5 | Low | THREAT-MODEL §6.9 says to compare the console's script hash against `SHA256SUMS`. That file holds whole-file hex digests; the script hash is in `MANIFEST.json`. | L20-docs-sha256sums-wrong-file | Corrected |
| H6 | Low | THREAT-MODEL, SSDF, SECURITY.md and CHANGELOG say 483 `style=` attributes and call the in-file "481" stale. 481 is the attribute count: the other two `style=` hits are the comment itself and one escaped-quote string. | L17-style-count-contradiction | Corrected (CHANGELOG 2.8 left as history; see §9) |
| H7 | Low | README says the end-of-support table is editable JSON in Detection Config. It is the hard-coded `EOL_TABLE`. | L17-eol-table-not-configurable, L09-readme-eol-table-not-config | Corrected |
| H8 | Low | SSDF PO.1.2 credits `csp-lint.sh` with the network/storage checks, which live in `seal.mjs`. | L17-ssdf-tool-misattribution | Corrected |
| H9 | Low | 32 repository-looking evidence paths cited about 90 times (`evidence/…`, `baseline/verify-B.mjs`, `HARDENING-LEDGER.md`, `tools/sbom-check.py`) do not exist in the repository. Several SSDF "Met" verdicts rest only on them. | L17-phantom-evidence-paths | Noted at the top of SSDF-MAPPING and SECURITY-ASSESSMENT. Not regraded here: the verdicts belong to the document's authors |
| H10 | Info | Count nits: 32 export functions, not 31; the seventh `safeParse` site is the `.cklb` parse; 26 `csvq` uses. The mechanism is misworded: an injected `on*=` is dead because `script-src` carries neither `'unsafe-inline'` nor `'unsafe-hashes'`, not because "a hash makes unsafe-inline ignored". | L17-count-nits, L17-unsafe-inline-mechanism-wording | Mechanism wording corrected in README, CONTRIBUTING and SECURITY-ASSESSMENT; counts listed in §9 |

**Totals by consolidated issue:**

- High 19: A1–A4, B1, B2, C1, C3, E1, E2, E5, E6, E8, E9, E10, E11, F1, G1, G2.
- Medium 34.
- Low 29.
- Info 5.

87 in all.

---

## 5. Behaviour changes in v2.9 an operator will notice

1. **CUI opt-ins are always off at start-up.** "Include session in package", "Include host names"
   (AI package) and "Include host names" (report) start unticked, whatever the markup says. The
   report row cap starts at 40.
2. **Newer results replace older ones.** For STIG results, the newer SCC or XCCDF run wins by its
   own date. A checklist result is never overridden by SCC. Re-dropping an older file after a newer
   one changes nothing.
3. **Blank-identity checklists are no longer merged.** They appear as `UNIDENTIFIED-<FILE>`
   hosts with a warning.
4. **Listing approval wording is stricter.** Negations are Denied, and unrecognised wording is
   left Not Reviewed and listed as a conflict.
5. **A CSV without a plugin column is not a scan.** It is refused with a warning instead of
   becoming scan hosts.
6. **The change record is per host.** Security tooling lost from any single host is critical.
   A version change is "review", not "removed". A changed MAC or OS family is critical.
7. **Readiness fails on missing evidence.** No 19506 record, an auth failure, or undated findings
   now fail the corresponding check instead of passing it.
8. **Approvals import accepts only canonical statuses.** Others are counted in the status line
   and not applied.
9. **Profiles cannot redefine built-in report presets** and no longer carry scan-activated
   catalog columns.
10. **Session files are normalised on load.** Maps, value types and statuses are coerced.
    Rejected `re:` patterns are reported in the status line.

None of these changes the demo dataset's numbers. `check-frozen.mjs` is unchanged against
`baseline/FROZEN-BASELINE.txt`.

---

## 6. Verification performed on v2.9

| Check | Result |
|---|---|
| `node tools/seal.mjs palisade.html --verify` (hardened) | PASS: canonical policy, policy in `<head>`, one script, digest matches, v2.9 at all 4 version sites |
| `bash tools/csp-lint.sh palisade.html` (hardened) | PASS: handlers 1 (export-only), all other counters 0, script tags 1 |
| `node baseline/harness.mjs` + `check-frozen.mjs` | PASS: hosts 6, intel 6, listings 1, meter 21 %, ppsm 19, stig 8, sw 24, asset 9; 0 console / CDP / page / CSP / log errors |
| `node baseline/security-gate.mjs` | PASS: 52 of 52 |
| seal mutation set (comment, `<noscript>`, `<title>` first, `script-src-elem`, duplicate `default-src`, widened `img-src`, `<SCRIPT>` block, NUL, report-only) | every mutation FAILS `--verify`; the clean copy PASSES; `--seal` after a legitimate script edit PASSES and loads with 0 CSP violations |
| `sha256sum -c SHA256SUMS`, `sha384sum -c SHA384SUMS` | OK for every listed file (regenerated for v2.9) |

---

## 7. Residual risk (not fixed, and why)

1. **The seal cannot stop someone who can write the file.** The hardened `seal.mjs` refuses a
   neutralised or widened policy, but an attacker with write access does not run `seal.mjs`.
   They can also edit the markup outside the script, which the hash does not cover. **The control
   for a copy is its whole-file digest, compared against a value taken from the project's
   repository, never from the copy.** The in-browser check (an edited script loads inert) protects
   against accidental corruption and careless edits only. The documents now say so.
2. **Name-keyed host identity (E8).** Hosts are keyed by name because that is how the evidence is
   addressed. A hostile host that claims a victim's name is still merged into it. v2.9 surfaces the
   collision ("IP mismatch" in Ingest integrity) instead of hiding it, and the operator must review
   it.
3. **Memory, not bytes (D6).** The inflate caps bound decompressed bytes. A small file can still
   inflate to a few tens of MiB of XML whose DOM costs gigabytes. Bounding DOM memory needs a
   streaming parser, which is out of proportion for a single-file tool. The tab can be exhausted;
   no evidence is changed.
4. **Same-name principals (E26).** A domain account and a local account with the same name on one
   host merge into one row. Splitting them needs the scanner to report the authority consistently,
   and it does not.
5. **Product attribution by substring (E19).** The intel index still matches inventory names to
   intel products by containment. v2.9 removes the first-match takeover, but a hostile DisplayName
   can still collect intel matches in the Software tab's intel column. Anchored matching would drop
   legitimate matches ("Chrome" vs "Google Chrome") and is left for a design change.
6. **EOL matching (F12).** This is a first-substring match over name and version. The known false
   "unsupported" rows are fixed, and the error direction is conservative.
7. **Platform limits on the policy.**
   - `style-src 'unsafe-inline'` remains: CSS cannot execute, but it can change what the operator
     sees, which is why every sink escapes.
   - Navigation (`<meta refresh>`, links) and speculative connections (`dns-prefetch`,
     `preconnect`) are not governed by CSP in Chromium. The control is that no attacker text
     reaches markup, now enforced at every sink found.
   - The exported report's `'unsafe-hashes'` admits only its own print button. Injected markup can
     call `window.print()` and nothing else.
8. **Release chain.**
   - The workflow's actions are referenced by tag, not commit SHA. No verified SHAs were available
     offline, and pinning to unverified values would be worse than the tag.
   - The workflow has never run. Until it does, no attestation exists, and the digests in
     `SHA256SUMS`, checked against the repository, are the evidence.

---

## 8. Hypotheses tested and refuted

242 attack hypotheses were tested and found not to hold. These are the results an accreditor
is most likely to ask about:

- **Hostnames, account names and listing hosts as `__proto__`/`constructor`.** Refuted.
  `hostKeyFrom` and `acctGet` upper-case every key (`__PROTO__`), and PPSM and software keys always
  contain `/` or `|`. The prototype path was through *other* keys (§4.2 B1).
- **XML entity expansion, depth bombs and external entities.** Refuted. Internal expansion is
  refused by Chromium's parser, depth 10,000 is a parse error, and no external entity resolves.
- **Zip entry named `__proto__`, malformed offsets and sizes, duplicate names.** Refuted. Each
  yields a clean parse warning. (Aliased *data* regions were real: D2.)
- **Formula injection through the neutraliser.** Leading whitespace, BOM, fullwidth `＝`, TAB/LF
  prefixes, signed-number exemption, joined cells and TSV quote tricks were all rendered inert by
  LibreOffice 24.2. (Bare CR was real, but as a quoting defect: A4.)
- **Download-filename injection.** Refuted. Every name is a fixed template plus a sanitised token.
- **The report preview frame navigating or altering the parent.** Refuted for the `srcdoc` frame.
  The parent was reachable only through the in-app Trend renderer (A2).
- **Injected handlers running under the exported report's `'unsafe-hashes'`.** Refuted. An
  arbitrary handler body is refused (`script-src-attr`); only the hashed `window.print()` matches.
- **The AI package or the e-mail summary leaking host names.** Refuted for the default settings
  (0 of 14 identifiers). The leadership HTML `title=` leak was real: F8.
- **Status normalisation gamed so that Open reads as Not a Finding.** Refuted.
- **The dispatcher steered by crafted `data-*` attributes.** Refuted across 26 injected
  elements, and `auditUIActions()` reports no dead controls.
- **Session type confusion corrupting state silently.** Mostly refuted, because `'use strict'`
  throws inside the transactional `loadSession`. The exceptions were the ones that *don't* throw:
  B2 and B3.

The full list, with the reason each failed, is kept with the audit working papers. It is not
distributed, because it embeds probe scripts.

---

## 9. Errata to the v2.8 accreditor package

| Where | v2.8 says | Measured | v2.9 |
|---|---|---|---|
| README "For accreditors"; SECURITY-ASSESSMENT §11.7; SBOM.md | The verify workflow runs on every push and tag; a release tag attests the bytes | 0 runs, 0 tags, 0 releases | Corrected in place |
| README; CONTRIBUTING; SECURITY-ASSESSMENT §4; THREAT-MODEL §6.2; CHANGELOG 2.8 | "a hash makes `'unsafe-inline'` be ignored for script — which is what kills every injected `on*`" | The policy has no `'unsafe-inline'` to ignore; handlers are dead because neither `'unsafe-inline'` nor `'unsafe-hashes'` is present | Corrected in README, CONTRIBUTING and SECURITY-ASSESSMENT; noted here for THREAT-MODEL and CHANGELOG |
| README | The end-of-support table is editable JSON | Hard-coded `EOL_TABLE` | Corrected |
| SECURITY.md (scope and verification); THREAT-MODEL §6.9; MOBILE-CODE §2; SSDF PS.2.1; CHANGELOG 2.8; CONTRIBUTING | The seal makes a tampered copy visible or inert; "two independent checks" | Only for edits that leave the policy intact; anyone who can write the file can re-seal or neutralise it | Corrected in SECURITY.md, CONTRIBUTING, THREAT-MODEL §6.9 and MOBILE-CODE; noted here for SSDF and CHANGELOG |
| THREAT-MODEL §6.9 | Compare the console hash against `SHA256SUMS` | It is in `MANIFEST.json` → `inlineScriptBlocks[0].sha256` | Corrected |
| THREAT-MODEL §7.1; SSDF PW.9.2 and gap note; SECURITY.md; CHANGELOG 2.8 | 483 `style=` attributes; the in-file "481" is stale | 481 `style="` attributes (the other two `style=` hits are the CSP comment itself and one escaped-quote string) | Corrected except CHANGELOG 2.8 (history) |
| SECURITY-ASSESSMENT §8, §9.5; THREAT-MODEL §7.5 | All twenty report builders verified escaped | Two cells raw (PPSM port, trend); session *values* not reviewed | Corrected |
| SECURITY-ASSESSMENT §4 | Every request refused "before a packet exists"; no attacker data reaches a URL or CSS context | Speculative connections and navigation are not governed; the drawer sink reached URL and CSS contexts | Corrected |
| SECURITY-ASSESSMENT §1 | 31 export functions | 32 (`async function exportPackage`) | Noted here |
| SECURITY-ASSESSMENT §5.2 | The seventh `safeParse` site is "approvals import" | It is the `.cklb` parse; `importApprovals` parses CSV | Noted here |
| SECURITY-ASSESSMENT §5.3 | `csvq` has 27 uses | 26 uses, 1 comment, 1 definition | Noted here |
| SECURITY-ASSESSMENT §9.6, §5.8, §5.1; THREAT-MODEL §3.1; SSDF (many rows) | Re-run `baseline/verify-B.mjs` (one command); `evidence/…`, `HARDENING-LEDGER.md`, `tools/sbom-check.py` | None of these is in the repository | Flagged at the top of each document |
| SSDF PO.1.2 | `csp-lint.sh` counts network and storage primitives | Those checks are in `seal.mjs` | Corrected |
| SSDF PW.9.1 / PW.9.2 | 7,600 lines; three behaviour changes | 7,957 lines (v2.8); four | Noted here |
| THREAT-MODEL diagram | `checkFileSize() 1801` | 1803 (1801 is the comment) | Noted here |
| `palisade.html` line 2 | "release tag and SHA-256 manifest in SHA256SUMS" | No tag exists; the manifest is `MANIFEST.json` | Corrected (outside the script; the hash is unaffected) |

---

## 10. Reproducing this audit's results

```sh
# 1. digests first -- take the expected values from the repository, not from the copy
sha256sum -c SHA256SUMS
sha384sum -c SHA384SUMS

# 2. the seal, read the way the browser reads it
node tools/seal.mjs palisade.html --verify
bash tools/csp-lint.sh palisade.html

# 3. the page in a real browser from a real file:// URL (Node 22+, any Chromium)
CHROMIUM=/path/to/chromium node baseline/harness.mjs "file://$PWD/palisade.html" ./gate
node baseline/check-frozen.mjs ./gate/result.json baseline/FROZEN-BASELINE.txt

# 4. the hostile-input regression gate: one check per fixed finding
CHROMIUM=/path/to/chromium node baseline/security-gate.mjs "file://$PWD/palisade.html" ./gate
```

**Negative control.** Run the same gate against the v2.8 file (sha256 `fd2f80e9…`). It passes
the four checks before the first hostile input: the policy is present, canonical and enforced,
and the shipped markup leaves the opt-ins unticked. The v2.8 policy was sound. It then stops at
the first prototype-key input with `TypeError: Cannot read properties of undefined (reading
'includes') at rebuildPPSMFromHosts`, which is finding B1. The polluted page cannot run the rest
of the suite. The gate is therefore not a per-finding matrix against v2.8. That evidence is each
finding's own reproduction (§2). What the gate does show is the regression direction: undo any
v2.9 fix and at least one named check fails.
