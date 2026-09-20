# Palisade 2.8 — NIST SP 800-218 v1.1 (SSDF) practice map

## Read this first: what this document is, and what it is not

**No CISA Secure Software Development Attestation Form has been filed for Palisade, and none is
required.** Under OMB M-22-18 as updated by OMB M-23-16, the self-attestation requirement reaches
third-party software an agency *procures*. Software an agency obtains freely and directly —
which includes open-source software the agency downloads itself — is outside that requirement.
Palisade is MIT-licensed and freely obtained. If an agency instead receives Palisade bundled
inside a commercial product it buys, the producer of *that* product is the attesting party; it is
not this project, and this document does not become an attestation in that case either.

So this map is **voluntary evidence of practice**. It exists because an ISSM reasonably wants to
know how a piece of software was built before allowing it into an enclave, and "look at the
source, it's one file" is a fair answer but not a complete one. It is not a filing, not a
certification, and not a claim of SSDF conformance. It is a practice-by-practice statement of
what this two-person project actually does, what it does not do, and how you check either one.

Where a practice is genuinely inapplicable it is marked **N/A** with the reason, not quietly
scored as met. Where a practice is only partly done it is marked **Partially met** and the
shortfall is named in the same row. Thirteen of the forty tasks below are short of Met. They are
collected again at the end so you do not have to derive the list from the tables.

### Verdict vocabulary

| Verdict | Meaning |
|---|---|
| **Met** | Implemented, and verifiable by you from the artifact or the evidence bundle |
| **Partially met** | Implemented in part; the named shortfall is real and is repeated in the gap list |
| **Not met** | A gap. What it would take is stated |
| **N/A** | Genuinely inapplicable to this codebase, with the reason |

### The tally, so you can check it against the tables

Forty verdict rows across the nineteen practices of SP 800-218 v1.1 that apply here (PO.1-PO.5,
PS.1-PS.3, PW.1-PW.2 and PW.4-PW.9, RV.1-RV.3; PW.3 is not used in v1.1). Count the rows
yourself; the arithmetic is meant to be checkable, not taken on faith. Two rows each cover a
pair of tasks (PW.4.1/PW.4.4 and PW.6.1/PW.6.2), so the forty rows carry forty-two task IDs.

| Verdict | Tasks |
|---|---|
| Met | 22 |
| Partially met | 10 |
| Not met | 3 |
| N/A | 5 |
| **Total** | **40** |

PO.5.1 is counted as N/A — there is no build environment to separate — even though its row records
a substantive control (the CUI ignore rules) under the same heading.

## The artifact this describes

| | |
|---|---|
| file | `palisade.html` |
| version | 2.8 |
| bytes | 521,771 |
| sha256 | `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` |
| sha384 | `40c8ee517b7a7bf15a686f1231cdb039f9a94570f681dec25afd68f44816131fd9003d42c8de24e3915353c72928612f` |
| script block | one block, 438,777 bytes, `sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=` |
| licence | MIT — Gavin Lee Domingo Johnson, Jacob Keith |

### Evidence integrity note — read before you check a citation

Most of the hardening evidence bundle (`evidence/gate-B/`, `evidence/gate-C/`) was produced
against an interim v2.8 build: sha256 `376631c2…`, 521,745 bytes. The shipped file is
`fd2f80e9…`, 521,771 bytes. The 26-byte difference is one correctness fix applied after that
gate — doubling the backslashes in the 18 of 20 `productAliases` pattern literals that carry
`\s` or `\b`, so those escapes reach `RegExp` instead of degrading to `s` and `U+0008` — plus
the mandatory reseal. (The other two, `^(chromium)` and `^openssl`, contain no escape and were
never affected.) Those hashes will not match, and you should expect that rather than
discover it.

Three checks were therefore re-run against the **shipped** bytes for this document, on
2026-09-11. The Chromium transcripts from that campaign are a review-workspace bundle; they
are not in this repository. `tools/seal.mjs`, `tools/csp-lint.sh` and `baseline/harness.mjs`
*do* ship here, and those are the commands an accreditor can re-run. Hostile fixtures and
the other review transcripts stay out of the tree on purpose: they are not part of the file
a user receives.

The three re-runs (from the repository root; `palisade.html` is in that directory):

| Check | Command | Result |
|---|---|---|
| Seal / policy / version / offline invariants | `node tools/seal.mjs palisade.html --verify` | **PASS**, exit 0 |
| Static lint | `bash tools/csp-lint.sh palisade.html` | **PASS**, 1 tagged export-only handler, all other counters 0 |
| Functional regression gate, real `file://`, Chromium 150.0.7871.181 | `node baseline/harness.mjs "file://$PWD/palisade.html" ./gate` | **VERDICT: PASS** — hosts 6, ppsm 19, stig 8, sw 24, asset 9, meter 21 %, 0 console errors, 0 CSP violations |

The frozen table counts are identical to `baseline/FROZEN-BASELINE.txt`, which is what shows the
alias fix changed no measured behaviour in the baseline set.

---

# PO — Prepare the Organization

## PO.1 Define Security Requirements for Software Development

| Task | Verdict | Evidence |
|---|---|---|
| **PO.1.1** Requirements for the development infrastructure and process | **Partially met** | `CONTRIBUTING.md` states four hard constraints as merge-blocking requirements, not style preferences: single file, no dependencies, no network calls, no browser storage. It also makes CUI handling the first section — never commit scan data, genericize site identifiers, redact before pasting into an issue or PR. What is absent is any requirement covering the *workstation* the code is written on. |
| **PO.1.2** Requirements for the software itself | **Met** | The four hard constraints are security requirements for the product, and each is machine-checked at release: `tools/csp-lint.sh` counts network primitives, storage primitives, `javascript:` URLs, `setAttribute`-on-handlers and script tags; `tools/seal.mjs` checks byte hygiene, version consistency and the inline-handler budget. A change that breaks a stated requirement fails the check rather than relying on a reviewer noticing. |
| **PO.1.3** Communicate requirements to third-party component suppliers | **N/A** | There are no third-party components and no suppliers. `components: []` in `palisade.cdx.json`, `DEPENDS_ON → NONE` in `palisade.spdx.json`, and thirteen falsification greps in `docs/SBOM.md` that a reviewer runs in under a minute. |

## PO.2 Implement Roles and Responsibilities

| Task | Verdict | Evidence |
|---|---|---|
| **PO.2.1** Define roles and responsibilities | **Partially met** | Two named authors, both of whom review. `CONTRIBUTING.md` assigns the one role that matters here — every change gets a second pair of eyes before merge — and the release checklist assigns the reseal and verify steps. There is no separate security-owner role, because with two people there is nobody to separate. |
| **PO.2.2** Role-based training | **Not met** | No training programme exists. Stating otherwise for a two-person project would be theatre. The nearest real thing is that `CONTRIBUTING.md` encodes the non-obvious traps (CRLF and BOM break the seal; inline `on*` handlers are dead controls; the version lives in four places) so they are learned from the document rather than by breaking a release. |
| **PO.2.3** Upper-management commitment | **N/A** | No organization. The two authors are the whole project. |

## PO.3 Implement Supporting Toolchains

| Task | Verdict | Evidence |
|---|---|---|
| **PO.3.1** Specify which tools must be used | **Met** | The toolchain is unusually short, and that is the point. **To run Palisade: a browser.** There is no compiler, no bundler, no transpiler, no package manager, no build step. To *release* it: `git`, plus `tools/seal.mjs` (Node) and `tools/csp-lint.sh`. To *verify* it: `baseline/harness.mjs` under Chromium, and `tools/sbom-check.py` under Python 3. `CONTRIBUTING.md` names the release commands explicitly. |
| **PO.3.2** Deploy and operate tools securely | **Partially met** | The release tools run locally against the finished file; none of them fetches anything, and none of them generates the file. The gap is that they run on the author's workstation, by hand, with no CI enforcing that they ran. See the gap list. |
| **PO.3.3** Tools generate artifacts of their support | **Met** | Every tool emits a durable transcript, and the transcripts are the deliverable: `evidence/gate-C/00-GATE-C-FINAL.txt` (four gate items consolidated), `evidence/gate-C/negative-tests.txt` (the browser's actual refusal text per attack primitive), `evidence/gate-C/05-tamper-evidence.txt` (one byte changed → page inert), `evidence/gate-B/verify-B.txt` (measured limits and neutralisation counts), `evidence/supply-chain/` (this release's re-runs), and `MANIFEST.json` from `seal.mjs --manifest`. |

## PO.4 Define and Use Criteria for Software Security Checks

| Task | Verdict | Evidence |
|---|---|---|
| **PO.4.1** Define criteria and track throughout the lifecycle | **Met** | The criteria are written down as numbers, not adjectives, and they gate the release. `baseline/FROZEN-BASELINE.txt` freezes the functional set (6 hosts; 19 / 8 / 24 / 9 table rows; 21 % meter). `tools/csp-lint.sh` locks eight counters against a baseline, one of which is "inline `on*` handlers: 1, and it must be the tagged export-only one". `tools/seal.mjs --verify` must exit 0. A regression on any of these fails the release. |
| **PO.4.2** Gather and safeguard the information needed | **Partially met** | The information is gathered and kept — the evidence bundle above. It is not yet *safeguarded* by anything stronger than the filesystem: there is no CI attestation, no signed transcript, and the bundle is not published with the release. |

## PO.5 Implement and Maintain Secure Environments for Software Development

| Task | Verdict | Evidence |
|---|---|---|
| **PO.5.1** Separate and protect each environment | **N/A in the usual sense, Partially met in substance** | There is no build environment to separate, because there is no build — the file is authored, then verified, then shipped. What *is* separated is the data: `.gitignore` enforces that no scan data, session file, checklist, XCCDF XML or results archive enters the repository. That control was dead until this release (it shipped as `gitignore.txt`, a filename git never reads, so every rule in it was inert); it is now live and proven so — `git check-ignore -v test.nessus` returns `.gitignore:10:*.nessus`, and a history search found nothing of that shape was ever committed (`evidence/gate-C/07-repo-hygiene.txt`). |
| **PO.5.2** Secure and harden development endpoints | **Not met** | No endpoint hardening standard is documented or enforced for the authoring workstations. |

---

# PS — Protect the Software

## PS.1 Protect All Forms of Code from Unauthorized Access and Tampering

| Task | Verdict | Evidence |
|---|---|---|
| **PS.1.1** Store code with least privilege | **Partially met** | Source lives in one repository (`github.com/lexen13/Palisade`) with write limited to the two authors; external contributions arrive as pull requests and merge only after review. `CONTRIBUTING.md` requires `git add -p` hunk-by-hunk staging and a `git status` check before every commit, and says explicitly not to trust `.gitignore` blindly — a control aimed at CUI inclusion, which is the realistic tampering-adjacent risk for this project. The gap: branch protection and required reviews are repository settings not evidenced in the artifact, so you have our word for them and not a check. |

## PS.2 Provide a Mechanism for Verifying Software Release Integrity

| Task | Verdict | Evidence |
|---|---|---|
| **PS.2.1** Make integrity verification available to acquirers | **Partially met — but with one mechanism that is stronger than a checksum** | Three layers, and the honest limits of each. **(1) Digests.** `MANIFEST.json` carries bytes, sha256, sha384, sha512, the version, and the script-block hash; both SBOMs carry the same digests; `docs/SBOM.md` gives the commands. A digest only helps someone who runs it. **(2) The seal.** `script-src` is the SHA-256 of the file's own script block, so a single changed byte — whitespace included — makes the browser refuse to execute the script, and the page loads styled, complete and completely inert with the expected hash named in the console. That is tamper evidence that needs no tooling and no cooperation from whoever opened the file; it was demonstrated, not reasoned about (`evidence/gate-C/05-tamper-evidence.txt`: control build `appDefined: true, tablesFilled: 326`; one byte changed inside the script block → `appDefined: false, tablesFilled: 0, violations: 1`). **(3) What is missing.** There is no detached OpenPGP signature and no signing key, so nothing here proves *who* produced the file — only that it has not changed since the digest was taken. Do not read the seal as a code signature. It is not one, and an `.html` cannot carry one the browser verifies. |

## PS.3 Archive and Protect Each Software Release

| Task | Verdict | Evidence |
|---|---|---|
| **PS.3.1** Securely archive each release | **Not met** | `CHANGELOG.md` records every release back to 2.1, and the version is enforced identical across the four places it appears in the file. But **the repository carries no git tags** — `git tag -l` is empty — so there is no immutable per-release marker and no release archive. This is the most concrete gap in the document. What it takes: tag each release, attach `palisade.html` plus `MANIFEST.json` and both SBOMs to the release. |
| **PS.3.2** Collect and share provenance data | **Partially met** | Line 2 of the shipped file is a provenance comment naming the tool, version, licence, both authors, the source repository and where the hashes live — so the artifact states its own origin even when it arrives on a USB drive with no context. Both SBOMs record supplier, authors, licence, purl and digests. What provenance does *not* cover: there is no build-provenance attestation, because there is no build to attest to. |

---

# PW — Produce Well-Secured Software

> **PW.3** is not used in SP 800-218 v1.1's practice table; nothing is being skipped. If your copy
> numbers it differently, the third-party-software content it once carried is addressed under
> PO.1.3 and PW.4 — both of which are N/A here for the same reason: there is no third-party code.

## PW.1 Design Software to Meet Security Requirements and Mitigate Security Risks

| Task | Verdict | Evidence |
|---|---|---|
| **PW.1.1** Use risk modelling | **Met** | Two artifacts, doing different jobs. `docs/THREAT-MODEL.md` is the standing model for the shipped build (sha256 `fd2f80e9…`): assets, adversaries, trust boundaries, the sink classes with the control on each and how each is verified, residual risk, and explicit non-goals. `HARDENING-LEDGER.md` is the record of the adversarial review that produced it — every finding through two independent skeptic passes, plus an explicitly refuted list, which is the material that shows the review was adversarial rather than a list of everything imaginable. Honest caveat: the threat model is new with this release, so there is no history yet of a design change being checked against it. |
| **PW.1.2** Track security requirements, risks and design decisions | **Met** | `HARDENING-LEDGER.md` records each finding, its severity, the change, and the reasoning — including decisions *not* to act and why (`'self'` is unreliable on `file:`; a nonce in a public static file degrades to `'unsafe-inline'`; `'unsafe-hashes'` for 192 handlers re-opens the attribute channel and was used only for the single exported-report print button). `notes/router-findings.md` records where the ledger's own analysis was wrong and was corrected, which is the part most such documents omit. |
| **PW.1.3** Build in standardized security features | **Met** | The file uses the platform's own standardized control rather than a bespoke one: a W3C Content Security Policy delivered by `<meta>`, with `script-src` bound to the SHA-256 of the single script block and every fetch directive set to `'none'`. Feasibility on `file://` was established empirically before adoption, not assumed (`evidence/csp-probe/RESULT.md`). |

## PW.2 Review the Software Design to Verify Compliance

| Task | Verdict | Evidence |
|---|---|---|
| **PW.2.1** Qualified reviewer reviews the design | **Partially met** | The v2.8 design changes were reviewed against the stated requirements and the review is documented in the ledger, including the two-pass skeptic discipline. The reviewers are the authors and one adversarial review pass; there is no independent external design review. |

## PW.4 Reuse Existing, Well-Secured Software When Feasible

| Task | Verdict | Evidence |
|---|---|---|
| **PW.4.1 / PW.4.4** Acquire and verify third-party components | **N/A** | Nothing is acquired. `components: []`; no bundled library, no vendored code, no CDN reference, no subresource-integrity attribute, no package-manager manifest, no external `src` or `href`; zero `import … from` and zero `require(`. Every one of those is a grep in `docs/SBOM.md`, and `evidence/supply-chain/greps.txt` is the transcript of running them against the shipped bytes. `CONTRIBUTING.md` makes it a merge-blocking rule: "If you need to parse something, parse it." |
| **PW.4.2** Well-secured in-house components | **Met** | The parsers — `.nessus` XML, Tenable CSV, XLSX, `.ckl`/`.cklb`, XCCDF — are written in-file rather than pulled in, which is why "no dependencies" is achievable at all. They are bounded by a named `LIMITS` table and every breach surfaces in the parse-warning banner; the limits were measured, not asserted (see PW.8). |

## PW.5 Create Source Code by Adhering to Secure Coding Practices

| Task | Verdict | Evidence |
|---|---|---|
| **PW.5.1** Follow secure coding practices for the language | **Met, with the failure that motivated it stated** | The escaping discipline is real and was traced, not assumed: escaping is pervasive rather than selective — the token `esc(` occurs 344 times in the shipped file (`grep -oE '\besc\(' palisade.html | wc -l`, measured 2026-09-11) — and all 20 report-section builders were walked to confirm every scan-derived value is escaped before it reaches the report. Two renderers nonetheless got it wrong in 2.7 — `renderPPSM` and `renderSTIG` interpolated an object key *raw* into a JS string inside an `on*=""` attribute, and because the PPSM key is `proto + "/" + port` with `proto` taken verbatim from the `.nessus` `protocol` attribute, a crafted scan export ran script the moment it was dropped in. That is a JS-string context being handed an HTML-entity control, not a pattern of carelessness — and the fix removes the sink class rather than patching two call sites: keys now travel as `esc()`'d `data-*` attributes and are read back from the DOM as strings, and the bypassable `JSON.stringify(x).replace(/"/g,"&quot;")` idiom is gone from all nine sites that used it. Proven both ways on real `file://`: pristine build plus `hostile.nessus` → `document.title` becomes `pwned` and 16 injected `<img>` elements appear; hardened build → canary silent, 0 injected, 0 CSP violations (`evidence/gate-C/06-hostile-fixtures.txt`). |

## PW.6 Configure the Compilation, Interpreter, and Build Processes

| Task | Verdict | Evidence |
|---|---|---|
| **PW.6.1 / PW.6.2** Use and configure build-tool security features | **N/A — no compiler, no build, no binary** | There is nothing to compile and no executable to harden, so the usual contents of this practice (stack protectors, RELRO, CFI, ASLR opt-in, compiler warning levels) have no referent. Recorded but **not claimed as compliance**: the nearest analogue is that the file configures its own interpreter — the browser — to refuse everything except one script identified by cryptographic digest, which is closer in spirit to PW.6 than to anything else in the framework. It is described here so a reviewer can judge it, not scored as a met practice. |

## PW.7 Review and/or Analyze Human-Readable Code

| Task | Verdict | Evidence |
|---|---|---|
| **PW.7.1** Decide whether review/analysis should be performed | **Met** | It is a standing rule, not a judgement call per change. `CONTRIBUTING.md`: "Every change gets a second pair of eyes before merge — the review catches accidental data inclusion at least as often as it catches bugs, which is why it stays even when it feels like overhead on a two-person change." The reason given is the honest one: on a project this size the review's main yield is CUI spillage, not defects. |
| **PW.7.2** Perform the review and/or analysis | **Partially met** | *Human review:* the workflow is branch → `git add -p` → `git status` → PR → review → merge. It is exercised on external contributions, not only internal ones: merge commit `442f203`, "Merge pull request #1 from Cratioo/ui/simplify-for-new-users", merged 2026-08-29 — a pull request from a contributor outside the two authors, reviewed before merge. One caveat you should know: the working clone used to produce this document is a shallow clone, so the review thread and per-commit history are on GitHub and cannot be reconstructed from the clone. *Automated analysis:* `tools/csp-lint.sh` is a custom static check over eight counters and it gates the release, but **no general-purpose SAST tool (semgrep, CodeQL, ESLint security rules) has been run**. The custom lint finds regressions in the specific properties this project promises; it does not look for the classes it was not written to look for. |

## PW.8 Test Executable Code

| Task | Verdict | Evidence |
|---|---|---|
| **PW.8.1** Decide what testing is needed | **Met** | `CONTRIBUTING.md` is candid that "There is no test suite; the tool is verified by driving it", and gives a six-step manual procedure. For v2.8 that was judged insufficient for security-relevant change, and a headless gate was built to replace judgement with measurement. |
| **PW.8.2** Scope, design, perform and document the testing | **Met — and this is the strongest row in the document** | Every figure below was measured in Chromium 150.0.7871.181 on real `file://` URLs, and every transcript is in the evidence bundle. **Injection:** four hostile fixtures; canary never fired, `window.__pwned` undefined, 0 injected `<img>`, 0 CSP violations. **Negative tests** (`evidence/gate-C/negative-tests.txt`) record the browser's actual refusal text per attack primitive — 5 of 6 refused, and the 6th is reported rather than dropped: Chromium exempts debugger-originated `eval` from CSP so that a CSP'd page stays debuggable, so that test measures the debugger, not the policy; the same compiler reached from a call site *inside* the page, which is what hostile input actually has, is refused with `blockedURI: eval`. **CSV/TSV formula injection:** 43 cells neutralised across 19 exports, 0 left live, and `-5`, `+5`, `-5%` still arrive numeric so the columns still sum. **Prototype pollution:** pristine build gains `Object.prototype.fromScan === true` from a crafted session file; hardened build stays clean. **Decompression bomb:** uncapped inflate peaked at 2,573 MiB of resident memory and *silently succeeded*; the capped build peaks at 329.8 MiB and refuses by name, a 7.8× reduction, with the tab responsive in 52 ms. **Tamper evidence:** one byte changed inside the script block → page inert, `tablesFilled` 326 → 0. **Non-regression:** 19 of 19 exported artifacts byte-identical across the change; frozen table counts unchanged. What is still missing: no unit tests and no fuzzing. |

## PW.9 Configure Software to Have Secure Settings by Default

| Task | Verdict | Evidence |
|---|---|---|
| **PW.9.1** Define a secure baseline | **Met** | The defaults are chosen so the safe configuration is the one you get without doing anything, and the risky one requires a deliberate act. **No network, structurally.** `default-src 'none'` with `connect-src`, `img-src`, `font-src`, `frame-src`, `object-src`, `media-src`, `manifest-src`, `worker-src`, `base-uri` and `form-action` all `'none'`. Measured on the shipped file: 0 call sites for `fetch(`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or `EventSource`, and 0 occurrences of any `http://`, `https://` or `ftp://` string anywhere in 521,771 bytes. The claim stops being something you confirm by reading 7,600 lines and becomes something the browser refuses to let the page break. **No storage, structurally.** 0 call sites for `localStorage`, `sessionStorage`, `indexedDB` or `document.cookie`; state lives in memory and persistence is an explicit export the user performs. **CUI is not bundled by default.** The evidence package no longer includes the session file — the complete raw dataset, every host, IP, software row and enumerated account with RID, groups and admin flags — unless the operator ticks a box, because packages get handed to people the enumerated accounts do not belong to. Measured: unticked → 22 zip entries, 0 session files, and the index says "No resume session file is included"; ticked → 23 entries, 1 session file, and the index says so instead. **Exports are inert by default.** The report preview iframe is sandboxed without `allow-scripts`; all three generated HTML artifact types carry their own CSP; CSV neutralisation is on with no opt-out. **Ingestion is bounded by default:** 1 GiB per input file refused before it is read, 256 MiB per inflated zip entry, 768 MiB per archive, 1,048,576 worksheet rows (Excel's own maximum, so a legal worksheet cannot be truncated). |
| **PW.9.2** Implement and document the defaults | **Met, including the parts that are worse for the user** | The defaults are implemented as described above and documented in `README.md` and `CHANGELOG.md`. The 2.8 changelog calls out three behaviour changes in the user's favour of knowing rather than the project's favour of looking clean: a neutralised CSV cell now carries a *visible* apostrophe on import ("it is not hidden the way a typed-in leading quote is, and a value that needed neutralising is worth seeing"); the sandboxed preview lost its own print button, so printing moved to a parent-page control; and the evidence package no longer contains the session file unless asked. Two honest caveats are documented rather than buried: `style-src` remains `'unsafe-inline'` because the file sets `style=` 483 times (measured on the shipped build; the file's own CSP comment still reads 481, a figure carried over from an earlier build — the drift is worth noticing and not worth repeating), and CSP governs neither downloads, the clipboard, nor printing — nobody should claim it does. |

---

# RV — Respond to Vulnerabilities

## RV.1 Identify and Confirm Vulnerabilities on an Ongoing Basis

| Task | Verdict | Evidence |
|---|---|---|
| **RV.1.1** Gather information from acquirers, users and public sources | **Met (newly)** | `SECURITY.md` establishes the intake route — GitHub private security advisories on `github.com/lexen13/Palisade` — with a stated acknowledgement window, scope, supported version and a safe-harbour statement. It is new with this release, so there is no track record behind it yet; judge the process, not a history it does not have. |
| **RV.1.2** Review, analyse and test the code for vulnerabilities | **Met** | The v2.8 adversarial review is the instance: seven lens audits, two independent skeptic passes per finding, a router pass that found four more and corrected the ledger where it was wrong, and the measured gate under PW.8. |
| **RV.1.3** Have a vulnerability disclosure policy and implement it | **Met (newly), with the right scoping stated** | `SECURITY.md` is the policy. It also states plainly that **CISA BOD 20-01 binds federal agencies, not this project** — the policy is best practice voluntarily adopted, not a compliance artifact, and reading it as one would be wrong. |

## RV.2 Assess, Prioritize, and Remediate Vulnerabilities

| Task | Verdict | Evidence |
|---|---|---|
| **RV.2.1** Analyse each vulnerability enough to plan remediation | **Met** | Each finding in `HARDENING-LEDGER.md` carries mechanism, reachability, measured impact and a break-risk assessment. The severities were adjudicated twice and *held down* where the evidence did not support more: CSV formula injection stays medium because it fires on the recipient's machine and requires their interaction; the two XSS sinks stay high rather than critical because the deployment has no network egress, so the real impact is silent tampering of the compiled evidence — which the memo names as the actual risk rather than dressing it up as exfiltration. Nothing in the review was scored at CVSS 9.0. |
| **RV.2.2** Plan and implement risk responses | **Met** | Fixes are grouped into blocks with their own gates, each block independently shippable, with an explicit rule not to ship the structural block partially. Remediation is recorded per release in `CHANGELOG.md` in terms a reader can check. |

## RV.3 Analyze Vulnerabilities to Identify Their Root Causes

| Task | Verdict | Evidence |
|---|---|---|
| **RV.3.1** Determine root causes | **Met** | Root causes were named rather than symptoms patched. The injection root cause was a context error — an HTML-entity control applied to a JavaScript-string context — not carelessness. The prototype-pollution root cause was that `JSON.parse` creates a genuine *own* `__proto__` property, so a `for..in` read of it returns `Object.prototype` and the subsequent write lands there; the first two skeptic passes dismissed this class by analysing `Object.assign`, which was correct and irrelevant. Read the correction in `notes/router-findings.md` (R3), not in the ledger: `HARDENING-LEDGER.md` section 5 still lists "Prototype pollution via JSON loaders" under EXPLICITLY OUT OF SCOPE / REFUTED, and that entry is superseded. The finding is real, it was fixed, and it is measured in `evidence/gate-B/verify-B.txt` §8. |
| **RV.3.2** Analyse root causes over time to identify patterns | **Partially met** | Patterns within the 2.7→2.8 review were identified and acted on. There is no cross-release trend analysis, because there is one security review to trend. |
| **RV.3.3** Review for similar vulnerabilities and proactively fix | **Met — and this is the practice the fixes were actually designed around** | Each fix was placed at a choke point so the class cannot recur, rather than at the site where it was found. The `JSON.stringify().replace(/"/g,"&quot;")` idiom was removed from all nine sites, not just the two that were live. A single `safeParse()` reviver was routed at all seven untrusted-JSON entry points rather than guarding the file's 41 `for..in` loops — chosen explicitly because it is one reviewable choke point that a future renderer cannot forget. One `csvq`/`tsvSafe` pair neutralises formulas in all ~30 exporters. And converting 191 of 192 inline handlers to delegated `data-click`/`data-change` actions against an allow-list means an injected `on*` attribute is a dead control by policy, not by escaping discipline. |
| **RV.3.4** Review and update the SDLC process | **Met** | The process changed as a result, in checkable ways: the version-consistency check now compares all four places the version is written, because a session file stamped `2.6` shipped in a 2.7 build and nothing caught it; `--verify` became a mandatory pre-commit and pre-release step; the CUI ignore file was renamed from the inert `gitignore.txt` to `.gitignore` and verified live; and `CONTRIBUTING.md` was updated with the seal's failure mode so the next contributor learns it from the document instead of from a broken release. |

---

# The gaps, in one place

Thirteen tasks are short of Met — ten partially met, three not met. The nine rows below are the
ones with a concrete action attached; the four remaining are named underneath, with why they have
no action. A map that reports only its strengths is not evidence.

| # | Practice | Gap | What closing it takes |
|---|---|---|---|
| 1 | **PS.3.1** | No git tags at all; no per-release archive | Tag each release; attach `palisade.html`, `MANIFEST.json` and both SBOMs |
| 2 | **PS.2.1** | No detached signature and no signing key — integrity is provable, origin is not | Publish a key fingerprint; sign each release; document `gpg --verify` |
| 3 | **PO.3.2 / PO.4.2** | Release checks run by hand on the author's workstation; nothing enforces that they ran | A CI workflow running `seal.mjs --verify`, `csp-lint.sh` and the harness on every push, PR and tag |
| 4 | **PW.7.2** | No general-purpose SAST has ever been run; the custom lint only checks the properties this project promises | Run semgrep or CodeQL; triage and record the output |
| 5 | **PW.8.2** *(residual inside a Met row)* | No unit tests and no fuzzing; the gate is end-to-end only | Fuzz the parsers, which are the untrusted-input boundary |
| 6 | **PW.2.1** | No independent external design review — the reviewers are the two authors plus one adversarial pass | Obtain one review from outside the project |
| 7 | **PO.5.2** | No documented hardening standard for authoring workstations | Adopt and document one |
| 8 | **PO.2.2** | No role-based security training | Honest answer for a two-person project: unlikely to change |
| 9 | **PS.1.1** | Branch protection and required reviews are repository settings, not evidenced in the artifact | Publish the ruleset, or accept it on our word |

Four short-of-Met tasks are deliberately absent from that table, because the honest action for
each is "none": **PO.1.1** (no requirements covering the authoring workstation — the action is
PO.5.2, row 7, and would be double-counted here); **PO.2.1** (no separate security-owner role —
with two people there is nobody to separate); **PS.3.2** (no build-provenance attestation — there
is no build to attest to); and **RV.3.2** (no cross-release root-cause trend — there is one
security review to trend, and a second one will fix this by existing).

Two further items are not gaps at all but are easy to mistake for them, so they are stated here
as well:
`style-src` remains `'unsafe-inline'` (483 `style=` occurrences measured on the shipped build; CSS cannot execute and every
channel that could send anything anywhere is `'none'` — hashing the style elements is a later
step), and CSP governs neither downloads, the clipboard, nor printing.

# What this document does not claim

Stated explicitly, because a single inflated claim would fairly discredit everything above it.

- **No CISA Secure Software Development Attestation Form has been filed**, and none is required
  for freely obtained open-source software under OMB M-23-16. This map is voluntary.
- **Not an SSDF conformance or certification claim.** Thirteen of forty tasks are short of Met,
  tallied above and listed at the end.
- **The file is not code-signed.** The CSP hash is a tamper seal, not a signature; it proves the
  bytes have not changed, never who produced them. An `.html` cannot carry a signature a browser
  verifies.
- **There is no reproducible, hermetic or SLSA build**, because there is no build at all. The file
  is authored, verified, and shipped. Sealing is a release step run against the finished file, not
  a step that produces it.
- **No DoDIN APL listing is claimed or sought.** The APL covers UC network infrastructure, and an
  APL listing is not an RMF authorization. Palisade is assessed as application software inside an
  existing workstation or enclave boundary.
- **No accessibility conformance is claimed here, and none is claimed anywhere in the package.**
  A WCAG 2.1 / Section 508 evaluation *has* been completed and ships as
  `docs/ACCESSIBILITY-CONFORMANCE-REPORT.md`; its own conformance statement is that **Palisade
  v2.8 does not conform to WCAG 2.1 Level AA**. Per-criterion "Supports" cells in that report are
  VPAT row vocabulary, not a product-level conformance claim.
- **No ASD STIG requirement is cited here.** Only two V-IDs have been read from a current release
  (APSC-DV-002490, XSS, CAT I; APSC-DV-002480, CAT II) and they belong in the security assessment
  memo, not in this map. Any other V-ID must be confirmed against the current STIG release before
  it is quoted — including by us.
- **`evidence/gate-B/` and `evidence/gate-C/` describe an interim build**, sha256 `376631c2…`, not
  the shipped `fd2f80e9…`. The three checks re-run against the shipped bytes are named at the top
  of this document, with their transcripts in `evidence/supply-chain/`.

---

*Palisade 2.8 · sha256 `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` ·
mapped against NIST SP 800-218 v1.1 · 2026-09-11 · MIT · this document is voluntary evidence of
practice and is not an attestation.*
