# Security Assessment — Palisade v2.8

**For:** the ISSM / ISSO / SCA assessing Palisade for use on a NIPRNet or air-gapped
assessment workstation.
**From:** Jacob Keith (co-author), 11 September 2026.
**Companion document:** `MOBILE-CODE-DETERMINATION.md` — answers "it's an HTML file with
JavaScript in it" specifically.

---

## 0. Bottom line

Palisade v2.7 was put through an adversarial review. The review found **two places where text
from a scanned host was written into the page as code**, and **one place where a session file
handed over by a colleague could change the behaviour of every object in the tool**. Both are
fixed in v2.8, and both fixes were measured before and after rather than argued. The in-repo
verification commands in §11 reproduce the functional gate, the seal, and the CSP-surface
lint against the shipped bytes. The Chromium transcripts from the hardening campaign are a
separate review bundle; they are not published in this repository.

Two things about the impact, stated plainly because they cut in opposite directions:

- **It was never exfiltration.** There is no network egress in this deployment. The realistic
  impact of the injection defects was **silent tampering with the evidence the tool compiles** —
  STIG applicability marks, PPSM rows, POA&M drafts, eMASS baselines. For an RMF evidence
  compiler that is the worse of the two, not the milder one: exfiltrated data is a disclosure
  you can scope, but corrupted evidence is a package the AO signs believing something untrue.
- **Nothing here reaches CVSS 9.** Severities in §5 are argued down as often as up, and the
  reasoning for each is given.

What v2.8 can claim that v2.7 could not is that the central assurance properties are now
**enforced by the browser** rather than asserted by the authors. "The tool makes no network
calls" used to be a claim you verified by reading 7,957 lines and trusting that no future edit
would add a `fetch()`. It is now `connect-src 'none'`, and the browser refuses.

---

## 1. What the tool is

Palisade compiles RMF control evidence from Tenable/ACAS scan exports. The operator drops
`.nessus`, `.csv`, `.xlsx`, `.ckl`/`.cklb` and SCC result files onto the page; it produces STIG
applicability worksheets, eMASS hardware and software baselines, PPSM registry rows, POA&M
drafts, account audits, asset inventories, scan-coverage and reconciliation views, an assessment
report and a packaged evidence `.zip`. There are **31** export functions in the file
(`grep -cE '^function export[A-Za-z]+\(' palisade.html`).

It is a single HTML file, opened from `file://`, typically off a USB drive or a local copy, on a
workstation that may be air-gapped. It is MIT licensed. It has no installer, no service, no
configuration file, no telemetry, and no persistent state: close the tab and nothing remains.

---

## 2. Why this architecture is unusually assessable

Most application assessments are a sampling exercise: you read some of the code, trust the build
system to turn it into the artifact, and trust the dependency tree not to contain surprises. All
three of those steps are absent here, and that is worth stating first because it changes what
the rest of this memo is worth.

**One file. No build step. The bytes an assessor reads are the bytes that run.** There is no
bundler, minifier, transpiler, or generator between the source and the artifact. `palisade.html`
*is* the source. When you read line 5037 and see how a PPSM row is built, you have read the code
that executes — not a pre-image of it.

**No dependency tree.** Zero third-party components. No CDN reference, no `<script src>`, no
`integrity` attribute (because there is no subresource to have integrity of), no package
manifest, no lockfile, no transitive anything. Measured:

```
grep -oiF '<script' palisade.html | wc -l      # 1  — one inline block, no src attribute
grep -oE  'https?://' palisade.html | wc -l    # 0  — not one absolute URL, comments included
grep -oiF '<link'   palisade.html | wc -l      # 0
grep -oE  'integrity[[:space:]]*=' palisade.html | wc -l   # 0
```

A supply-chain question about Palisade has exactly one component in scope, and its SHA-256 is
in §3.1.

**The release tooling is verification, never a build.** `tools/seal.mjs` recomputes the script
hash, checks byte hygiene and version consistency, counts inline handlers, and emits a manifest.
It *checks* the shipped file; it does not *produce* it. That distinction is what keeps the
"bytes you read are the bytes that run" property true, and it is a deliberate project constraint:
`CONTRIBUTING.md` line 21 — *"**Single file.** Everything ships in `palisade.html`. No build
step, no bundler."*

**The whole execution surface is enumerable.** One script element, identified by cryptographic
digest. One iframe, sandboxed without `allow-scripts`. One inline event handler in the entire
file, and it is written into a *downloaded* document, not this one. That is not a claim about
discipline; §3 and §4 are how you check it.

---

## 3. The artifact, and the measured zeros

### 3.1 Identity

| | |
|---|---|
| file | `palisade.html` (v2.8) |
| bytes | 521,771 |
| lines | 7,957 |
| sha256 | `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` |
| sha384 | `40c8ee517b7a7bf15a686f1231cdb039f9a94570f681dec25afd68f44816131fd9003d42c8de24e3915353c72928612f` |
| inline script | 1 block, 438,777 bytes, `sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=` |
| line endings / BOM | LF only / none |
| release check | `node tools/seal.mjs palisade.html --verify` → **PASS**, exit 0 |
| static lint | `bash tools/csp-lint.sh palisade.html` → **PASS**, exit 0 |
| functional gate | `node baseline/harness.mjs file://…/palisade.html …` → **VERDICT: PASS**, frozen numbers identical |

### 3.2 Measured zeros

Every count below was produced by the command beside it, run against the file identified above
on 11 September 2026. `grep -o … | wc -l` counts occurrences, not lines.

| Property | Command | Count |
|---|---|---|
| no HTTP client | `grep -oE '\bfetch[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| no XHR | `grep -oF 'XMLHttpRequest' palisade.html \| wc -l` | **0** |
| no sockets | `grep -oF 'WebSocket' palisade.html \| wc -l` | **0** |
| no beacon | `grep -oF 'sendBeacon' palisade.html \| wc -l` | **0** |
| no server-sent events | `grep -oF 'EventSource' palisade.html \| wc -l` | **0** |
| no image beacon | `grep -oE 'new[[:space:]]+Image' palisade.html \| wc -l` | **0** |
| no absolute URL anywhere | `grep -oE 'https?://' palisade.html \| wc -l` | **0** |
| no local storage | `grep -oF 'localStorage' palisade.html \| wc -l` | **0** |
| no session storage | `grep -oF 'sessionStorage' palisade.html \| wc -l` | **0** |
| no IndexedDB | `grep -oF 'indexedDB' palisade.html \| wc -l` | **0** |
| no cookies | `grep -oF 'document.cookie' palisade.html \| wc -l` | **0** |
| no `eval` | `grep -oE '\beval[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| no `Function` constructor | `grep -oE '[^a-zA-Z0-9_$.]Function[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| no `document.write` | `grep -oE 'document[[:space:]]*\.[[:space:]]*write' palisade.html \| wc -l` | **0** |
| no string-argument timers | ``grep -oE 'set(Timeout\|Interval)[[:space:]]*\([[:space:]]*["'"'"'`]' palisade.html \| wc -l`` | **0** |
| no `javascript:` URLs | `grep -oiF 'javascript:' palisade.html \| wc -l` | **0** |
| no ActiveX | `grep -oF 'ActiveXObject' palisade.html \| wc -l` | **0** |
| no applet / object / embed | `grep -oiE '<(applet\|object\|embed)' palisade.html \| wc -l` | **0** |
| no WebAssembly | `grep -oF 'WebAssembly' palisade.html \| wc -l` | **0** |
| no workers | `grep -oEi 'new[[:space:]]+(Shared)?Worker\|importScripts\|serviceWorker' palisade.html \| wc -l` | **0** |
| no forms | `grep -oiF '<form' palisade.html \| wc -l` | **0** |
| no base URL | `grep -oiF '<base' palisade.html \| wc -l` | **0** |
| no dynamic handler attributes | `grep -oE 'setAttribute\(["'"'"']on' palisade.html \| wc -l` | **0** |
| the bypassable escaping idiom, removed | `grep -oF 'replace(/"/g,"&quot;")' palisade.html \| wc -l` | **0** |
| **untrusted JSON parsed unguarded** | see note below | **0** |

Five of those rows — the string-argument timers, `eval`, `new Function`, `Function(` used as a
call, and `document.write` — were **positive-controlled** against a file that deliberately
contains the thing they look for, so a typo in one of those regexes cannot masquerade as a clean
result: the same commands return `3 / 1 / 1 / 2 / 1` there and `0` here, and
`MOBILE-CODE-DETERMINATION.md` §3.2 carries that reproduction. The remaining rows were **not**
individually positive-controlled; most are fixed-string (`grep -F`) matches on a literal API
name, and a reader who wants the same assurance for one of them can build the control file the
same way.

Two rows need a sentence each rather than a bare zero, because a naive grep would mislead:

- **`JSON.parse` appears 11 times.** Ten are `JSON.parse(JSON.stringify(DEFAULT_CONFIG…))` — a
  deep clone of an in-code constant, not input. The eleventh *is* the guarded parser. Every one
  of the seven places the tool reads JSON from a file or a text box goes through `safeParse()`,
  which strips `__proto__` at the boundary (§5.2). Check with
  `grep -n 'JSON.parse(' palisade.html` and read the eleven lines; it takes a minute.
- **`.swf` matches twice under `grep -i`** and zero times without it. Both hits are `.swF`
  inside `S.settings.swFiscalYear`. There is no Flash in this file; there is a field called
  "SW Fiscal Year". This is disclosed rather than quietly suppressed because a reviewer running
  their own case-insensitive grep will hit it.

### 3.3 The non-zero rows

| Property | Count | Why |
|---|---|---|
| script elements | **1** | line 1169, `<script>` with no `src`/`type`/`nonce`; this is the block the CSP hash covers |
| inline `on*=` attributes | **1** | v2.7 had **192**. The survivor is at line 4139 — `<button onclick="window.print()">` — a string written into a *downloaded* report, tagged `/*EXPORT-ONLY-HANDLER*/` so the release tool reports it rather than hiding it. That downloaded document carries its own policy permitting the SHA-256 of exactly the 14 bytes `window.print()` |
| iframes | **1** | the report preview, `sandbox="allow-same-origin allow-modals"` — **no `allow-scripts`** |
| `data-click`/`change`/`input` attributes | **193** | the replacement for those 191 handlers: delegation through one listener per event type |
| allow-listed UI actions | **108** | a frozen `ACTIONS` object; markup can only name an action that is an own property of it |
| occurrences of `esc(` | **344** | output escaping applied at the point of use: 1 definition, 343 call sites (`grep -oE '\besc[[:space:]]*\(' palisade.html \| wc -l`) |
| `style=` attributes | **481** | `grep -oE 'style="' palisade.html \| wc -l`. Why `style-src` is still `'unsafe-inline'` — see §4. Disclosed because a reviewer will improvise the looser command: `grep -oE 'style='` returns **483**, the two extra hits being the file's own comment at line 15 (which states this figure) and one attribute written with escaped quotes, `style=\"`, at line 7083 |

---

## 4. The policy in force

Delivered as a `<meta http-equiv="Content-Security-Policy">` element. There is no server, so a
response header is impossible; `<meta>` delivery is the mechanism available to a `file://`
document, and §6 shows it enforcing.

```
default-src 'none';
script-src 'sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=';
style-src 'unsafe-inline';
img-src 'none';
font-src 'none';
connect-src 'none';
frame-src 'none';
worker-src 'none';
object-src 'none';
media-src 'none';
manifest-src 'none';
base-uri 'none';
form-action 'none'
```

Thirteen directives. **No directive names an origin, a host, or a scheme.** There is no `'self'`
and no allow-list, because there is nothing the page is permitted to load from anywhere.

### `connect-src 'none'` — read this one first

This is the directive that matters most to an accreditor, and it is why it is not buried in
alphabetical order. Palisade's central claim has always been *"it never talks to the network."*
In v2.7 that claim rested on a code review: someone read the file, found no `fetch`, and wrote it
down. That is a claim about a moment in time. It survives exactly until the next contributor adds
a feature.

`connect-src 'none'` converts it into a property the browser enforces at run time. A `fetch()`,
an `XMLHttpRequest`, a `WebSocket`, an `EventSource`, a `sendBeacon` — any of them, from anywhere
in the file, added by anyone, on purpose or by accident — is refused by the browser before a
packet exists. **The claim no longer depends on nobody ever adding a `fetch()`.** Measured live:

```
fetch("https://example.invalid")
  -> rejected TypeError: Failed to fetch
  -> securitypolicyviolation: effectiveDirective "connect-src",
     blockedURI "https://example.invalid/", disposition "enforce"
```

That is one line an assessor reads, in place of auditing 7,957.

### The rest, one line each

| Directive | Why it is set this way |
|---|---|
| `default-src 'none'` | The deny-by-default floor. Any resource type not named below inherits "nothing is permitted", so a future directive nobody thought of still fails closed. |
| `script-src 'sha256-M+Ke…'` | Exactly one script may run, identified by the digest of its bytes. Because a hash is present, the browser **ignores `'unsafe-inline'`** for script — so every injected `on*=` attribute and every injected `<script>` element is dead by policy, not by escaping discipline. No `'unsafe-eval'`, so `eval`, `new Function`, and the string forms of `setTimeout`/`setInterval` all fail the same check. |
| `style-src 'unsafe-inline'` | **The one concession, stated plainly.** The file sets 481 `style=` attributes, 102 of which carry an interpolated or concatenated runtime value (measured, not estimated). CSS cannot execute; and every channel by which CSS is normally abused to exfiltrate — `img-src`, `font-src`, `connect-src`, and external stylesheets via `default-src` — is `'none'`. Hashing the `<style>` elements (`style-src-elem`) is a known, scoped next step, not a claim made today. |
| `img-src 'none'` | The image beacon is the cheapest exfiltration channel in a `file://` page and the classic bypass for a policy that only closes `connect-src`. Closed. The file contains 0 `<img>` elements, so nothing legitimate is lost. |
| `font-src 'none'` | A remote font is a network request. The tool uses system font stacks. |
| `frame-src 'none'` | No frame may be *fetched*. The report preview uses `srcdoc`, which is materialised from the attribute rather than fetched, so it still renders. Verified on the shipped bytes under this exact policy: the preview builds (`report iframe srcdoc length: 22818`) with `CSP violations: 0` — `evidence/gate-C/RERUN-shipped-fd2f80e9/harness.txt`. The earlier feasibility probe (`evidence/csp-probe/RESULT.md`) established that a parent policy is inherited by `srcdoc`, but it ran `frame-src 'self' data:`, not `'none'`, so it is the shipped-build run that settles this directive. |
| `worker-src 'none'` | A worker is a second script context the hash would not cover. There are none, and now there can be none. |
| `object-src 'none'` | Plugin content — the Category 1 mobile-code class. Zero present; now also forbidden. |
| `media-src 'none'` | Same reasoning as `img-src`: an `<audio>`/`<video>` `src` is a network fetch. |
| `manifest-src 'none'` | A web app manifest is a fetch and an install surface. Neither is wanted. |
| `base-uri 'none'` | Stops an injected `<base>` element from re-pointing every relative reference in the document. |
| `form-action 'none'` | Stops an injected form from posting anywhere. The file contains 0 `<form>` elements. |

### What the policy does **not** cover

Stated here rather than left for a reviewer to discover:

- **Downloads.** Blob-URL downloads are not governed by CSP. Every export still works, and that
  is by design — it is how evidence leaves the tool.
- **Clipboard and printing.** `navigator.clipboard.writeText` and `window.print()` are not CSP
  surfaces.
- **A browser that ignores policy.** A defect in the browser's CSP implementation, or a build
  configured to disregard it, is outside what one HTML file can control. The deployed browser
  remains the enclave's assurance, as it is for every web application.
- **Markup sanitisation.** CSP does not remove injected elements; it stops them executing. In
  the negative test in §6, the injected `<button>` *is* created in the DOM. Its handler never
  runs. The escaping fixes in §5.1 are what stop the element being created in the first place;
  the policy is the second layer.

---

## 5. What was found, and what was done

Severities were adjudicated by two independent skeptic passes and are argued, not asserted.

> **Evidence provenance — read once, applies throughout.** The functional gate, the negative
> tests, the hostile-fixture probe and the tamper-evidence capture cited in this memo were
> **re-run against the shipped bytes** (`fd2f80e9…`) on 11 September 2026. The Block B
> behavioural measurements (CSV/TSV neutralisation, zip-bomb cap, ReDoS filter, sandbox,
> artifact CSP, package opt-in) and the export byte-diff were captured against the immediately
> prior build `376631c2…`, which differs from the shipped file only by finding R4 (§5.8) — a
> change to regex string literals, applied after that capture, after which the file was
> re-sealed. The frozen functional numbers are identical before and after. Expecting those
> Block B measurements to hold on the shipped bytes is a reasoned inference, and it is labelled
> as one here rather than presented as a measurement of the shipped build.
>
> The Chromium transcripts themselves are a review-workspace bundle; they are not in this
> repository. What *is* in this repository, and what an accreditor can re-run offline, is in
> §11: `tools/seal.mjs --verify`, `tools/csp-lint.sh`, and `baseline/harness.mjs` against a
> real `file://` URL.

### 5.1 HIGH — two renderers executed attacker-controlled text as JavaScript

**What it was.** `renderPPSM` and `renderSTIG` built each table row by pasting an object key
*raw* into a single-quoted JavaScript string inside an `on*=""` attribute. The PPSM key is
`protocol + "/" + port`, and `protocol` came verbatim from the `protocol` attribute of a
`.nessus` file (or the protocol column of a CSV). A scan export carrying a crafted protocol
value therefore closed the attribute and everything after it was parsed as markup — at the
moment the operator dropped the file in, before any click. The same sinks were reachable, with
every character preserved, through a session `.json` handed over by a colleague.

Nine further sites used an idiom that *looked* safe — `JSON.stringify(x).replace(/"/g,"&quot;")`
— and is bypassed by a value containing the literal six characters `&quot;`.

**Impact in this deployment: evidence-integrity tampering, not exfiltration.** There is no
egress. Script running in this page cannot send anything anywhere. What it *can* do is silently
alter the artifact the tool exists to produce: flip a STIG applicability mark, change a PPSM row,
edit a POA&M line, adjust an eMASS baseline — in a package an AO will rely on. That is the
honest claim and it is the more serious one. Do not read "XSS" here and think "data theft."

**Measured, before.** Pristine v2.7 against the hostile fixtures, real Chromium, real `file://`
(`baseline/out-A/hostile-probe-NEGATIVE-CONTROL-pristine.txt`):

```
hostile.nessus            -> document.title becomes "pwned";  16 injected <img>;  window.__pwned set
hostile-session-xss.json  -> document.title becomes "PWNED";  14 injected <img>;  window.__pwned set
                          ==> CANARY FIRED (FAIL) on 2 of 4 fixtures
```

**Measured, after** — shipped build, `evidence/gate-C/RERUN-shipped-fd2f80e9/hostile-fixtures.txt`:

```
all four fixtures         -> titleUnchanged true;  injected <img> 0;  window.__pwned undefined
                             csp violations []     ==> CANARY DID NOT FIRE (pass)
HOSTILE PROBE: PASS
```

**What changed.** Keys now travel as `esc()`-escaped `data-key` / `data-arg` attributes and are
read back from the DOM as strings — one decode, no code context. The bypassable idiom is gone
from the file (`grep -oF 'replace(/"/g,"&quot;")' palisade.html | wc -l` → **0**). All 191 live
inline handlers were converted to delegated `data-*` dispatch, and the CSP hash makes any handler
attribute that hostile data manages to create inert anyway. The dispatcher additionally checks
each key with `Object.prototype.hasOwnProperty` before writing, so a row keyed `__proto__` cannot
reach a prototype through the UI either.

### 5.2 MEDIUM-HIGH — global `Object.prototype` pollution from a crafted session, baseline, profile or trend file

This finding was **dismissed by two skeptic passes and was wrong to dismiss**. It is real, it was
reproduced independently before action, and it is fixed. It is recorded here, in findings, and
deliberately **not** in the refuted list in §8.

**Mechanism.** `JSON.parse` creates a genuine *own* `__proto__` data property — it does not go
through the setter. `buildAssets` enumerates its input with `for..in`, which sees that key. The
subsequent *read* of `S.assets["__proto__"]` goes through the prototype getter and returns
`Object.prototype`, which is truthy — so the code took the "already exists, refresh it" branch
and wrote `fromScan`, `ip`, `os`, `lastSeen`, `type` onto `Object.prototype` itself. For every
object in the page, for the rest of the session.

**Why it is an evidence finding, not a crash.** `buildAssets`' second loop marks an asset as *not
seen by this cycle's scan* with a test of the form `S.assets[k].fromScan === undefined`. Once
every object in the program inherits `fromScan === true`, that test never fires again. The
scan-detected versus inventory-only distinction silently inverts — and it feeds the asset
inventory, the reconciliation view, and the readiness meter. No error, no warning, nothing to
notice. For an evidence compiler that is the worst available failure mode.

Note also that restoring `S` from a backup does **not** undo it: the prototype write outlives the
state object.

**Measured, before / after** (`evidence/gate-B/verify-B.txt` §8, and `notes/router-findings.md`):

```
pristine  : Object.prototype gains ["fromScan","type"];   ({}).fromScan === true
hardened  : Object.prototype own props 12 before, 12 after;  polluted keys []
            ({}).fromScan undefined   ({}).ip undefined   ({}).os undefined
            prior dataset intact after the refusal: hosts=6, ppsm=19 stig=8 sw=24 asset=9
```

**What changed.** One choke point rather than twenty-five guards: `safeParse()`, a `JSON.parse`
reviver that drops any `__proto__` key, routed at all seven places the tool reads untrusted JSON
(session, baseline, profile, trend ingest, approvals import, the detection-config box, the
`.cklb` sniff). Zero raw `JSON.parse` on file or user input now remains (§3.2). This was chosen
over guarding each `for..in` because it is one reviewable line that a future renderer cannot
forget to apply.

### 5.3 MEDIUM — spreadsheet formula / DDE injection in every CSV and TSV export

**What it was.** A cell beginning `=`, `@`, TAB or CR is treated as a formula by Excel and
LibreOffice — including DDE, `WEBSERVICE` and `HYPERLINK`. A hostname, software DisplayName or
enumerated account name from a scan reaches those cells verbatim.

**Why this one matters more than it looks.** It does not fire on the air-gapped workstation. It
fires on the **assessor's networked machine**, when they open the evidence you sent them. That is
precisely where the air gap ends, and it is the one path by which this tool could contribute to
an incident on a network it never touched.

**Why it stays MEDIUM and not HIGH.** It requires the recipient to open the file and, in a modern
Excel, to accept a prompt; and the consequence lands on the recipient's machine, not on the
assessed system. Argued down, not up.

**Measured** (`evidence/gate-B/verify-B.txt` §1):

```
hostile.csv               : 19 exports captured; 43 cells neutralised;  0 cells left live
hostile-session-xss.json  : 19 exports captured; 27 cells neutralised;  0 cells left live
numeric controls -5, +5, -5%  : bare=6/6/6, apostrophe-prefixed=0/0/0  (type preserved)
```

**What changed.** One neutraliser at the two choke points: `csvq`, used at 27 call sites across
the CSV exports, and `tsvSafe` for the tab-delimited PPSM registry `.txt`
(`grep -oF 'csvq' palisade.html | wc -l` → 28: one definition at line 7226 and 27 uses). Leading `=`, `@`, TAB and CR are always prefixed with an
apostrophe; a leading `+` or `-` only when what follows is not a plain number, so `-5`, `+5` and
`-5%` keep their numeric type and numeric columns still sum.

**Disclosed behaviour change:** an affected cell shows a visible apostrophe on CSV import. Excel
does *not* hide it the way it hides a typed-in leading quote. That is deliberate — a value that
needed neutralising is worth seeing, and it is the honest rendering of a hostile hostname.

**Disclosed cosmetic consequence:** the Account Audit export contains tool-authored divider rows
such as `--- by user: which machines each account appears on ---`. They begin with a hyphen
followed by non-numeric text, so the rule prefixes them too. Correct per the rule as written,
harmless, and visible.

### 5.4 MEDIUM — decompression bomb: uncapped inflate

**What it was.** `zipOpen().read()` inflated a deflate stream straight into memory with no cap. A
few hundred KB of crafted `.xlsx` or SCC `.zip` expands without bound.

**Measured** (`evidence/gate-B/verify-B.txt` §2):

```
pristine v2.7 + bomb.xlsx (327,780 bytes) : peak RSS delta 2,573.0 MiB, 1,777 ms,
                                            parse-warning banner EMPTY — a silent success
hardened v2.8 + bomb.xlsx                 : peak RSS delta   329.8 MiB,   437 ms, refused by name:
  "bomb.xlsx: parse error — xl/worksheets/sheet1.xml: inflated size exceeds the tool's limit
   (256 MiB per entry, 768 MiB per archive) - possible decompression bomb"
                                            tab still responsive: 18 tabs clicked, 52 ms round trip
hardened v2.8 + bomb.zip                  : peak RSS delta   304.5 MiB,   429 ms, same refusal shape
```

A **7.8×** reduction in peak memory, and — more important than the number — the difference
between a silent success and a named refusal the operator can read.

**Realistic magnitude, stated honestly.** One deflate-raw stream cannot exceed roughly 1032:1, so
the ceiling on this class is about 4 MB compressed to 4 GB. The "40 KB to 4 GB" figure that
circulates for this class is not achievable in a single stream and is not claimed here.

**Not a regression for real data:** a legitimate 1,048,576-row worksheet is above the caps'
concern and still ingests in full — measured, 200,000 rows in 7,454 ms with an empty warning
banner, identical row count to the pristine build (`verify-B.txt` §3 and supplementary C1).

### 5.5 MEDIUM — unbounded ingestion

No input bound existed anywhere: no file-size check before `f.text()`/`f.arrayBuffer()`, no row
cap on worksheet extraction, no cap on CSV or `.nessus` parsing. Worst realistic case is a hung
or OOM-killed tab and a lost working session — local denial of service, no code execution.

Named, frozen limits now exist and every breach surfaces in the parse-warning banner:

```js
INPUT_FILE_BYTES      1 GiB       // checked BEFORE the file is materialised
INFLATE_ENTRY_BYTES   256 MiB
INFLATE_ARCHIVE_BYTES 768 MiB
SHEET_ROWS            1,048,576   // Excel's own maximum; never truncates a legal worksheet
REGEX_SOURCE_CHARS    512
```

These are stated operating bounds, not exploit mitigations, except on the inflate path where
amplification is real.

### 5.6 MEDIUM — ReDoS via a config-supplied regular expression, and the partial control adopted

A detection profile or config JSON can supply regex patterns that are compiled and run against
scan-derived text. A catastrophic pattern hangs the tab.

**The control is static rejection at construction, and it is partial. That is stated, not
softened.** It catches the classic nested-quantifier class. It does **not** catch adjacent-overlap
forms (`a*a*$`) or alternation overlap (`(a|ab)*`), and those were deliberately kept in the
fixture as *accepted* controls so the transcript shows the limit rather than hiding it. Two
alternatives were tried and rejected: subject-length bounding gives nothing (an exponential
pattern hangs at ~30 characters), and a Web Worker timeout is unreliable from `file://` in
Chromium. Synchronous regex in a `file://` page cannot be time-bounded portably, so static
rejection is what is available.

**Measured** (`verify-B.txt` §4): all **32** built-in `re:` patterns accepted (requirement: zero
false rejections); **6** hostile patterns rejected from `redos-profile.json`, named to the
operator in the status line — `re:(a+)+$`, `re:(a*)*b`, `re:(\d+)+x`, `re:((ab)+)+$`, and two
more; profile load 10 ms; detection re-run over the bait host 0 ms.

### 5.7 MEDIUM / LOW — the remaining four

| Finding | What changed | Measured |
|---|---|---|
| Report-preview iframe was unsandboxed and same-origin while receiving scan-derived HTML | `sandbox="allow-same-origin allow-modals"` — no `allow-scripts`, so the frame cannot run script or remove its own sandbox; parent policy is inherited too | 0 elements with any `on*` attribute in the rendered preview; 0 `<script>` tags; a script injected into that frame did not execute (`verify-B.txt` §5) |
| Exported HTML artifacts carried no policy | each generated document now carries its own CSP | all 3 artifact types checked: assessment report, leadership report, package `index.html` — each `default-src 'none'`, 0 `<script>` tags (`verify-B.txt` §6) |
| The evidence `.zip` bundled the complete session JSON — every host, IP, software row and enumerated account with RID, groups and admin flags — by default | now an opt-in checkbox, default **off**, with a caveat sentence in `index.html` either way | box unticked → 22 entries, 0 `Palisade_Session_*`; ticked → 23 entries, 1, and the matching caveat text present (`verify-B.txt` §7). **This is a deliberate default change** and is called out in `CHANGELOG.md` |
| Saved sessions were stamped `ver:"2.6"` in a v2.7 build — the artifact misstated what produced it | corrected, and version consistency is now enforced by the release tool across all four sites that carry it | `seal.mjs --verify` → "version consistent at v2.8 across all 4 sites" |

### 5.8 Repository and correctness findings (outside the security lenses)

**R1 — the CUI-protection ignore file was inert.** The repo shipped `gitignore.txt`. Git reads
only `.gitignore`. Every rule in it was dead text, including the block headed "CUI PROTECTION —
do not remove or loosen these rules" covering `*.nessus`, `session*.json`, `*.ckl`, `*XCCDF*.xml`
and `Results_*.zip` — while `CONTRIBUTING.md` told contributors the file covered them. A
contributor running `git add .` would have committed real enclave scan data to a public
repository.

Renamed and proven live (`evidence/gate-C/07-repo-hygiene.txt`):

```
git check-ignore -v test.nessus   ->  .gitignore:10:*.nessus	test.nessus
```

and history was checked: `git log --all --name-only -- '*.nessus' '*Session*.json' '*.ckl'`
returns **0** matches. Nothing of that shape was ever committed. The control was missing, not
breached.

**R4 — 18 of the 20 built-in product aliases carried a backslash defect that stopped them matching.** Not a security defect; an
evidence-completeness one, which in an evidence compiler is the product. The alias patterns were
written as double-quoted JavaScript string literals containing *single* backslashes, so
`"re:^(google[\s-]*)?chrome"` reached `RegExp` as `^(google[s-]*)?chrome` — which cannot match
"Google Chrome", because after "google" it accepts only the letter `s` or a hyphen, never a
space. `\b` was worse: it became U+0008 BACKSPACE, so `(java|jre|jdk)\b` could never match.

Two numbers, because two different things were counted and a reader who checks will find both.
**18 of the 20** alias patterns contain a backslash escape and were therefore affected; the other
two — `^(chromium)` and `^openssl` — contain no backslash and were never broken
(`grep -A22 'productAliases:\[' palisade.html`). Separately, measured in the page on the pristine
build against the product names the aliases are declared for, **17 of 20** failed to match
(`baseline/probe-aliases.mjs`, reported at `verify-B.txt` supplementary C6). On a 9-probe
representative set: before, 1 matched and 8 failed; after, 8 matched and 1 failed. That remaining
non-match is correct — it is the Adobe *Reader* alias tested against "Adobe Acrobat Reader DC",
which the *Acrobat* alias above it already claims. In the shipped file all 18 affected patterns
now carry doubled escapes.

**Operator-visible behaviour change:** the Software Summary will now consolidate product names it
previously listed separately, so counts in that view will **drop** for environments carrying
several scanner spellings of one product. That is the corrected number, not a lost one. A CM-8
software inventory built with v2.7 over-counted distinct products.

---

## 6. Negative tests — the transcript

Run against the shipped bytes, real Chromium 150.0.7871.181, real `file://`, CDP driver, with
`Page.setBypassCSP` never sent. Full transcript:
`evidence/gate-C/RERUN-shipped-fd2f80e9/negative-tests.txt`.

The app was verified healthy before the tests began — `{"scriptRan":true,"violationsSoFar":0}` —
because a dead page would "pass" every refusal test below.

| # | Attack primitive | Browser's response | Canary |
|---|---|---|---|
| 1 | `insertAdjacentHTML` a `<button onclick="document.title=1">`, then click it | **refused** — `script-src-attr`, `blockedURI: inline`, `disposition: enforce` | `document.title` unchanged |
| 2 | `eval("1")` typed at an **attached debugger** | **NOT refused** — returns `1`, 0 violations. See the note below. | unchanged |
| 3 | `setTimeout("window.__evalCanary=1", 0)` — the same compiler reached from a call site *inside* the page | **refused** — `script-src`, `blockedURI: eval` | `window.__evalCanary` still `undefined` after 300 ms |
| 4 | `fetch("https://example.invalid")` | **refused** — `connect-src`; call rejected `TypeError: Failed to fetch` | unchanged |
| 5 | `new Image().src = "https://example.invalid/x"` | **refused** — `img-src` | unchanged |
| 6 | inject a `<script>` element carrying `window.__pwned=1; document.title="PWNED"` | **refused** — `script-src-elem`, `blockedURI: inline`; element is in the DOM, its bytes never run | `window.__pwned` `undefined` |

After all six, the page was still fully functional and loaded the demo dataset normally:
`{"demoClick":1,"hosts":6,"ppsmRows":19,"title":"Palisade v2.8"}`. That final step is what makes
the six refusals mean anything.

**Test 2 is reported rather than dropped, and it is important to read it correctly.** Chromium
deliberately exempts debugger-originated evaluation from CSP so that a page with a strict policy
remains debuggable. That result measures the debugger, not the policy — no violation fires because
the browser did not apply the check. An attacker supplies hostile *bytes* (a scan file, a session
file, a hostname), not an attached DevTools session; test 3 reaches the same compiler the way
hostile bytes would, and it is refused with `blockedURI: eval`. An assessor re-running the manual
check list will see exactly this, and needs to know it is expected.

In all six cases the app's own violation handler also logged the refusal and surfaced it in the
status bar, e.g. `CSP blocked connect-src (https://example.invalid/) line 1` — so an operator
sees a policy refusal without opening DevTools.

**Tamper evidence** (`evidence/gate-C/RERUN-shipped-fd2f80e9/tamper-evidence.txt`). One byte was
changed at offset 83048 — `a` → `X` — **inside a comment**. No statement in the program changed.

```
sealed    : script ran = true   demo load -> hosts = 6, PPSM rows = 19
tampered  : script ran = false  demo load -> "S is not defined", PPSM rows = 0
            DOM nodes 782, stylesheet applied, 0 table cells filled
browser   : Executing inline script violates the following Content Security Policy directive
            'script-src 'sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=''. …
            The action has been blocked.
```

The browser names the expected hash in its own refusal, so an operator can compare it to the
`inlineScriptBlocks[0].sha256` value in `MANIFEST.json` — the same base64, minus the `sha256-`
prefix — with no Palisade-specific tooling. The seal does not judge whether a change was
harmful — the edit demonstrated here was inert, and was still refused. The cost of this property
is a discipline the release process carries: **any** edit to the script, whitespace included,
requires a re-seal before the file works at all.

---

## 7. Behaviour was proven unchanged

Hardening that quietly changes output is worse than no hardening, because the evidence stops
matching last cycle's. A frozen functional baseline is re-run after every change, headless, on a
real `file://` URL.

Against the shipped bytes (`evidence/gate-C/RERUN-shipped-fd2f80e9/harness.txt`):

```
VERDICT: PASS
  zeroErrors · zeroCsp · inlineHandlerFired · generatedHandlerFired · hosts6
  coreTablesPopulated · meterComputed · allTabsClean · reportBuilt
hosts: 6   intelRows: 6   listingFiles: 1
meter: 21% (6 of 28 checks pass)
core table <tr> counts: ppsm=19 stig=8 sw=24 asset=9
report iframe srcdoc length: 22818
console errors: 0   cdp exceptions: 0   window.onerror: 0   CSP violations: 0
```

and the frozen-number diff against the reference captured before any hardening began produced
**no output** — identical.

The exports were byte-compared too: 19 of 19 CSV/TSV artifacts byte-for-byte identical between
the build immediately before the policy was locked and the sealed build
(`evidence/gate-C/06b-export-bytediff.txt`). That comparison is labelled honestly in its own
transcript: the reference set the ledger originally specified was never created, so the
comparison run is the one that actually isolates the sealing change.

---

## 8. Refuted — investigated and dismissed, with the evidence that killed each lane

This section is the one that shows the review was adversarial rather than a list of everything
imaginable. Each item below was a live hypothesis that was chased and closed.

**Parsers and memory safety**

- **Malicious zip `csize` / `offset` / entry-count fields.** `Uint8Array.subarray` clamps
  out-of-range views; `DataView` reads past the buffer throw `RangeError` into handlers that are
  already catching; the end-of-central-directory back-scan never runs on a sub-22-byte buffer;
  the entry count is a uint16 and the loop breaks on the first bad signature. Worst case is a
  clean error message.
- **`__proto__` or `constructor` as a *zip entry name*.** Affects the local `entries` object's
  prototype only and never reaches `Object.prototype`; `Object.keys` omits it; entry names are
  only ever object keys, regex-matched, or `split("/").pop()`'d. A `file://` page cannot write to
  disk, so path traversal is unreachable. *(Distinct from §5.2, which was a different mechanism
  in a different function, and which is real.)*
- **XXE and billion-laughs.** Browser `DOMParser` in `text/xml` mode resolves no external
  entities, and there is no network to reach if it did. Internal entity expansion is bounded by
  the browser, not by this code. The realistic XML failure mode is size — i.e. tab denial of
  service — which is §5.5.
- **`noisePatterns` and the EOL `match` field as ReDoS sinks.** The first uses plain
  `.includes()`; the second is a hardcoded developer constant, not operator config. The ReDoS
  lane stands only on `catalog.patterns` / `osPatterns` and `productAliases`.
- **"40 KB inflating to 4 GB."** Not achievable in one deflate stream (~1032:1 ceiling). The
  corrected figures are in §5.4.
- **The CSV sniff consumers.** Already bounded at 32,768 bytes and 15 rows. Only the full
  parser and the two ingesters were uncapped.

**Sinks and escaping**

- **`esc()`'s five-character alphabet as the defect.** Adequate for the quoted-attribute and text
  contexts where it is used. No attacker-controlled data reaches a URL, scheme or CSS context.
  The defect in §5.1 was `esc()`'s *absence* in a JavaScript-string context — the wrong control
  for the context — not a weakness in its alphabet.
- **`loadBaseline` and `ingestTrendSessions` as live injection vectors.** Both restore the prior
  state object before any render. Verified by reading both functions end to end. Only
  `loadSession` renders attacker-supplied keys.
- **Tenable-authored plugin name and remediation text as the formula-injection vector.** Those
  fields come from the scanner, not the scanned host. The lane stands on hostnames, product
  names, account names and group names. They are all neutralised uniformly regardless.
- **The 20 report section builders and the `rpt*` helpers as live injection.** All twenty were
  traced; every scan-derived value is escaped before it reaches the report. The unsandboxed
  preview and the raw-cell helpers were defence-in-depth gaps — now closed (§5.7) — not live
  injection.
- **Handlers keyed by in-code constants** (column definition lists, view ids, help topics,
  settings field names). Not injectable; they come from constant arrays in the file.

**Downloads, packaging, navigation**

- **Download-filename injection.** Every CSV filename is a fixed template; the two
  operator-influenced names are sanitised to `[A-Za-z0-9_]`.
- **Zip path traversal, NUL or CRLF in entry names.** Every entry name is a fixed folder plus a
  fixed filename; no hostname or ingested filename reaches one. Entry-name sanitisation was added
  anyway, to keep that property true if a future export ever derives a name from data — it fixes
  no live bug and is not claimed as one.
- **`frame-src 'none'` breaking the report preview.** `srcdoc` frames render under it because
  they are materialised from the attribute, not fetched. Confirmed on the shipped bytes —
  preview built, srcdoc 22,818 chars, 0 CSP violations
  (`evidence/gate-C/RERUN-shipped-fd2f80e9/harness.txt`). The pre-adoption probe
  (`evidence/csp-probe/RESULT.md`) ran `frame-src 'self' data:`, so it is that run, not the
  probe, which settles the `'none'` case.
- **`sandbox=""` for the preview.** Would have been stricter and was rejected for a measured
  reason: with it, the parent's `contentDocument` is `null` and `contentWindow.print` throws, so
  the print button becomes impossible. `allow-same-origin allow-modals` without `allow-scripts`
  keeps printing and still blocks script.
- **CSP as a control over downloads, clipboard or printing.** It is not, and nobody should claim
  it is. Stated in §4.

**Policy and compliance claims**

- **DoDIN APL.** Not applicable. APL covers UC network infrastructure, and an APL listing is not
  an RMF authorization. Palisade is assessed as application software / active content inside the
  existing workstation and enclave boundary.
- **A special review because it is open-source software.** Not required. OSS is commercial
  computer software and receives the same assessment as any other software.
- **The CISA Secure Software Development Attestation Form.** Not required for freely obtained
  open-source software under OMB M-23-16. A voluntary SSDF practice map can be provided as
  evidence of practice; a *filing* must never be claimed, and none is claimed here.
- **`'self'` in the policy.** Unreliable on `file:` and unnecessary — the policy names no origin,
  host or scheme from which anything may load.
- **Nonces.** A nonce constant in a static public file degrades to `'unsafe-inline'`. Rejected.
- **`'unsafe-hashes'` for the app's own handlers.** Would have re-opened the attribute channel
  across an unbounded set of handler bodies. Used only in the *exported report*, for the single
  14-byte statement `window.print()`, whose hash was independently recomputed:
  `printf 'window.print()' | openssl dgst -sha256 -binary | base64` →
  `MguIPR6qNR8D3B+eAlK+bIRTZe8t3wkOY4B/56Me9FU=`, identical to the hash in that document's
  policy.

**Severity decisions argued down**

- CSV formula injection stays **MEDIUM**, not high: recipient interaction is required and the
  consequence lands on the recipient's machine.
- The injection sinks stay **HIGH**, not critical: there is no egress in this deployment, so the
  impact is evidence-integrity tampering. Naming that accurately is worth more than inflating it.

---

## 9. Residual risk

What an assessor should carry forward, rather than a claim that nothing remains.

1. **`style-src 'unsafe-inline'`.** The one relaxation in the policy. 481 `style=` attributes,
   102 of them carrying runtime values. CSS cannot execute, and every channel by which
   injected CSS normally exfiltrates is `'none'` — but this is a real gap, not a rhetorical one.
   Hashing the `<style>` elements is a scoped next step.
2. **ReDoS rejection is partial** (§5.6) and catches one class only. The realistic consequence of
   a miss is a hung tab, not code execution, and it requires the operator to load a config or
   profile file from an untrusted source.
3. **The browser is the trusted computing base.** Everything in §4 and §6 depends on the deployed
   browser enforcing CSP correctly. Confirm the deployed build; and, if the exported report's
   print button matters on Firefox ESR, confirm `'unsafe-hashes'` support there before relying
   on it.
4. **The seal is only as good as the discipline.** Any edit to the script requires a re-seal.
   The failure mode is loud (the page goes inert) rather than silent, which is the right way
   round, but it is an operational commitment.
5. **Report cells still accept markup from a small number of call sites by design** (tags,
   scope badges, styled spans). All twenty builders are verified escaped today and the report is
   contained by CSP in both the preview and the export, so this is hardening not yet done rather
   than a live defect — but it is the next thing a hostile reviewer should look at.
6. **Block B measurements were captured against the immediately prior build** (see the provenance
   note in §5). Re-running `baseline/verify-B.mjs` against the shipped bytes would close that gap
   entirely and costs one command.

---

## 10. What this assessment does **not** claim

Stated explicitly, because a package that overclaims once is discounted entirely.

- **Not** a CISA Secure Software Development Attestation Form filing. None was filed, and none is
  required for freely obtained open-source software under OMB M-23-16.
- **Not** code signing of the `.html` in any form a browser verifies. No such mechanism exists
  for an HTML document. The CSP hash is tamper *evidence*; the manifest is the integrity control.
- **Not** a reproducible, hermetic, or SLSA-attested build. **There is no build at all.** That is
  the architectural point of §2 and it cuts both ways: nothing to reproduce, and therefore no
  build attestation to offer.
- **Not** a WCAG conformance claim. Accessibility is outside this memo's scope entirely; it is
  covered separately in `docs/ACCESSIBILITY-CONFORMANCE-REPORT.md`, which reports per criterion
  — including criteria marked *Partially Supports* and *Does Not Support* — rather than claiming
  conformance. No overall "Supports" conformance claim is made anywhere in this package.
- **Not** a DoDIN APL listing, and not a suggestion that one applies. APL covers UC network
  infrastructure; it is not an RMF authorization.
- **Not** a claim about any ASD STIG requirement other than **APSC-DV-002490** (XSS, CAT I) and
  **APSC-DV-002480** (CAT II), and **not** a claim that those two were read from the current
  release. Both IDs and both severities must be validated against the release your program is
  assessed under before anything goes into eMASS. No requirement text is quoted anywhere in this
  package.
- **Not** a claim that the tool is free of defects. It is a claim that a specific adversarial
  review was performed, that what it found is listed above with measurements, and that what it
  dismissed is listed in §8 with the reasoning.
- **Not** a claim about the browser, the operating system, the USB medium, or the operator.
- **Not** a penetration test, and not a formal source-code audit by an independent third party.
  It is a co-author's adversarial review, with the evidence needed for someone else to check it.

---

## 11. Verify every claim in this memo yourself

This section is what turns the memo from assertion into evidence. Nothing below requires anything
Palisade ships except in the rows that say so.

### 11.1 Identity — 10 seconds

```bash
cd Palisade
sha256sum palisade.html
# expect fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97
wc -c < palisade.html          # expect 521771
```

### 11.2 The script really is the script the policy names — independent of Palisade's own tooling

```bash
python3 - <<'EOF'
import hashlib, base64, re
b = open('palisade.html','rb').read()
assert b.count(b'\r') == 0 and b[:3] != b'\xef\xbb\xbf', "CRLF or BOM drift"
assert b.count(b'<script>') == 1 and b.count(b'</script>') == 1, "more than one script block"
i = b.index(b'<script>') + 8; j = b.index(b'</script>')
print("script bytes :", j - i)
print("computed     : sha256-" + base64.b64encode(hashlib.sha256(b[i:j]).digest()).decode())
print("in the policy:", re.search(rb"script-src '([^']*)'", b).group(1).decode())
EOF
# both hash lines must print sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=
```

### 11.3 The measured zeros — one paste

```bash
F=palisade.html
for p in fetch\( XMLHttpRequest WebSocket sendBeacon EventSource localStorage \
         sessionStorage indexedDB document.cookie ActiveXObject WebAssembly; do
  printf '%-22s %s\n' "$p" "$(grep -oF "$p" $F | wc -l)"
done
printf '%-22s %s\n' 'http(s)://'   "$(grep -oE 'https?://' $F | wc -l)"
printf '%-22s %s\n' 'eval('        "$(grep -oE '\beval[[:space:]]*\(' $F | wc -l)"
printf '%-22s %s\n' 'Function('    "$(grep -oE '[^a-zA-Z0-9_$.]Function[[:space:]]*\(' $F | wc -l)"
printf '%-22s %s\n' 'document.write' "$(grep -oE 'document[[:space:]]*\.[[:space:]]*write' $F | wc -l)"
printf '%-22s %s\n' 'inline on*='  "$(grep -oE ' on[a-z]+="' $F | wc -l)"   # 1, the export-only one
printf '%-22s %s\n' '<script'      "$(grep -oiF '<script' $F | wc -l)"      # 1
printf '%-22s %s\n' 'data-* actions' "$(grep -oE 'data-(click|change|input)=' $F | wc -l)"  # 193
```

Everything must be **0** except the three annotated rows. Then read the one surviving handler and
satisfy yourself it only ever reaches a downloaded file:

```bash
grep -n ' on[a-z]*="' palisade.html
# 4139:  +(preview?"":'<div class="pbar noprint"><button onclick="window.print()">…') /*EXPORT-ONLY-HANDLER*/
```

### 11.4 Read the policy out of the file rather than out of this memo

```bash
grep -o '<meta http-equiv="Content-Security-Policy"[^>]*>' palisade.html | tr ';' '\n'
```

That prints **three** policies. The first is the app's own, quoted in full in §4. The other two
are string literals — note the backslash-escaped quotes — that the tool *writes into* two of the
documents it exports: the leadership report (line 3444) and the package `index.html` (line 4343).

A **fourth** policy, the assessment report's, is at line 4133 and does **not** appear in that
output: its literal is split across two source lines, and `[^>]*>` stops at the line end. It is
the only one of the four carrying `'unsafe-hashes'`, so read it directly rather than assume the
grep showed it to you:

```bash
sed -n '4133,4134p' palisade.html
```

Those three exported policies are §5.7, and they are why a downloaded Palisade artifact is inert
on the assessor's machine too.

### 11.5 Watch the seal fail

Copy the file, change one byte anywhere inside the script block — a letter in a comment is
enough — open the copy in the deployed browser, and look at the console. The page will draw
completely and run nothing, and the console will name the expected hash.

### 11.6 Watch the policy refuse things

Open `palisade.html`, open DevTools, and paste each of these into the console. Note that `eval`
typed *here* is exempt by design (§6, test 2) — use the `setTimeout` form for the honest test:

```js
fetch("https://example.invalid")                            // connect-src  — refused
new Image().src = "https://example.invalid/x"               // img-src      — refused
setTimeout("window.__x=1", 0)                               // script-src (eval) — refused
document.body.insertAdjacentHTML("beforeend",
  '<button id="z" onclick="document.title=1">x</button>');
document.getElementById("z").click()                        // script-src-attr — refused
```

The app's status bar should name each refusal as it happens.

### 11.7 Run the gate

These three commands run from the repository root. They are the checks CI runs, and they are
the checks an accreditor can re-run on an air-gapped box against the file in this tree.

```bash
cd /path/to/Palisade          # the repository root; palisade.html is here
node tools/seal.mjs palisade.html --verify                 # PASS, exit 0
bash  tools/csp-lint.sh palisade.html                      # PASS, exit 0
node  baseline/harness.mjs "file://$PWD/palisade.html" ./gate
node  baseline/check-frozen.mjs ./gate/result.json baseline/FROZEN-BASELINE.txt
```

The hostile-fixture probe and the six negative-test primitives used during review are **not**
in this repository: they need working exploit payloads, which this tree does not ship. Their
results are summarised in §5 and §6; reproducing them requires the separate review bundle.

### 11.8 What was captured, and what ships

The review workspace next to this repository holds the Chromium transcripts (functional gate,
negative tests, hostile fixtures before and after, tamper evidence, CSV/bomb/ReDoS/sandbox
measurements, export byte-diff, repo-hygiene proof). They are not published here, on purpose:
several of them embed local paths from the machine that ran them, and the hostile fixtures
are working exploits against v2.7.

What an accreditor can verify from this repository, without that bundle, is in §11.4–§11.7:
the file's own hashes, the script-src seal, the CSP-surface lint, and the 18-tab functional
gate against the frozen demo numbers.

---

*Palisade v2.8 · MIT Licence · Gavin Lee Domingo Johnson, Jacob Keith ·
`fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` ·
companion: `docs/MOBILE-CODE-DETERMINATION.md`*
