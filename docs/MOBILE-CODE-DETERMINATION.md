# Mobile Code Determination — Palisade v2.8

**Prepared for:** the ISSM / ISSO reviewing Palisade for use on a NIPRNet or air-gapped
assessment workstation.
**Prepared by:** Jacob Keith (co-author), 11 September 2026.
**Subject:** whether the active content in `palisade.html` is permitted, and under what
conditions.

---

## 1. The objection this answers

> "That is an HTML file with JavaScript in it."

Correct. It is. This document establishes three things, each one re-runnable by the reader
against the shipped file in under a minute:

1. The **only** active content in the file is client-side JavaScript. There is no ActiveX,
   no Java applet, no `<object>`/`<embed>`, no Flash, no WebAssembly, no worker, and no
   string-to-code compiler (`eval`, `new Function`, `document.write`, string-argument timers).
2. Client-side JavaScript is **Category 3** mobile code under DoD mobile code policy, which
   is the category that may be used **without a signature**.
3. In this deployment the file is **not transmitted from a server and auto-executed** — it is
   a local copy the operator already holds and opens deliberately from `file://`. The residual
   control is therefore *integrity of the local copy*, and that control is provided twice:
   by a SHA-256 manifest, and — more strongly, because it requires no cooperation from the
   person opening the file — by a **CSP script-hash seal** that makes a tampered copy inert.

Nothing below is asserted from reading source. Every number is the output of a command
printed next to it, run against the shipped bytes — with one exception, a behavioural
measurement carried over from the immediately prior build, which is labelled as such where it
appears (§3.5).

---

## 2. The artifact this determination covers

| | |
|---|---|
| file | `palisade.html` |
| version | 2.8 |
| bytes | 521,771 |
| sha256 | `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` |
| sha384 | `40c8ee517b7a7bf15a686f1231cdb039f9a94570f681dec25afd68f44816131fd9003d42c8de24e3915353c72928612f` |
| inline script blocks | 1, of 438,777 bytes, `sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=` |
| line endings / BOM | LF only / none |
| licence | MIT |
| authors | Gavin Lee Domingo Johnson, Jacob Keith |

This determination covers **that byte string and no other**. If the file in front of you
hashes differently, this document does not describe it — and, as section 6 shows, it will
not run either.

---

## 3. Active-content inventory (measured)

All commands run from the directory containing `palisade.html`. `grep -o … | wc -l` counts
**occurrences**, not lines; `-F` is a fixed-string match; `-i` is case-insensitive. Re-run
any row and you should get the number in the right-hand column.

### 3.1 Category 1 and Category 2 classes — none present

| Command | Count |
|---|---|
| `grep -oiF '<applet' palisade.html \| wc -l` | **0** |
| `grep -oiF '<object' palisade.html \| wc -l` | **0** |
| `grep -oiF '<embed' palisade.html \| wc -l` | **0** |
| `grep -oF 'ActiveXObject' palisade.html \| wc -l` | **0** |
| `grep -oiF 'classid' palisade.html \| wc -l` | **0** |
| `grep -oiF 'codebase=' palisade.html \| wc -l` | **0** |
| `grep -oF '.swf' palisade.html \| wc -l` | **0** |
| `grep -oiF 'application/x-shockwave' palisade.html \| wc -l` | **0** |
| `grep -oiF 'application/java' palisade.html \| wc -l` | **0** |
| `grep -oF 'WebAssembly' palisade.html \| wc -l` | **0** |
| `grep -oF 'importScripts' palisade.html \| wc -l` | **0** |
| `grep -oEi 'new[[:space:]]+(Shared)?Worker' palisade.html \| wc -l` | **0** |
| `grep -oiF 'serviceWorker' palisade.html \| wc -l` | **0** |

> **One measurement caveat, disclosed because it is the kind of thing that discredits a
> package when a reviewer finds it themselves.** The `.swf` row is deliberately
> **case-sensitive**. `grep -oiF '.swf'` returns **2**, and both hits are the substring
> `.swF` inside `S.settings.swFiscalYear`. There is no Flash object in this file; there is a
> field called "SW Fiscal Year". See both hits in context with
> `grep -oiE '.{20}\.swf.{20}' palisade.html`, which prints:
>
> ```
>        fy:S.settings.swFiscalYear, popEnd:S.
>        fy:S.settings.swFiscalYear, popEnd:S.
> ```

### 3.2 String-to-code compilers — none present

| Command | Count |
|---|---|
| `grep -oE '\beval[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| `grep -oE '\bnew[[:space:]]+Function[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| `grep -oE '[^a-zA-Z0-9_$.]Function[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| `grep -oE 'document[[:space:]]*\.[[:space:]]*write' palisade.html \| wc -l` | **0** |
| ``grep -oE 'set(Timeout\|Interval)[[:space:]]*\([[:space:]]*["'"'"'`]' palisade.html \| wc -l`` | **0** |
| `grep -oiF 'javascript:' palisade.html \| wc -l` | **0** |
| `grep -oEi 'data:text/(html\|javascript)' palisade.html \| wc -l` | **0** |

The third row is worth a sentence: it looks for `Function(` used as a call in any position,
not only after `new`, because `Function("…")()` is the same compiler by another spelling.
Zero.

**A zero is only worth something if the command can return non-zero.** Five of the seven
patterns above — the string-argument timers, `eval`, `new Function`, `Function(` used as a call,
and `document.write` — were positive-controlled against a file that deliberately contains the
thing, so a broken regex cannot masquerade as a clean result. The `javascript:` and
`data:text/…` rows are **not** in the control file below; add a line containing each if you want
the same assurance for them. Reproduce it:

```bash
cat > ./control.js <<'EOF'
setTimeout("alert(1)", 0);
setInterval('x=1', 5);
setTimeout(`y=2`, 5);
eval("1");
new Function("return 2");
var f = Function("return 3");
document.write("hi");
EOF
printf '%-16s %s\n' 'timer(string)'  "$(grep -oE 'set(Timeout|Interval)[[:space:]]*\([[:space:]]*["'"'"'\`]' ./control.js | wc -l)"   # 3
printf '%-16s %s\n' 'eval('          "$(grep -oE '\beval[[:space:]]*\(' ./control.js | wc -l)"                                     # 1
printf '%-16s %s\n' 'new Function('  "$(grep -oE '\bnew[[:space:]]+Function[[:space:]]*\(' ./control.js | wc -l)"                   # 1
printf '%-16s %s\n' 'Function( call' "$(grep -oE '[^a-zA-Z0-9_$.]Function[[:space:]]*\(' ./control.js | wc -l)"                      # 2
printf '%-16s %s\n' 'document.write' "$(grep -oE 'document[[:space:]]*\.[[:space:]]*write' ./control.js | wc -l)"                    # 1
rm ./control.js
```

Same commands, same machine: **3 / 1 / 1 / 2 / 1** on a file that contains them, **0 / 0 / 0 / 0 / 0**
on `palisade.html`.

### 3.3 Script surface and external references

| Command | Count | What it means |
|---|---|---|
| `grep -oiF '<script' palisade.html \| wc -l` | **1** | exactly one script element; line 1169, written `<script>` with **no** `src`, `type`, or `nonce` attribute — it is inline, and it is the block the CSP hash covers |
| `grep -oE 'https?://' palisade.html \| wc -l` | **0** | not one absolute URL anywhere in the file, including in comments |
| `grep -oiF '<link' palisade.html \| wc -l` | **0** | no external stylesheet, no favicon fetch |
| `grep -oiF '<img' palisade.html \| wc -l` | **0** | no image element, so no image beacon in markup |
| `grep -oiF '<form' palisade.html \| wc -l` | **0** | nothing can be submitted anywhere |
| `grep -oiF '<base' palisade.html \| wc -l` | **0** | no base URL to hijack relative references |
| `grep -oE 'integrity[[:space:]]*=' palisade.html \| wc -l` | **0** | no subresource to have integrity *of* |
| `grep -oiF 'crossorigin' palisade.html \| wc -l` | **0** | — |

### 3.4 Network and storage primitives

| Command | Count |
|---|---|
| `grep -oE '\bfetch[[:space:]]*\(' palisade.html \| wc -l` | **0** |
| `grep -oF 'XMLHttpRequest' palisade.html \| wc -l` | **0** |
| `grep -oF 'WebSocket' palisade.html \| wc -l` | **0** |
| `grep -oF 'sendBeacon' palisade.html \| wc -l` | **0** |
| `grep -oF 'EventSource' palisade.html \| wc -l` | **0** |
| `grep -oE 'new[[:space:]]+Image' palisade.html \| wc -l` | **0** |
| `grep -oF 'localStorage' palisade.html \| wc -l` | **0** |
| `grep -oF 'sessionStorage' palisade.html \| wc -l` | **0** |
| `grep -oF 'indexedDB' palisade.html \| wc -l` | **0** |
| `grep -oF 'document.cookie' palisade.html \| wc -l` | **0** |

The tool keeps nothing after the tab is closed and sends nothing anywhere. Data leaves the
page only through a download the operator clicks.

### 3.5 The three non-zero rows, explained rather than omitted

| Command | Count | Explanation |
|---|---|---|
| `grep -oE ' on[a-z]+="' palisade.html \| wc -l` | **1** | v2.7 had 192. The one that remains is at line 4139: `<button onclick="window.print()">`, and it is a string written **into a downloaded report**, never into this page's DOM. It is tagged `/*EXPORT-ONLY-HANDLER*/` in the source so the release tool reports it instead of hiding it. The downloaded report carries its own policy permitting exactly the SHA-256 of the 14 bytes `window.print()` and nothing else. |
| `grep -oiF '<iframe' palisade.html \| wc -l` | **1** | the report-preview pane, line 1007: `<iframe id="rptPreview" title="Report preview" sandbox="allow-same-origin allow-modals">`. **No `allow-scripts`**, so the frame cannot run script and cannot remove its own sandbox; the parent policy is inherited into it as well. Measured: 0 elements with any `on*` attribute inside the rendered preview, 0 `<script>` tags, and a script injected into that frame did not execute — `evidence/gate-B/verify-B.txt`, section 5. **That capture is from build `376631c2…`, not the shipped bytes**; it differs only in the `productAliases` regex literals, and the shipped build reproduces the same preview (`report iframe srcdoc length: 22818`) in `evidence/gate-C/RERUN-shipped-fd2f80e9/harness.txt`. |
| `grep -oE 'srcdoc[[:space:]]*=' palisade.html \| wc -l` | **3** | three assignments to that one iframe's `srcdoc`: two fixed placeholder strings (lines 4425, 4430) and the built report (4434). `about:srcdoc` content is materialised from the attribute, not fetched, so it renders under `frame-src 'none'`. Verified on the shipped bytes — the preview builds and the page records 0 CSP violations (`evidence/gate-C/RERUN-shipped-fd2f80e9/harness.txt`). The earlier feasibility probe (`evidence/csp-probe/RESULT.md`) showed that a parent policy is inherited by `srcdoc`, but it ran `frame-src 'self' data:`, not `'none'`. |

Script is dispatched through delegation instead of attributes: **193** `data-click` /
`data-change` / `data-input` attributes, routed by one listener per event type against a
frozen allow-list of **108** named actions, with `setAttribute("on…` appearing **0** times.

```
grep -oE 'data-(click|change|input)=' palisade.html | wc -l     # 193
grep -oE 'setAttribute\(["'"'"']on' palisade.html | wc -l       # 0
```

---

## 4. The determination

**Palisade's only active content is client-side JavaScript (ECMAScript) executing in the
operator's browser. That is Category 3 mobile code, and Category 3 mobile code may be used
without a digital signature.**

The three-category scheme in DoD mobile code policy (DoDI 8552.01) works, as it is commonly
applied, like this:

| Category | Examples | Signing |
|---|---|---|
| 1 | ActiveX, Windows Scripting Host in the shell, shell/batch scripts | Prohibited unless signed with an approved certificate and used in a controlled configuration |
| 2 | Java applets and other Java mobile code, VBA, LotusScript, PostScript | Permitted from a trusted source over an assured channel; signing is the usual means of establishing that |
| 3 | **JavaScript / JScript / ECMAScript**, VBScript | **May be used. No signing requirement.** |

Palisade contains **zero** instances of every Category 1 and Category 2 technology listed
above (section 3.1) and its script is ECMAScript in a browser (section 3.2, 3.3).

> **Confirm the categorisation table against the current issuance of DoDI 8552.01 before you
> enter it in the package.** This document reproduces the scheme as it is commonly applied;
> it does not quote the instruction, and the author has not read the current issuance for
> this memo. That check costs five minutes and it is the ISSM's to make, not the author's to
> assert.

A category-3 determination removes the *signing* question. It does not, by itself, approve a
piece of software. The rest of the case — what the code does, what can reach it, what was
found and fixed — is in **`SECURITY-ASSESSMENT.md`** alongside this file.

---

## 5. Why "mobile code" may not be the right frame at all

Mobile code policy exists because of a specific hazard: code that arrives **from a remote
system, across a network, and executes on the receiving host without the user explicitly
installing or invoking it**. A web page that silently runs script when you visit it is the
paradigm case.

That is not this deployment:

- There is **no server**. The file is opened from `file://` — off a USB drive, a share the
  operator has already copied from, or a local directory. Nothing transmits it at run time.
- The operator **already holds the bytes** before anything executes, and can hash them,
  read them, or diff them against a known copy first.
- Execution is **deliberate**: the operator opens a file they chose. Nothing auto-executes on
  a visit to a page.
- Nothing is fetched afterwards: 0 absolute URLs, 0 network primitives (section 3.3–3.4), and
  a policy that forbids the network outright (`connect-src 'none'`, section 6).

So under the definition, the hazard mobile code policy is aimed at — untrusted code arriving
over the wire and running on sight — is absent. What remains is an ordinary software-assurance
question about a **local file**: *is the copy in front of the operator the copy that was
reviewed?*

That is the residual control, and it is the one worth spending effort on.

> As with section 4, this is a reading of the definition, offered so the ISSM can make the
> call. If the ISSM prefers to treat the file as mobile code regardless of how it arrives,
> the answer does not change: it is Category 3, and Category 3 needs no signature.

---

## 6. The residual control: integrity of the local copy

Two mechanisms, deliberately different in kind.

### 6.1 The manifest — verification if someone runs it

`MANIFEST.json` ships beside `palisade.html` and records the digests, the byte count, the
version, and the hash of the script block:

```
sha256sum palisade.html
# fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97  palisade.html

grep sha256 MANIFEST.json
#   "sha256": "fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97",
#       "sha256": "M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q="
```

Two digests, because they answer different questions. The first is the whole file. The second
is the script block alone — the value the CSP names, stored without the `sha256-` prefix the
policy and the browser use.

(A `SHA256SUMS` file is simply `sha256sum palisade.html > SHA256SUMS`; the manifest is what
the release tool emits, and it is the file this document points at.)

This is the ordinary control, and it has the ordinary weakness: it only helps if somebody
actually runs it. Nobody does, every time, forever.

### 6.2 The seal — enforcement whether or not anyone runs anything

The file carries a Content Security Policy in a `<meta http-equiv>` element (there is no
server, so a response header is impossible). Its `script-src` is not a keyword. It is the
SHA-256 of the exact bytes of the one script block:

```
script-src 'sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q='
```

Change one byte of that script and the browser refuses to execute it. Not "warns" — refuses.

**Measured, against the shipped file, on 11 September 2026** (full transcript:
`evidence/gate-C/RERUN-shipped-fd2f80e9/tamper-evidence.txt`). One byte was changed at offset
83048 — `a` → `X` — **inside a comment**, a banner line reading `Palisade (offline)`. The
program is byte-for-byte unchanged in every statement it contains:

```
sealed copy    : script ran = true   demo load -> hosts = 6, PPSM rows = 19
tampered copy  : script ran = false  demo load -> "S is not defined", PPSM rows = 0
```

and the browser said, in its own words:

```
Executing inline script violates the following Content Security Policy directive
'script-src 'sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=''. Either the
'unsafe-inline' keyword, a hash ('sha256-jr2PcEQm3pZJxpHVPbW6mW30lqNS+tWfeCecgc8Hy28='),
or a nonce ('nonce-...') is required to enable inline execution. The action has been blocked.
```

Four properties of that failure matter to an accreditor:

1. **It needs no tooling and no cooperation.** The operator does not have to remember to hash
   anything. The check happens at load, in the browser, every time.
2. **It is loud and unmistakable.** The tampered page still drew its markup and stylesheet
   (782 DOM nodes, correct background colour) but populated **0** table cells. It is visibly
   Palisade and visibly not working — not subtly wrong, which is the failure mode that
   actually hurts an evidence compiler.
3. **The browser names the expected hash.** Compare it to the `inlineScriptBlocks[0].sha256`
   value in `MANIFEST.json` — the same base64, minus the `sha256-` prefix. No Palisade-specific
   tooling is involved, and no part of that comparison requires taking this document's word.
4. **The seal does not judge intent.** The edit demonstrated here was inert — one letter in a
   comment. It was still refused. A real attacker's edit would not be inert.

The cost of this property is a discipline, and it is stated here rather than buried: **any
edit to the script, whitespace included, requires `node tools/seal.mjs palisade.html --seal`
before the file is usable again.** That is why the release tool runs `--verify` before a
release rather than after.

### 6.3 What the policy also forbids, measured

The same policy that seals the script also removes the egress channels. Observed live, in
Chromium 150 on a real `file://` URL, against the shipped bytes — the app healthy before the
tests and still loading demo data afterwards (`evidence/gate-C/RERUN-shipped-fd2f80e9/negative-tests.txt`):

| Attempted in the page | Result |
|---|---|
| `fetch("https://example.invalid")` | refused — `connect-src`, `TypeError: Failed to fetch` |
| `new Image().src = "https://example.invalid/x"` | refused — `img-src` |
| inject a `<script>` element with hostile bytes | refused — `script-src-elem`; `window.__pwned` stayed `undefined` |
| `insertAdjacentHTML` a `<button onclick="document.title=1">` and click it | refused — `script-src-attr`; title unchanged |
| `setTimeout("window.__evalCanary=1", 0)` | refused — `script-src`, `blockedURI: eval`; canary never set |

One test is **not** refused and is reported rather than dropped: `eval("1")` typed at an
**attached debugger** returns `1`. Chromium exempts debugger-originated evaluation from CSP so
that a strict-policy page stays debuggable. That measures the debugger, not the policy. The
same compiler reached from a call site *inside* the page — which is what hostile input
actually has — is refused, and that is the row above it.

---

## 7. ASD STIG mapping — deliberately minimal

The Application Security and Development STIG is the right instrument for this tool, and this
document quotes almost none of it, on purpose.

| Requirement | Severity | Status |
|---|---|---|
| **APSC-DV-002490** — cross-site scripting | CAT I | Two live injection sinks were found in v2.7 and closed in v2.8; a hash-based `script-src` now makes injected handlers and injected `<script>` inert as well. Measured both ways — see `SECURITY-ASSESSMENT.md` §5 and the transcripts named there. |
| **APSC-DV-002480** | CAT II | An ID that existed in the ASD STIG release consulted while writing this. That is not a claim it was read from the current release. Its requirement text is **not** reproduced here; read it from the release your program is assessed under. |

**No other V-ID or Rule ID appears in this package.** The ASD STIG is revised on a regular
cycle, IDs are retired and re-severitised, and a requirement quoted from memory is worse than
no requirement at all. Before any of this is entered in eMASS, validate both IDs, both
severities, and the current requirement text **against the current release**. If a mapping
row cannot be validated that way, it should be left out — the same rule this document applied
to itself.

---

## 8. Re-run this determination yourself

The whole of section 3 is one paste. Run it from the directory holding `palisade.html`:

```bash
F=palisade.html
echo "identity"; sha256sum $F; wc -c < $F

echo "--- Cat 1 / Cat 2 technologies (all must be 0) ---"
for p in '<applet' '<object' '<embed' 'ActiveXObject' 'classid' 'codebase=' \
         'application/x-shockwave' 'application/java' 'WebAssembly' 'importScripts'; do
  printf '%-28s %s\n' "$p" "$(grep -oiF "$p" $F | wc -l)"
done
printf '%-28s %s\n' '.swf (case-sensitive)' "$(grep -oF '.swf' $F | wc -l)"

echo "--- string-to-code compilers (all must be 0) ---"
printf '%-28s %s\n' 'eval('        "$(grep -oE '\beval[[:space:]]*\(' $F | wc -l)"
printf '%-28s %s\n' 'new Function(' "$(grep -oE '\bnew[[:space:]]+Function[[:space:]]*\(' $F | wc -l)"
printf '%-28s %s\n' 'Function( call' "$(grep -oE '[^a-zA-Z0-9_$.]Function[[:space:]]*\(' $F | wc -l)"
printf '%-28s %s\n' 'document.write' "$(grep -oE 'document[[:space:]]*\.[[:space:]]*write' $F | wc -l)"
printf '%-28s %s\n' 'timer(string)' "$(grep -oE 'set(Timeout|Interval)[[:space:]]*\([[:space:]]*["'"'"'\`]' $F | wc -l)"
printf '%-28s %s\n' 'javascript:'   "$(grep -oiF 'javascript:' $F | wc -l)"

echo "--- surface (expect 1 / 0 / 0 / 0 / 0 / 1 / 1 / 193) ---"
printf '%-28s %s\n' '<script'      "$(grep -oiF '<script' $F | wc -l)"
printf '%-28s %s\n' 'http(s)://'   "$(grep -oE 'https?://' $F | wc -l)"
printf '%-28s %s\n' '<link'        "$(grep -oiF '<link' $F | wc -l)"
printf '%-28s %s\n' '<img'         "$(grep -oiF '<img' $F | wc -l)"
printf '%-28s %s\n' '<form'        "$(grep -oiF '<form' $F | wc -l)"
printf '%-28s %s\n' 'inline on*='  "$(grep -oE ' on[a-z]+="' $F | wc -l)"
printf '%-28s %s\n' '<iframe'      "$(grep -oiF '<iframe' $F | wc -l)"
printf '%-28s %s\n' 'data-* actions' "$(grep -oE 'data-(click|change|input)=' $F | wc -l)"
```

Then confirm that the script bytes really are the bytes the policy names, using nothing that
ships with Palisade:

```bash
python3 - <<'EOF'
import hashlib, base64, re
b = open('palisade.html','rb').read()
assert b.count(b'\r') == 0 and b[:3] != b'\xef\xbb\xbf', "CRLF or BOM"
assert b.count(b'<script>') == 1 and b.count(b'</script>') == 1
i = b.index(b'<script>') + 8; j = b.index(b'</script>')
print("computed :", "sha256-" + base64.b64encode(hashlib.sha256(b[i:j]).digest()).decode())
print("in policy:", re.search(rb"script-src '([^']*)'", b).group(1).decode())
EOF
```

Both lines must print `sha256-M+KeGiNQAgQszIVsK+kxHtQl6rAXsDOoD9LKjRHIS/Q=`.

And, if you want to watch the seal fail rather than take section 6.2 on trust: copy the file,
change any single byte inside the script block — a letter in a comment is enough — open the
copy in Chromium or Edge, and look at the console. The page will draw and will not run.

---

## 9. What this determination does **not** claim

- **Not** that the file is code-signed in any way a browser verifies. There is no such thing
  for a `.html` document. The CSP hash seals the script *against the policy carried in the
  same file*; it is a tamper-evidence property, not a code signature, and an attacker who
  rewrites both the script and the hash produces a file whose SHA-256 no longer matches the
  manifest — which is why both controls are named in section 6, not just one.
- **Not** that a DoDI 8552.01 categorisation has been read from the current issuance for this
  memo. The category assignment for ECMAScript is stated as commonly applied and flagged for
  confirmation (section 4).
- **Not** that any ASD STIG requirement other than the two IDs in section 7 has been assessed,
  and **not** that those two were read from the current release (section 7).
- **Not** that the browser itself is in scope. A defect in Chromium's CSP implementation, or a
  browser configured to ignore policy, is outside what a single HTML file can control. The
  deployed browser build remains the ISSM's assurance, as it is for every web application in
  the enclave.
- **Not** that Category 3 status is an approval to operate. It answers the signing question
  only. The assurance case is in `SECURITY-ASSESSMENT.md`.

---

*Palisade v2.8 · MIT Licence · Gavin Lee Domingo Johnson, Jacob Keith ·
`fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97`*
