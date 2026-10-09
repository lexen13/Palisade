#!/usr/bin/env node
/* Palisade release seal / verify.
 *
 * This is NOT a build step. palisade.html is complete and openable before and
 * after this runs; the file is never generated from sources. This tool only:
 *
 *   1. recomputes the SHA-256 digests of the inline <script> blocks and writes
 *      them into the Content-Security-Policy meta tag (--seal), or checks that
 *      the ones already there are correct (--verify);
 *   2. checks the version string is consistent across every place it is written --
 *      the three CONTRIBUTING.md requires it to be bumped, plus the provenance
 *      comment, which postdates that instruction and is the one a release misses;
 *   3. re-asserts the offline invariants by static inspection;
 *   4. emits the SHA-256 / SHA-384 integrity manifest.
 *
 * What the seal does NOT prove: it checks that the policy text is the canonical
 * one and that the browser will see it (one <meta>, first thing in <head>, not
 * inside a comment). It cannot stop someone who can write the file from writing
 * a different file; the whole-file digest in SHA256SUMS / the release attestation
 * is the control for that. Anyone verifying a copy checks the digest first.
 *
 * The digest is taken over the EXACT bytes between <script> and </script>.
 * No trimming, no normalisation, no re-indentation: a single whitespace change
 * invalidates the hash and the browser will refuse to run the script. That is
 * the point — it is what makes the policy a tamper-evident seal.
 *
 *   node tools/seal.mjs palisade.html --seal      # write hashes into the CSP
 *   node tools/seal.mjs palisade.html --verify    # fail if anything drifted
 *   node tools/seal.mjs palisade.html --manifest MANIFEST.json
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve, basename } from 'node:path'

const file = resolve(process.argv[2] || 'palisade.html')
const mode = process.argv.includes('--seal') ? 'seal' : 'verify'
let raw = readFileSync(file)           // Buffer: byte-exact, never a decoded string
const text = raw.toString('utf8')
const problems = [], notes = []

/* ---- 0. byte hygiene: LF-only, no BOM ----------------------------------- */
/* The digest has to be taken over the same bytes the BROWSER hashes, and the
 * browser does not hash what is on disk. The HTML parser normalises every CRLF
 * and lone CR in the source to a single LF before the script element's text is
 * ever handed to the CSP hash check (HTML Standard, "preprocessing the input
 * stream"). So a file saved with CRLF hashes one way here and a different way
 * in the browser: script-src would reject the only script in the file and the
 * page would load completely inert — styled, clickable, and doing nothing.
 * A UTF-8 BOM is the same class of problem from the other end: it sits ahead of
 * <!DOCTYPE html>, and it is bytes in the whole-file manifest digest that an
 * operator re-running sha256sum on a re-saved copy will not reproduce.
 * The rule is "the repo stays LF-only", not "normalise on the way past", so
 * this refuses the file rather than rewriting it — including in --seal mode,
 * where writing a hash computed from bytes the browser will never see would
 * hand the operator a seal that is wrong by construction. */
const crCount = raw.reduce((n, b) => n + (b === 0x0d ? 1 : 0), 0)
const hasBOM = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf
/* NUL bytes and invalid UTF-8: grep treats a file holding a NUL as binary and prints
 * nothing, which blinded csp-lint's counts in v2.8; the browser decodes invalid UTF-8
 * as U+FFFD, so the bytes hashed here would not be the ones it hashes. Refused. */
const nulCount = raw.reduce((n, b) => n + (b === 0 ? 1 : 0), 0)
let utf8ok = true
try { new TextDecoder('utf-8', { fatal: true }).decode(raw) } catch { utf8ok = false }
if (nulCount) problems.push(`${nulCount} NUL byte(s) present — refused (text tools treat the file as binary and lint nothing)`)
if (!utf8ok) problems.push('the file is not valid UTF-8 — refused (the browser would hash replacement characters, not these bytes)')
if (crCount) problems.push(`${crCount} CR byte(s) (0x0D) present — the file must be LF-only. The browser normalises CRLF to LF before computing the script hash, so a CRLF file on disk hashes differently from what the browser computes and the page loads inert. Fix: sed -i 's/\\r$//' the file (and set core.autocrlf=false / add *.html -text).`)
if (hasBOM) problems.push('UTF-8 BOM (EF BB BF) at offset 0 — the file must have no BOM. It precedes <!DOCTYPE html> and it changes the whole-file digest an operator verifies against SHA256SUMS.')
if (!crCount && !hasBOM) notes.push('byte hygiene: LF-only, no BOM (script hash will match what the browser computes)')
const bytesAreSealable = !crCount && !hasBOM && !nulCount && utf8ok

/* ---- 1. inline script digests ------------------------------------------ */
/* Structure is read from a copy with every HTML comment blanked to equal-length
 * spaces, because that is what the parser does with them: a <meta> or a <script>
 * inside <!-- --> does not exist for the browser. v2.8 matched the raw text, so a
 * policy wrapped in a comment still verified PASS while the page ran with no CSP.
 * Offsets are preserved, so the script bytes are still cut from the original. */
const unterminated = /<!--(?![\s\S]*?-->)/.test(text)
if (unterminated) problems.push('an HTML comment is opened and never closed — everything after it is invisible to the browser')
const blanked = text.replace(/<!--[\s\S]*?-->/g, c => ' '.repeat(c.length))
const blocks = []
const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi
let m
while ((m = re.exec(blanked)) !== null) {
  const open = m[0].indexOf('>') + 1
  const body = text.slice(m.index + open, m.index + open + m[2].length)
  const start = Buffer.byteLength(text.slice(0, m.index + open), 'utf8')
  const bytes = Buffer.from(body, 'utf8')
  blocks.push({ at: m.index + open, attrs: m[1].trim(), body, bytes, len: bytes.length, sha256: createHash('sha256').update(bytes).digest('base64'), start })
}
const scriptOpens = (blanked.match(/<script\b/gi) || []).length
/* markup = what the parser reads as markup: comments and script bodies blanked (the script
 * legitimately carries CSP strings for the standalone reports it writes) */
let markup = blanked
for (const b of blocks) markup = markup.slice(0, b.at) + ' '.repeat(b.body.length) + markup.slice(b.at + b.body.length)
if (!blocks.length) problems.push('no inline <script> block found')
if (blocks.length !== 1 || scriptOpens !== 1)
  problems.push(`expected exactly one <script> element, found ${scriptOpens} opening tag(s) and ${blocks.length} complete block(s)`)
for (const b of blocks) {
  if (b.attrs) problems.push(`the <script> tag carries attributes (${b.attrs.slice(0, 60)}) — the release form is a bare <script>`)
  /* "<!--" and "<script" inside script data switch the tokenizer into the escaped
   * states, where the block's end is no longer the first </script>. */
  if (/<!--|<script|<\/script/i.test(b.body)) problems.push('the script body contains "<!--", "<script" or "</script" — the parser would not end the block where this tool does')
}
const wanted = blocks.map(b => `'sha256-${b.sha256}'`).join(' ')

/* ---- 2. CSP meta tag ---------------------------------------------------- */
/* The attribute quote is captured and back-referenced rather than closing on the first quote
 * of either kind: every real policy contains keyword sources written in single quotes
 * ('none', 'unsafe-inline', 'sha256-...'), so a [^"']* body can never match one. */
const cspRe = /<meta\s+http-equiv=["']Content-Security-Policy["']\s+content=(["'])([\s\S]*?)\1\s*>/i
const csp = markup.match(cspRe)
/* Placement. A <meta> policy is honoured only if the parser puts it in <head>, and only
 * for what comes after it. So: exactly one policy element in the file (outside comments),
 * and nothing ahead of it but the doctype, <html>, <head> and other <meta> tags -- which
 * rules out <noscript>, <template>, <title>, <style>, <textarea> or any body content
 * swallowing it or ending the head early. */
const policyMetas = (markup.match(/<meta\b[^>]*http-equiv\s*=\s*["']?\s*content-security-policy/gi) || []).length
if (policyMetas > 1) problems.push(`${policyMetas} Content-Security-Policy <meta> elements outside comments — the release has exactly one`)
if (/content-security-policy-report-only/i.test(markup)) problems.push('a report-only policy is present — it enforces nothing')
if (csp) {
  const before = markup.slice(0, csp.index)
  const PREAMBLE = /^\s*<!DOCTYPE html>\s*<html\b[^>]*>\s*<head>\s*(?:<meta\b(?![^>]*http-equiv)[^>]*>\s*)*$/i
  if (!PREAMBLE.test(before))
    problems.push('the policy <meta> is not the first thing in <head> — only <!DOCTYPE html>, <html>, <head> and plain <meta> tags may precede it, otherwise the parser can drop it or apply it too late')
  else notes.push('policy <meta> is in <head>, outside any comment, ahead of every script')
}
if (!csp) {
  /* (d) always surface the digest the operator needs, even when there is no
   * tag to compare it against yet — this is the number that goes into C2. */
  problems.push(`no <meta http-equiv="Content-Security-Policy"> the browser would see (none present, or only inside a comment)\n      expected script-src: ${wanted}`)
} else {
  const cur = (csp[2].match(/script-src\s+([^;]*)/i) || [, ''])[1].trim()
  if (cur !== wanted) {
    if (mode === 'seal' && !bytesAreSealable) {
      problems.push(`refusing to --seal: byte hygiene failed above, so this digest is not what the browser would compute\n      expected script-src (after the file is fixed): ${wanted}`)
    } else if (mode === 'seal') {
      const patched = csp[2].replace(/script-src\s+[^;]*/i, `script-src ${wanted}`)
      raw = Buffer.from(text.slice(0, csp.index) + csp[0].replace(csp[2], patched) + text.slice(csp.index + csp[0].length), 'utf8')
      writeFileSync(file, raw)
      notes.push(`script-src resealed -> ${wanted}`)
    } else {
      problems.push(`script-src digest MISMATCH — the script bytes changed since the last seal\n      in file:  ${cur}\n      expected: ${wanted}\n      fix: re-run with --seal (or paste the expected value into the CSP meta tag)`)
    }
  } else notes.push('script-src digests match the script bytes')

  /* The whole policy is compared to the canonical one, not a substring list: v2.8
   * checked five directives were present, so an added script-src-elem/-attr (which
   * override script-src), a second weaker default, or a widened style/img source
   * all verified PASS. Only the script-src digest list varies between releases. */
  const CANONICAL = ["default-src 'none'", 'script-src <digests>', "style-src 'unsafe-inline'",
    "img-src 'none'", "font-src 'none'", "connect-src 'none'", "frame-src 'none'", "worker-src 'none'",
    "object-src 'none'", "media-src 'none'", "manifest-src 'none'", "base-uri 'none'", "form-action 'none'"]
  const got = csp[2].split(';').map(d => d.trim().replace(/\s+/g, ' ')).filter(Boolean)
    .map(d => /^script-src /i.test(d) ? 'script-src <digests>' : d)
  const missing = CANONICAL.filter(d => !got.includes(d))
  const extra = got.filter(d => !CANONICAL.includes(d))
  const dupes = got.length !== new Set(got.map(d => d.split(' ')[0].toLowerCase())).size
  if (missing.length || extra.length || dupes)
    problems.push(`CSP differs from the canonical policy${missing.length ? `\n      missing: ${missing.join('; ')}` : ''}${extra.length ? `\n      not allowed: ${extra.join('; ')}` : ''}${dupes ? '\n      a directive is repeated (the first one wins)' : ''}`)
  else notes.push(`CSP is exactly the canonical ${CANONICAL.length}-directive policy (only the script-src digest varies)`)
}

/* ---- 3. version consistency (CONTRIBUTING.md "Releasing") --------------- */
const cur = readFileSync(file, 'utf8')
const vTitle = (cur.match(/<title>Palisade v([\d.]+)<\/title>/) || [])[1]
const vSpan  = (cur.match(/<span class="ver">v([\d.]+)<\/span>/) || [])[1]
const vMeta  = (cur.match(/meta:\{tool:"Palisade",\s*ver:"([\d.]+)"/) || [])[1]
/* The provenance comment (ledger B10) is a FOURTH place the version is written. It postdates
 * CONTRIBUTING.md's "bump it in three places", so it is exactly the site a release is most
 * likely to miss -- which is the defect R2 recorded against meta.ver, one site over. It is
 * checked here, and reported by name, so the next release cannot reintroduce it. */
const vProv  = (cur.match(/<!--\s*Palisade v([\d.]+)\s/) || [])[1]
const vers = { title: vTitle, headerSpan: vSpan, sessionMeta: vMeta, provenanceComment: vProv }
const present = Object.entries(vers).filter(([, v]) => v !== undefined)
if (new Set(present.map(([, v]) => v)).size !== 1 || !vTitle)
  problems.push(`version strings disagree: ${JSON.stringify(vers)} — every place the version is written must match (CONTRIBUTING.md names the first three; the provenance comment is the fourth)`)
else notes.push(`version consistent at v${vTitle} across all ${present.length} sites that carry it (${present.map(([k]) => k).join(', ')})`)

/* ---- 4. offline invariants (CONTRIBUTING.md "Hard constraints") --------- */
/* (e) The provenance header (ledger B10) is an HTML comment carrying the source
 * repo URL. It is written scheme-less on purpose so the absolute-URL rule below
 * does not trip on it, but exempt it explicitly rather than relying on that:
 * a comment is inert — the parser never fetches anything out of one — so the
 * invariant being enforced here (no fetchable external reference) genuinely
 * does not apply to it, and a maintainer who later writes the URL with a scheme
 * should get a lint nudge from csp-lint, not a hard seal failure. Only the
 * provenance comment is exempted, not comments in general. */
const PROVENANCE_RX = /<!--[^>]*?\bPalisade\b[\s\S]*?\bSource:\s*[^\s>]*github\.com[\s\S]*?-->/g
const provenance = cur.match(PROVENANCE_RX) || []
/* blank it to equal-length spaces so every other offset/report stays honest */
const scan = cur.replace(PROVENANCE_RX, m => ' '.repeat(m.length))
if (provenance.length) notes.push(`provenance comment present and exempt from the absolute-URL rule (${provenance.length}x)`)
const banned = [
  [/\bfetch\s*\(/g, 'fetch('], [/XMLHttpRequest/g, 'XMLHttpRequest'],
  [/\bWebSocket\b/g, 'WebSocket'], [/localStorage/g, 'localStorage'],
  [/sessionStorage/g, 'sessionStorage'], [/indexedDB/g, 'indexedDB'],
  [/\beval\s*\(/g, 'eval('], [/new\s+Function\s*\(/g, 'new Function('],
  [/document\.write\s*\(/g, 'document.write('],
  [/\bnavigator\.sendBeacon\b/g, 'sendBeacon'],
  /* SECURITY.md and the assessment claim zero of these too; v2.8 checked neither */
  [/\bEventSource\b/g, 'EventSource'], [/new\s+Image\b/g, 'new Image'],
  [/https?:\/\/(?!www\.w3\.org|schemas\.|purl\.org|cyclonedx\.org|spdx\.org)/g, 'absolute http(s) URL'],
  [/<(script|link|img|iframe)[^>]+\b(src|href)=["']?(https?:)?\/\//gi, 'external resource reference'],
]
for (const [rx, label] of banned) {
  const hits = scan.match(rx)
  if (hits) problems.push(`offline invariant broken: ${hits.length}x ${label}`)
}

/* ---- 4b. inline event-handler attributes -------------------------------- */
/* The leading class is "any byte that cannot continue a JS identifier or a
 * member access", not whitespace: pristine line 4277 emits
 *   ...+'onchange="toggleRptSection('+...
 * with the attribute glued to the opening quote of a string literal, so a
 * /\son[a-z]+=/ pattern walks straight past it and undercounts by one (191 vs
 * the true 192). Excluding . $ _ and word characters is what keeps
 * `el.onclick=` and `obj.onchange=` property assignments — which are the
 * CSP-safe form we are converting TO — out of the count. */
const HANDLER_RX = /(^|[^A-Za-z0-9_.$-])on[a-z][a-z0-9]*\s*=/gim
const countHandlers = s => (s.match(HANDLER_RX) || []).length
/* (b) A line carrying the EXPORT_ONLY marker below holds an on* attribute that
 * is written into a DOWNLOADED artifact (a standalone exported HTML report
 * that has no CSP of its own), not into this page.
 * It is never governed by this file's CSP, so it is exempt from the count —
 * but the tag is the whole audit trail for it, so it must be on the same line
 * as the attribute and it is reported separately, never silently. */
const EXPORT_ONLY = '/*EXPORT-ONLY-HANDLER*/'
const lines = cur.split('\n')
let tagged = 0, live = 0
for (const ln of lines) {
  const n = countHandlers(ln)
  if (!n) continue
  if (ln.includes(EXPORT_ONLY)) tagged += n; else live += n
}
/* The static body is everything before the first <script tag. Under a
 * hash-based script-src an on* attribute there cannot run at all, so it is not
 * "mostly converted", it is a dead button. This count must be exactly 0. */
const scriptAt = cur.search(/<script/i)
const staticBody = scriptAt < 0 ? cur : cur.slice(0, scriptAt)
const bodyHandlers = countHandlers(staticBody)
if (bodyHandlers)
  problems.push(`${bodyHandlers} inline event-handler attributes in the STATIC BODY (before <script>) — required to be exactly 0: under a hash-based script-src these attributes never execute, so each one is a visibly dead control. Convert to delegated data-click/data-change dispatch.`)
else notes.push('static body carries 0 inline event-handler attributes')
if (live)
  problems.push(`${live} inline event-handler attributes remain in the page — dead code under a hash-based script-src; convert to delegated data-act handlers, or tag a genuinely export-only one with ${EXPORT_ONLY} on the same line`)
else notes.push('no live inline event-handler attributes (all delegated)')
if (tagged) notes.push(`${tagged} inline event-handler attribute(s) exempt via ${EXPORT_ONLY} — these are written into downloaded artifacts, not into this page`)

/* ---- 5. integrity manifest ---------------------------------------------- */
const final = readFileSync(file)
/* The CSP hash covers the script only. The markup around it (the policy itself, every
 * control, label and default) is covered by the whole-file digest and nothing else, so
 * it gets its own digest here: a reviewer comparing two builds can tell a script change
 * from a markup change without diffing 500 KB. */
const finalText = final.toString('utf8')
const sm = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/i.exec(finalText.replace(/<!--[\s\S]*?-->/g, c => ' '.repeat(c.length)))
const outside = sm ? Buffer.concat([
  Buffer.from(finalText.slice(0, sm.index + sm[0].indexOf('>') + 1), 'utf8'),
  Buffer.from(finalText.slice(sm.index + sm[0].indexOf('>') + 1 + sm[1].length), 'utf8')]) : final
const manifest = {
  file: basename(file), bytes: final.length,
  sha256: createHash('sha256').update(final).digest('hex'),
  sha384: createHash('sha384').update(final).digest('hex'),
  sha512: createHash('sha512').update(final).digest('hex'),
  version: vTitle, inlineScriptBlocks: blocks.map(b => ({ bytes: b.len, sha256: b.sha256 })),
  outsideScript: { bytes: outside.length, sha256: createHash('sha256').update(outside).digest('hex'),
    note: 'markup outside the script block: not covered by the CSP hash, only by the whole-file digest' },
  lineEndings: crCount ? 'MIXED/CRLF' : 'LF', bom: hasBOM,
  inlineHandlers: { staticBody: bodyHandlers, live, exportOnlyExempt: tagged },
}

console.log(`\n  Palisade release seal — ${basename(file)}  (${mode})\n`)
for (const n of notes) console.log(`  ok    ${n}`)
for (const p of problems) console.log(`  FAIL  ${p}`)
console.log(`\n  sha256 ${manifest.sha256}\n  sha384 ${manifest.sha384}\n  bytes  ${manifest.bytes}`)
console.log(`\n  ${problems.length ? `RESULT: FAIL (${problems.length})` : 'RESULT: PASS'}\n`)
if (process.argv.includes('--manifest')) writeFileSync(resolve(process.argv[process.argv.indexOf('--manifest') + 1]), JSON.stringify(manifest, null, 2))
process.exit(problems.length ? 1 : 0)
