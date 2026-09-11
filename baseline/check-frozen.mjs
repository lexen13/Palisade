#!/usr/bin/env node
/* Compare a fresh harness run against the frozen reference numbers.
 *
 * harness.mjs already exits non-zero when its own verdict fails. This adds the
 * second half of the gate: that the numbers the tool PRODUCES have not moved.
 * A change that leaves the page error-free but silently alters how many PPSM
 * rows or software entries the demo dataset yields is exactly the regression the
 * harness verdict alone would wave through.
 *
 * Only the stable numbers are compared. Deliberately NOT compared:
 *   - the timestamp and the file:// url (different on every machine)
 *   - the chromium version string (CI and the dev box differ)
 *   - the report iframe srcdoc length (moves with any copy edit in a section)
 *   - the demoTrigger wording (changed when inline onclick became data-click)
 *
 *   node baseline/check-frozen.mjs <outDir>/result.json [baseline/FROZEN-BASELINE.txt]
 */
import { readFileSync } from 'node:fs'

const resultPath = process.argv[2]
const frozenPath = process.argv[3] || new URL('./FROZEN-BASELINE.txt', import.meta.url).pathname
if (!resultPath) { console.error('usage: check-frozen.mjs <result.json> [FROZEN-BASELINE.txt]'); process.exit(2) }

const r = JSON.parse(readFileSync(resultPath, 'utf8'))
const frozen = readFileSync(frozenPath, 'utf8')

const grab = (re, name) => {
  const m = frozen.match(re)
  if (!m) { console.error(`could not read "${name}" out of ${frozenPath}`); process.exit(2) }
  return Number(m[1])
}

const expect = {
  hosts:        grab(/^hosts:\s*(\d+)/m, 'hosts'),
  intelRows:    grab(/intelRows:\s*(\d+)/, 'intelRows'),
  listingFiles: grab(/listingFiles:\s*(\d+)/, 'listingFiles'),
  meterPct:     grab(/^meter:\s*(\d+)%/m, 'meter'),
  ppsm:         grab(/ppsm=(\d+)/, 'ppsm'),
  stig:         grab(/stig=(\d+)/, 'stig'),
  sw:           grab(/sw=(\d+)/, 'sw'),
  asset:        grab(/asset=(\d+)/, 'asset'),
}

const actual = {
  hosts:        r.probe.hosts,
  intelRows:    r.probe.intelRows,
  listingFiles: r.probe.listingFiles,
  meterPct:     Number(String(r.probe.meterPct).replace('%', '')),
  ppsm:         r.probe.tableRows.ppsm,
  stig:         r.probe.tableRows.stig,
  sw:           r.probe.tableRows.sw,
  asset:        r.probe.tableRows.asset,
}

/* these must be zero regardless of what the frozen file says */
const zeros = {
  consoleErrors: r.consoleErrors.length,
  cdpExceptions: r.cdpExceptions.length,
  pageErrors:    r.pageErrors.length,
  cspViolations: r.cspViolations.length,
}

let bad = 0
console.log('frozen-number check')
for (const k of Object.keys(expect)) {
  const ok = actual[k] === expect[k]
  if (!ok) bad++
  console.log(`  ${ok ? 'ok ' : 'XX '} ${k.padEnd(13)} ${String(actual[k]).padStart(5)}  expected ${expect[k]}`)
}
for (const [k, v] of Object.entries(zeros)) {
  const ok = v === 0
  if (!ok) bad++
  console.log(`  ${ok ? 'ok ' : 'XX '} ${k.padEnd(13)} ${String(v).padStart(5)}  expected 0`)
}
const verdictOk = r.verdict && r.verdict.PASS === true
if (!verdictOk) { bad++; console.log('  XX  harness verdict.PASS is not true') }

console.log(bad ? `\nRESULT: FAIL (${bad} check(s))` : '\nRESULT: PASS')
process.exit(bad ? 1 : 0)
