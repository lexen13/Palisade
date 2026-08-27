# Contributing

## Before anything else

**Never commit scan data, session files, or generated artifacts.** They contain real host and
network data from whatever environment produced them. The `.gitignore` covers the known
filename patterns, but run `git status` before every commit rather than trusting it blindly.

If site-specific identifiers would end up in a change — hostname prefixes, IP ranges, internal
system or program names, organization acronyms — genericize them first. Detection rules ship
generic examples on purpose; real naming conventions belong in a local environment profile
that stays out of the repository.

This applies to issues and pull request descriptions too. Redact before you paste a stack
trace or a sample row.

## Hard constraints

These are not style preferences. A change that breaks one of them will not be merged.

- **Single file.** Everything ships in `palisade.html`. No build step, no bundler.
- **No dependencies.** No CDN links, no npm, no vendored libraries. If you need to parse
  something, parse it.
- **No network calls.** No `fetch`, no `XMLHttpRequest`, no remote fonts or images, no
  telemetry. The tool must work on an air-gapped machine, and that has to be verifiable by
  reading the source.
- **No browser storage.** No `localStorage`, no `sessionStorage`, no IndexedDB, no cookies.
  State lives in memory; persistence is an explicit session export the user controls.

## Conventions

- Detection logic belongs in `DEFAULT_CONFIG`, not hardcoded in functions, so it can be
  maintained from the Detection Config tab without code changes.
- Comment the *why* for anything non-obvious — especially parsing quirks in scanner output,
  which is where most of the hard-won knowledge in this file lives.
- Match the surrounding style. It is dense in places; that is deliberate in a single-file tool.

## Workflow

```bash
git checkout -b feature/short-description
# make changes
git add -p                 # review each hunk rather than staging blindly
git status                 # confirm nothing unexpected is staged
git commit -m "Add X"
git push -u origin feature/short-description
```

Then open a pull request. Every change gets a second pair of eyes before merge — the review
catches accidental data inclusion at least as often as it catches bugs, which is why it stays
even when it feels like overhead on a two-person change.

## Testing a change

There is no test suite; the tool is verified by driving it. To check a change:

1. Open `palisade.html` in a browser and confirm the console is clean.
2. Click **Load demo data** — the six synthetic hosts exercise the real parsing, detection,
   scoring, and export paths.
3. Check that the affected tab renders and that the readiness meter still behaves.
4. Run the affected export and confirm the CSV structure is intact.
5. Save a session, reload it, and confirm round-trip integrity — including loading an older
   session as a baseline if your change touches state shape.
6. If your change touches parsing, drag in a synthetic fixture of the affected format and
   confirm it routes and renders.

If you add test data, it must be synthetic: fictional hostnames and reserved documentation
addresses (RFC 5737 for IPv4, RFC 5398 for AS numbers). This applies equally to SCC XCCDF
fixtures and STIG Viewer checklists — build them to the published format with invented hosts.
Real exports are never acceptable, sanitized or otherwise.

## Session compatibility

Session files are a user-facing format. People hand partially-finished work to each other with
them, and old sessions get re-opened cycles later. Do not break loading an older session
without a migration path — `loadSession()` and `loadBaseline()` accept historical tool
identifiers on purpose.

## Releasing

Bump the version in three places:

1. the `<title>` tag
2. the header `.ver` span
3. `meta.ver` in `newState()`

Then add the entry to `CHANGELOG.md`.
