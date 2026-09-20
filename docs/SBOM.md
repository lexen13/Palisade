# Palisade 2.8 — SBOM notes

Two files, one artifact, same facts:

| File | Format | Why both |
|---|---|---|
| `palisade.cdx.json` | CycloneDX 1.6 | Richer at expressing *completeness* (`compositions.aggregate`) |
| `palisade.spdx.json` | SPDX 2.3 | Some review pipelines accept only SPDX |

They describe the same file and carry the same digests. If they ever disagree, one of them has
been edited and neither should be trusted.

## The artifact they describe

| | |
|---|---|
| file | `palisade.html` |
| version | 2.8 |
| bytes | 521,771 |
| sha256 | `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` |
| sha384 | `40c8ee517b7a7bf15a686f1231cdb039f9a94570f681dec25afd68f44816131fd9003d42c8de24e3915353c72928612f` |
| sha512 | `c4b5f4f91245065eaeeb1d1d16bdc675f858606963d284c056a07e8b7e6cbfd1382cb9e9d4bace259a1a9c4f1f9983d41bf6fc61c11c0d73cc79d09907193df6` |
| line endings / BOM | LF only / none |
| licence | MIT |

Digests were computed twice, from the shipped bytes, by two implementations that share no code
(GNU coreutils 9.10 `sha256sum`/`sha384sum`/`sha512sum`, and CPython 3.14.6 `hashlib`). They
agree, and they agree with `MANIFEST.json` emitted by `tools/seal.mjs --manifest`.

## NTIA minimum elements — where each one lives

The seven data fields from *The Minimum Elements For a Software Bill of Materials* (NTIA, 14 July
2021). Both documents carry all seven.

| NTIA element | CycloneDX 1.6 (`palisade.cdx.json`) | SPDX 2.3 (`palisade.spdx.json`) |
|---|---|---|
| Supplier name | `metadata.supplier.name`, and `metadata.component.supplier.name` | `packages[0].supplier` (`Organization: …`), `originator` |
| Component name | `metadata.component.name` = `Palisade` | `packages[0].name` = `palisade` |
| Version of the component | `metadata.component.version` = `2.8` | `packages[0].versionInfo` = `2.8` |
| Other unique identifiers | `metadata.component.purl` = `pkg:generic/palisade@2.8`; `hashes[]` (SHA-256/384/512) | `packages[0].externalRefs[0].referenceLocator` (same purl); `checksums[]`; `packageVerificationCode` |
| Dependency relationship | `dependencies[0].dependsOn` = `[]`, plus `components` = `[]` and `compositions[0].aggregate` = `complete` | `relationships`: `DEPENDS_ON → NONE`, plus exactly one package and `CONTAINS` the one file |
| Author of SBOM data | `metadata.authors[0].name` | `creationInfo.creators` (`Person: …`, `Organization: …`, two `Tool:` entries) |
| Timestamp | `metadata.timestamp` | `creationInfo.created` |

No CPE is asserted in either document. Palisade has no entry in the NVD CPE dictionary, and
writing one would imply a registration that does not exist. The purl is the unique identifier.

## Why an empty `components` array is the strongest statement here

Most SBOMs are long, and length reads as diligence. It is the opposite. Every entry in a
components array is a thing somebody else wrote, shipped on a schedule you do not control, and
can push a new version of into your artifact. The list is the attack surface — an inventory of
who can change your software without asking you.

Palisade's is empty. Not "not yet populated", not "scanner found nothing": there is nothing to
populate it with. One file, authored in full by the two named authors, with no bundled library,
no vendored code, no CDN reference, no subresource-integrity attribute, no package-manager
manifest and no external `src` or `href`. There is no build step, so there is no build-time
dependency either — no compiler plugin, no bundler, no lockfile, nothing that resolves a name to
someone else's bytes. The bytes an assessor reads are the bytes that run.

That is worth stating precisely because of what it removes. A dependency-confusion attack needs a
dependency. A compromised transitive package needs a transitive package. A malicious postinstall
script needs an install step. A typosquatted CDN needs a CDN. None of those apply here, and the
empty array is the machine-readable form of that sentence.

Both documents say so **explicitly** rather than by omission, because an empty list is otherwise
ambiguous — it can mean "none" or it can mean "we did not look":

- CycloneDX: `"compositions": [{"aggregate": "complete", …}]` — the spec's own word for *this
  inventory is complete and the relationships are known*.
- SPDX: a `DEPENDS_ON` relationship whose `relatedSpdxElement` is the literal `NONE`, which the
  spec defines as an assertion of absence, distinct from `NOASSERTION`.

## How a reviewer machine-verifies it in under a minute

Do not take the SBOM's word for it. Every check below is a falsification test — a non-zero count
on any of the first thirteen disproves the empty inventory. Run from the repository root.

```bash
# 1  no external resource of any kind, of any scheme
grep -ciE '(https?|ftp)://'                     palisade.html   # 0
grep -ciE "(src|href)=[\"']//"                  palisade.html   # 0   protocol-relative CDN

# 2  no subresource anybody else controls
grep -ci  'integrity='                          palisade.html   # 0   SRI implies a remote dep
grep -ci  'crossorigin='                        palisade.html   # 0
grep -ciE '<script[^>]*src='                    palisade.html   # 0   no external script
grep -ci  '<link'                               palisade.html   # 0   no stylesheet, no font
grep -ci  '<img'                                palisade.html   # 0
grep -ciE '<(object|embed|applet)'              palisade.html   # 0
grep -ci  '@import'                             palisade.html   # 0   CSS can fetch too

# 3  no module system reaching for someone else's code
grep -ciE '^\s*import .* from'                  palisade.html   # 0
grep -ci  'require('                            palisade.html   # 0

# 4  no way to fetch one at runtime, and nowhere to cache one
grep -ciE '(fetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource)' palisade.html   # 0
grep -ciE '(localStorage|sessionStorage|indexedDB|document\.cookie)'  palisade.html   # 0

# 5  positive control — exactly one script block, and it is the app's own
grep -ci  '<script'                             palisade.html   # 1

# 6  no package-manager manifest anywhere in the repository
ls package.json package-lock.json yarn.lock pnpm-lock.yaml node_modules \
   requirements.txt Gemfile go.mod 2>&1 | grep -c 'No such file'   # 8 = none exist
git ls-files | grep -cE '(package|yarn|pnpm)-?lock|package\.json|node_modules'   # 0
```

Then confirm the SBOM describes the file actually in hand, and that the file is the one that was
reviewed:

```bash
sha256sum palisade.html                      # must equal the digest above
node tools/seal.mjs palisade.html --verify   # exit 0  (shipped in this repository)
bash tools/csp-lint.sh palisade.html         # RESULT: PASS

# sbom-check.py is NOT shipped in this repository -- it is in the review
# workspace bundle. Adjust the path to wherever you unpacked that.
python3 ../tools/sbom-check.py palisade.html palisade.cdx.json palisade.spdx.json
```

`seal.mjs` and `csp-lint.sh` ship **inside this repository** at `tools/`, because a reviewer
needs to verify the seal without being handed a second bundle; `.github/workflows/verify.yml`
runs both of them from the repository root on every push, pull request and tag. `sbom-check.py`
is *not* shipped: it lives in the review workspace beside the repository and is handed over as
part of the evidence bundle, so adjust its path to wherever you unpacked that. None of the three
is part of the single file a user receives, and none of them is needed to run Palisade.

The last of these re-derives every digest in both SBOMs from the shipped bytes and recomputes the
SPDX package verification code; it prints `RESULT: PASS -- 0 failures` when the documents and the
file agree. There is one more check the file performs on itself without any tooling: `script-src`
is the SHA-256 of the file's own script block, so if a byte of that block has changed, the page
loads inert rather than running modified code.

## Two limits on these documents, stated plainly

**They were structurally checked, not schema-validated.** `tools/sbom-check.py` enforces the
mandatory fields and the enum-valued fields of both specifications and recomputes every digest,
and both files parse under `python3 -m json.tool`. No canonical JSON-Schema validator
(`cyclonedx-cli validate`, `pyspdxtools`) was run — neither is installed on the authoring
workstation. If your pipeline runs one, run it; nothing here depends on our checker being the
authority.

**`packageVerificationCode` covers the distributed artifact only.** The SPDX package is scoped to
`palisade.html`, the one file a user receives. Repository documentation and release-verification
tooling are not shipped and are excluded, which is what makes the code reproducible from a single
file. The package `comment` field says so.
