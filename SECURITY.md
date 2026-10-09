# Security Policy

Palisade compiles RMF control evidence from scan exports, on an air-gapped or NIPR workstation,
from a single HTML file. The people who run it are handling CUI on someone's accreditation
boundary. A vulnerability here is worth reporting carefully, and worth receiving carefully. This
document says how to do both.

## Reporting a vulnerability

**Use GitHub's private security advisory route:**

> **<https://github.com/lexen13/Palisade/security/advisories/new>**

Or, equivalently: the repository's **Security** tab → **Report a vulnerability**.

That route is private until we publish it, it keeps the report and the fix in one place, and it
does not require you to trust an email address you found in a file. **Please do not open a public
issue or a pull request for a security problem** — a public issue tells everyone else before the
people running it on an enclave have a build to move to.

No email address is published for this. If GitHub is unreachable from where you are — which is
likely, because the machines Palisade runs on usually cannot reach the internet at all — report it
from any machine that can, or hand it to whoever gave you the file.

### Please do not send us scan data

This is the one that matters for this project. A `.nessus` export, a session `.json`, a `.ckl`, an
XCCDF results file or an evidence package contains real hostnames, IP addresses, MAC addresses,
full software inventories, open-port data and enumerated accounts with their RIDs, groups and
admin flags. **That is CUI, and it must not be sent to a public repository — not in an advisory,
not in a screenshot, not in a stack trace.**

If you need to show us an input that triggers the bug, build a synthetic one: invented hostnames,
RFC 5737 documentation addresses for IPv4, RFC 5398 AS numbers. That is the same standard
`CONTRIBUTING.md` applies to test fixtures, and it is not a formality — it is the reason the
project has never had a spillage to clean up.

### What makes a report actionable

- The version — it is in the `<title>`, in the header, and on line 2 of the file.
- The sha256 of the file you ran, so we know you tested what we shipped.
- What you did, what happened, and what you expected instead.
- A synthetic input that reproduces it, if input is involved.
- Browser and version — this is a browser application, and the behaviour differs between engines.

### What happens next, and how fast

| Stage | Target |
|---|---|
| Acknowledgement that we received it | **5 business days** |
| Initial assessment — valid / not, and rough severity | **10 business days** |
| Fix or a stated plan with a date, for a confirmed valid report | **45 days** from the initial assessment |
| Public disclosure | Coordinated with you, normally when the fixed release ships |

Set your expectations against what this project is: two people, unpaid, no on-call rotation. Those
targets are what we intend to meet, not a service-level agreement, and there is no support
contract behind them. If a response time is a requirement for you, say so in the report and we
will tell you honestly whether we can meet it rather than letting you assume.

If a report goes unanswered past the acknowledgement window, disclose on whatever timetable you
think is right. You do not owe silence to a project that did not answer you.

## Supported versions

| Version | Supported |
|---|---|
| 2.9 (current) | Yes |
| 2.8 and earlier | No |

Only the current release is supported. There is no long-term-support branch and no backporting,
because there is nothing to backport *to* — a release is one file, so upgrading is replacing it.

This matters more than usual here: **2.7 and earlier contain two proven JavaScript-injection sinks
reachable from a crafted scan export, an uncapped decompression path, and a prototype-pollution
path that silently inverts the scan-detected versus inventory-only distinction in the compiled
evidence.** They are fixed in 2.8 and described in `CHANGELOG.md`. If you are running 2.7 or
earlier, replace the file.

**2.8 is also superseded.** The v2.9 audit (`docs/SECURITY-AUDIT-2.9.md`) found 19 high-severity
issues in 2.8. None of them executes script, but several produce wrong evidence from a hostile
scan or a crafted session: an "Unapproved" listing recorded as Approved, an Open CAT I dropped,
security tooling removed from a host reported as no change, a `__proto__` plugin ID that wedges
every later ingest. Others inject markup that can hide evidence or navigate the tab away. If you
are running 2.8, replace the file.

## Scope

**In scope** — the single file `palisade.html` at the current release, and the artifacts it
generates:

- Anything that lets scan-derived data become code in the page or in an exported artifact.
- Anything that causes wrong evidence: a parser that silently drops, mis-attributes or
  mis-merges data, or a control whose absence inverts a mark in the compiled output. For an
  evidence compiler this is as serious as a code-execution bug, and it is judged that way.
- Anything that puts data on the network. There should be nothing here to find: the file's CSP
  sets `default-src 'none'` and `connect-src 'none'`, and the shipped bytes contain zero call
  sites for `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or `EventSource` and zero
  `http://`, `https://` or `ftp://` strings. If you find a way around that, it is a serious
  finding and we want it.
- Anything that leaks CUI further than the operator asked — into an export, an evidence package,
  or a generated report.
- A way to defeat the integrity seal: making a modified script run while the page still loads
  normally.
- Denial of service through a crafted input file: a hang or a memory exhaustion that costs an
  operator their working session.

**Out of scope:**

- Browser and operating-system vulnerabilities. Report those to the vendor.
- Attacks that require the attacker to already be able to write to the file on disk. At that point
  they can replace the tool entirely. The seal does not make that visible either: someone who can
  edit the file can re-seal it, or neutralise the policy and leave the script untouched. The
  control for that attacker is the digest check below, against a value taken from the repository.
- `style-src 'unsafe-inline'`, absent a demonstrated impact. It is a known, documented residual:
  the file sets 481 `style=` attributes, CSS cannot execute, and every directive that could send
  anything anywhere is `'none'`. A working exploit changes this answer; a scanner flagging the
  directive does not.
- Downloads, the clipboard and printing not being governed by CSP. They are not, by design of the
  web platform, and we say so rather than claiming otherwise.
- Missing hardening with no exploit path, and automated-scanner output pasted without a working
  reproduction.
- Social engineering, physical access, and anything about GitHub itself rather than this code.

## Safe harbour

If you are researching in good faith under this policy, we will not pursue or support legal action
against you, and we will not ask a third party to. Specifically:

- We consider good-faith research under this policy to be authorized, and we will say so in
  writing if a question about it ever arises.
- We will not report you to law enforcement or to your employer for research conducted under
  this policy.
- If a third party brings action against you for research that followed this policy, we will make
  clear that it was authorized.

To stay inside it: test only against your own copy and your own synthetic data; do not access,
modify or exfiltrate anyone else's data; do not degrade anyone else's service; stop as soon as you
have a proof of concept and report it; and give us the acknowledgement window before going public.

Two limits we cannot wave away, and you should read them as real rather than as boilerplate.
First, **we can only speak for this project.** Palisade runs on somebody's accreditation boundary,
and this safe harbour does not authorize you to test on a network you do not own. Your
organization's rules of engagement govern that, not this file, and no sentence here overrides
them. Second, if you report in good faith and we disagree about severity, that is a disagreement,
not a breach of this policy — you keep the safe harbour.

## Verifying the file you have

One check that ties the copy to this project, and one that catches accidental damage.

```bash
sha256sum palisade.html
# 84ea3d3299d58bf4f0413d54c97b82772f80d19d460cad146d9815c524a32994   (v2.9, 572,143 bytes)
```

`MANIFEST.json` carries the same digest plus sha384, sha512 and the script-block hash;
`palisade.cdx.json` (CycloneDX 1.6) and `palisade.spdx.json` (SPDX 2.3) carry it too, and
`docs/SBOM.md` explains how to check all of it in about a minute.

The check that needs no tooling: the file's `script-src` is the SHA-256 of the file's own script
block, so **if a byte of that script has changed and the policy has not, the browser refuses to
run it**. The page loads styled and complete but entirely inert, with the expected hash named in
the console. If you open Palisade and the interface is there but nothing works, that is not a bug
to report. That is the seal, and you should get a clean copy.

Note what the seal does and does not tell you. It catches accidental damage and careless edits.
It does not catch someone who means it: they can re-seal an edited script, or neutralise the
policy, and the markup outside the script (every control and default) is not covered by the hash
at all. `node tools/seal.mjs palisade.html --verify` catches a neutralised or widened policy, but
only for whoever runs it. The seal also does not prove who produced the file: there is no code signature, and an `.html` file
cannot carry one a browser verifies. **Anyone can seal a file they wrote.** The digest above is
what ties a copy to this project, so get it from the repository rather than from the same place
you got the file.

## On BOD 20-01

CISA Binding Operational Directive 20-01 requires federal civilian executive branch **agencies** to
publish a vulnerability disclosure policy. **It binds agencies. It does not bind this project, and
this file is not issued under it.**

We wrote this policy because software that runs on an accreditation boundary should have one, and
BOD 20-01 happens to describe what a good one contains. Treat it as best practice voluntarily
adopted. Do not cite it as evidence that Palisade satisfies a federal directive, in an RMF package
or anywhere else — it is not that, and a reviewer who checks will be right to say so.

---

*Palisade 2.9 · MIT · Gavin Lee Domingo Johnson, Jacob Keith ·
<https://github.com/lexen13/Palisade>*
