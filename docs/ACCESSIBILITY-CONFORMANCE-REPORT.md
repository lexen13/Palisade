# Accessibility Conformance Report — Palisade v2.8

**VPAT® 2.5-shaped report — International Edition structure, WCAG 2.1 and Revised Section 508**

| | |
|---|---|
| **Name of Product/Version** | Palisade v2.8 (`palisade.html`, single file, 521,771 bytes) |
| **Product Description** | An offline scan-to-evidence compiler. A single HTML file, opened from `file://`, that reads Tenable/ACAS scan exports, SCC XCCDF results and STIG checklists and compiles RMF control evidence (STIG applicability, eMASS baselines, PPSM rows, POA&M drafts, account audits, asset inventories). No network calls, no dependencies, no install, no build step, no browser storage. |
| **Report Date** | 2026-09-11 |
| **Evaluated Artifact** | SHA-256 `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97`<br>SHA-384 `40c8ee517b7a7bf15a686f1231cdb039f9a94570f681dec25afd68f44816131fd9003d42c8de24e3915353c72928612f` |
| **Contact** | Gavin Lee Domingo Johnson; Jacob Keith. Repository issues. |
| **Notes** | This report covers the browser user interface of `palisade.html` and the self-contained HTML report it generates. It does not cover the CSV, TXT and ZIP artifacts it exports, which are data files outside the scope of WCAG. |
| **Evaluation Methods Used** | Automated measurement of the **rendered DOM** in Chromium 150.0.7871.181 (Linux, headless, driven over the DevTools Protocol against the real `file://` URL), using the tool's own built-in demo dataset — six synthetic hosts, no real scan data. All 18 views were activated and measured. Colour ratios were computed twice by independent paths: once from `getComputedStyle` on every rendered text node, and once by hand from the hex literals in the `<style>` block. The two agree to the second decimal on every shared pair. Keyboard reachability was measured by dispatching 260 real `Tab` key events through the protocol and recording `document.activeElement` after each. **No manual screen-reader testing (JAWS/NVDA/VoiceOver) was performed.** Criteria whose determination depends on assistive-technology behaviour are marked accordingly. |

---

## Conformance statement — read this first

**Palisade v2.8 does not conform to WCAG 2.1 Level AA.** This report is not a conformance
claim. It is a measured, itemised statement of where the product meets the criteria, where it
meets them partially, and where it does not, so that a reviewing authority can make its own
determination and so that the gaps can be scheduled rather than discovered.

Across the 47 rows of Tables 1 and 2 — which cover every Level A and AA criterion, with the
time-based-media criteria grouped — **24 are Supports, 14 are Partially Supports, 2 are Does Not
Support, and 7 are Not Applicable**. The specific defects, with the measurements behind them,
are in those tables and are summarised with named remediation in
[Remediation](#remediation-summary) at the end.

The two findings most likely to matter to a reviewing authority are:

1. **The STIG applicability matrix cannot be operated from a keyboard.** Its 138 cells (demo
   dataset) are `<td>` elements with a click handler, no `tabindex` and no key handler. 260
   `Tab` presses reached 46 distinct controls — the 18 workflow-rail buttons among them — and
   **zero** matrix cells. There is no alternative
   path to that function in the UI. This is SC 2.1.1, one of the two **Does Not Support**
   determinations; the other is SC 4.1.3, for which the product contains no live region at all.
2. **Row-level table inputs have no accessible name.** On the Software view with six demo hosts,
   485 rendered form controls resolve to no accessible name from any source. Their meaning is
   carried only by the column header they sit under.

Two things commonly assumed to be problems here were measured and are **not**:

- **Colour contrast is strong.** 2,781 visible text-bearing elements were measured across all 18
  views. Exactly one colour pair fails — a decorative `›` chevron. Every text token in the
  palette clears 4.5:1 by a wide margin; the lowest real text pair is 5.61:1.
- **Drag-and-drop ingest has a full keyboard-operable alternative.** Every file type the drop
  zone accepts is also accepted by the `Load scans` `<button>`, which is a native button,
  `tabIndex` 0, and reachable by `Tab`. One caveat, measured: the drop zone tells the user to
  "use **Load scan exports** above", but the button's visible label is **Load scans**. The
  alternative path exists and works; the instruction points at a label that is not on screen.

---

## Applicable standards

| Standard | Included in this report |
|---|---|
| WCAG 2.1 Level A | Yes — Table 1 |
| WCAG 2.1 Level AA | Yes — Table 2 |
| WCAG 2.1 Level AAA | No |
| Revised Section 508 (36 CFR 1194, Appendix A–C) | Yes — Chapters 3, 4, 5, 6 |
| EN 301 549 | Not separately assessed |

**Terms.** *Supports* — the functionality meets the criterion without known defects.
*Partially Supports* — some functionality meets the criterion; named defects remain.
*Does Not Support* — the majority of the functionality does not meet the criterion.
*Not Applicable* — the criterion is not relevant to this product.

---

## Measurement basis

Every figure quoted in this report was produced by instrumenting the shipped file. The headline
counts:

### Markup inventory — static source

| Element / attribute | Count in `palisade.html` |
|---|---|
| `aria-*` attributes | 11 (all `aria-label`) |
| `role=` attributes | 2 (both `role="img"`) |
| `<img>` elements | 0 |
| `alt` attributes | 0 (no `<img>` exists to carry one) |
| `<svg>` elements | 16 |
| `<label>` elements | 20 (6 bare, 11 wrapping a checkbox via `class="chk"`, 3 carrying only a `title`, a `style` or a generated class) |
| `<input>` elements | 53 |
| `<select>` / `<textarea>` | 6 / 3 |
| `<button>` elements | 149 |
| `<table>` / `<th>` | 30 / 190 |
| `tabindex` attributes | 0 |
| `aria-live`, `role="status"`, `role="alert"`, `<output>` | 0 |
| `autocomplete` attributes | 0 |
| `<fieldset>` / `<legend>` | 0 |
| `lang` on `<html>` | present, `lang="en"` |

### Markup inventory — rendered DOM, demo dataset loaded

| Measurement | Value |
|---|---|
| `aria-label` attributes present | 12 |
| `role="img"` (generated chart `<svg>`) | 3 |
| `<svg>` rendered | 13 — 3 with `role="img"` + `aria-label`; 6 inside buttons that carry visible text; 4 decorative, none marked `aria-hidden` |
| `<img>` rendered | 0 |
| Landmarks | `<header>` 1, `<nav>` 1 (`aria-label="Workflow stages"`), `<main>` 1, `<aside>` 2 |
| Keyboard-focusable controls, Overview view | 37 |
| Distinct `Tab` stops in one full cycle, STIG view | 46 elements (18 of them the workflow-rail buttons) |
| Visible `<table>` across all views | 16 |
| `<th>` rendered across all views | 194 — **0 carry `scope`**, **0 tables carry `<caption>`** |
| Skip links / in-page anchors | 0 / 0 |

### Colour — WCAG 2.1 relative luminance, computed by hand from the `<style>` block

Relative luminance `L = 0.2126·R + 0.7152·G + 0.0722·B`, each channel linearised as
`c/255 ≤ 0.03928 ? (c/255)/12.92 : ((c/255 + 0.055)/1.055)^2.4`. Contrast `(L₁+0.05)/(L₂+0.05)`.

| Token | Hex | R,G,B | R\_lin | G\_lin | B\_lin | **L** |
|---|---|---|---|---|---|---|
| `--bg` | `#0b1117` | 11,17,23 | 0.0033 | 0.0056 | 0.0086 | **0.0053** |
| `--panel` | `#131c26` | 19,28,38 | 0.0065 | 0.0116 | 0.0194 | **0.0111** |
| `--panel2` | `#1b2733` | 27,39,51 | 0.0110 | 0.0203 | 0.0331 | **0.0192** |
| `--line` | `#29394a` | 41,57,74 | 0.0222 | 0.0409 | 0.0685 | **0.0389** |
| `--text` | `#e8eff6` | 232,239,246 | 0.8070 | 0.8632 | 0.9216 | **0.8554** |
| `--dim` | `#95a9bc` | 149,169,188 | 0.3005 | 0.3968 | 0.5029 | **0.3840** |
| `--accent` | `#57c8de` | 87,200,222 | 0.0953 | 0.5776 | 0.7305 | **0.4861** |
| `--accent2` | `#6fd08a` | 111,208,138 | 0.1590 | 0.6308 | 0.2542 | **0.5033** |
| `--warn` | `#f0b429` | 240,180,41 | 0.8714 | 0.4564 | 0.0222 | **0.5133** |
| `--bad` | `#f0685f` | 240,104,95 | 0.8714 | 0.1384 | 0.1144 | **0.2925** |
| `--cui` | `#5b2ea6` | 91,46,166 | 0.1046 | 0.0273 | 0.3813 | **0.0693** |
| white | `#ffffff` | 255,255,255 | 1.0000 | 1.0000 | 1.0000 | **1.0000** |

**Resulting ratios.** Worked example for the body text pair:
`(0.8554 + 0.05) / (0.0053 + 0.05) = 0.9054 / 0.0553 = 16.36`.

| Foreground | Background | Where it is used | Ratio | Threshold | Result |
|---|---|---|---|---|---|
| `--text` `#e8eff6` | `--bg` `#0b1117` | body text on the page ground | **16.36** | 4.5 | PASS |
| `--text` `#e8eff6` | `--panel` `#131c26` | body text on a card | **14.82** | 4.5 | PASS |
| `--dim` `#95a9bc` | `--panel` `#131c26` | secondary / help text on a card | **7.10** | 4.5 | PASS |
| `--dim` `#95a9bc` | `--bg` `#0b1117` | secondary text on the page ground | **7.84** | 4.5 | PASS |
| `--dim` `#95a9bc` | `--panel2` `#1b2733` | secondary text on a raised surface | **6.27** | 4.5 | PASS |
| `--accent` `#57c8de` | `--panel` `#131c26` | section headings and accents | **8.78** | 4.5 | PASS |
| `--accent` `#57c8de` | `--bg` `#0b1117` | accent on the page ground | **9.69** | 4.5 | PASS |
| `--accent2` `#6fd08a` | `--panel` `#131c26` | pass / OK state text | **9.06** | 4.5 | PASS |
| `--warn` `#f0b429` | `--panel` `#131c26` | warning state text | **9.22** | 4.5 | PASS |
| `--bad` `#f0685f` | `--panel` `#131c26` | failure / open-finding text | **5.61** | 4.5 | PASS |
| `--bad` `#f0685f` | `--bg` `#0b1117` | failure on the page ground | **6.19** | 4.5 | PASS |
| `#ffffff` | `--cui` `#5b2ea6` | **CUI banner**, 11.5px bold — *not* large text | **8.80** | 4.5 | PASS |
| `--accent` `#57c8de` | `--bg` `#0b1117` | 25px/600 stat figures (large text) | **9.69** | 3.0 | PASS |
| `--warn` `#f0b429` | `--bg` `#0b1117` | 25px/600 stat figures (large text) | **10.18** | 3.0 | PASS |
| `--line` `#29394a` | `--bg` `#0b1117` | `.flowstrip .arr` chevron glyph, 16px | **1.61** | 4.5 | **FAIL** |
| `--line` `#29394a` | `--panel` `#131c26` | resting border of text inputs / selects (non-text) | **1.46** | 3.0 | **FAIL** |
| `--line` `#29394a` | `--bg` `#0b1117` | resting border against the control's own fill (non-text) | **1.61** | 3.0 | **FAIL** |
| `--accent` `#57c8de` | `--panel2` `#1b2733` | **focused** control border (non-text) | **7.74** | 3.0 | PASS |

The `.cui-banner` deserves a specific note because it is the marking banner an assessor will
look at first. It is `#fff` on `#5b2ea6` at `font-size:11.5px; font-weight:700`. 11.5px bold is
**below** the WCAG large-text threshold (24px, or 18.66px when bold), so it is held to 4.5:1,
not 3:1. It measures **8.80:1** and passes on the stricter threshold.

**Independent cross-check.** The same ratios were computed a second time by walking every
rendered text element with `getComputedStyle`, compositing translucent backgrounds over their
ancestors, and applying the same formula in-browser. Across 2,781 visible text-bearing elements
in 18 views, 40 distinct foreground/background/size combinations were found on the Overview view
alone; the in-browser results match the hand computation above on every shared pair
(16.36, 14.82, 9.69, 9.22, 9.06, 8.80, 8.78, 7.84, 7.10, 6.27, 5.61, 1.61). **Three elements
fail, all of them the same `›` chevron** at 1.61:1. No other contrast failure exists anywhere in
the product.

### Reflow and zoom — measured

| Viewport | Equivalent | Document scroll width | Client width | Horizontal scroll? |
|---|---|---|---|---|
| 1280 CSS px | 100% | 1280 | 1280 | No |
| 640 CSS px | **200% browser zoom** | 640 | 640 | No |
| 320 CSS px | 400% zoom / SC 1.4.10 test width | **475** | 320 | **Yes — overflows by 155px** |

At 320 CSS px the Overview view overflows by 155px. The data views reflow correctly: the
Software view measured 320/320 with no overflow at the same width. The nav rail, the `<h1>` and
the primary action button all remain rendered and non-zero-sized at every width tested.

### Text spacing — measured

With `line-height:1.5`, `letter-spacing:0.12em`, `word-spacing:0.16em` and `p{margin-bottom:2em}`
forced over everything: 38 headings, paragraphs, cards and buttons examined, **0 clipped**, and
**0px** of document overflow introduced.

---

## Table 1 — WCAG 2.1 Level A

| Criterion | Conformance | Remarks and explanations |
|---|---|---|
| **1.1.1** Non-text Content | **Partially Supports** | There are no `<img>` elements, so there is no missing `alt` text. Of 13 rendered `<svg>`, the 3 generated charts carry `role="img"` and an `aria-label` naming the chart; 6 sit inside buttons whose visible text supplies the button's accessible name; 4 are decorative icons that are **not** marked `aria-hidden="true"`. The chart `aria-label` gives the chart a name but not a text alternative conveying its data. The same data is present as a table in the same view and in the matching CSV export, which serves the equivalent purpose, but no programmatic association states that. |
| **1.2.x** Time-based Media | **Not Applicable** | The product contains no audio, video, or time-based media of any kind. |
| **1.3.1** Info and Relationships | **Partially Supports** | Semantic structure is largely correct: `<header>`, `<nav aria-label="Workflow stages">`, `<main>`, `<aside>`, real `<table>`/`<thead>`/`<th>`, and a heading hierarchy. Four defects were measured. (a) **All 194 rendered `<th>` across the 16 visible tables carry no `scope` attribute, and no table carries a `<caption>`.** Browsers infer column association for these simple single-header-row tables, so this is a robustness gap rather than a demonstrated loss of relationship, but it is not explicit. (b) **Settings fields use `<label>` with neither a `for` attribute nor wrapping**, e.g. `<div class="field"><label>Banner text</label><input id="bannerText"></div>` — the label is visually adjacent but not programmatically associated; 49 controls on the Settings view are affected. (c) **Row-level table inputs carry no label at all**: 485 on Software, 154 on Assets, 111 on PPSM, 13 on STIG (demo dataset; counts scale with data volume). (d) No `<fieldset>`/`<legend>` groups the related checkbox sets in the report builder. |
| **1.3.2** Meaningful Sequence | **Supports** | DOM order matches visual order throughout. No CSS repositioning changes reading order. |
| **1.3.3** Sensory Characteristics | **Supports** | Instructions identify controls by name rather than by shape, colour or position alone — the drop zone reads "or use **Load scan exports** above" rather than "the button on the right". The criterion is met. *Note, however, that the name it gives is wrong:* the button's visible label is **Load scans**. That is a labelling defect, recorded under 3.3.2, not a sensory-characteristics failure. |
| **1.4.1** Use of Color | **Partially Supports** | Most states pair colour with a glyph or text — the STIG matrix prints `x` for applicable, findings show `✗`/`✓` alongside the colour. One state does not: **`.stigcell.manual` is indicated only by `outline:1px dashed var(--warn)`**, with no text, no `title` and no accessible name, so "this applicability call was overridden by a human" is conveyed by a purely visual treatment. |
| **1.4.2** Audio Control | **Not Applicable** | No audio. |
| **2.1.1** Keyboard | **Does Not Support** | **The STIG applicability matrix is not keyboard-operable.** Cells are emitted as `<td class="stigcell" data-click="toggleStig">` with no `tabindex`, no `role`, and no key handler; `element.focus()` reports `tabIndex = -1`. 260 dispatched `Tab` presses on the STIG view reached 46 distinct controls — 18 of them the workflow-rail buttons — and **0 of the 138 matrix cells present**. `toggleStig()` is the only path to setting an applicability override, so this function has no keyboard alternative. Two lesser instances share the defect: host names (`<span data-click="openHostDetail">`) and host-count pills (`<span class="pill" data-click="toggleHostlist">`) are also unreachable by keyboard. **Ingest is not affected** — see the note below this table. |
| **2.1.2** No Keyboard Trap | **Supports** | Focus can be moved away from every component with `Tab`/`Shift+Tab`. A 260-press traversal cycled and wrapped without becoming stuck. |
| **2.1.4** Character Key Shortcuts | **Supports** | The only key handlers are on `Escape`. No single-character shortcuts exist. |
| **2.2.1** Timing Adjustable | **Supports** | No time limits. |
| **2.2.2** Pause, Stop, Hide | **Supports** | No auto-updating, blinking or scrolling content. The only motion is a 0.25s panel transition, and `@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}` is honoured. |
| **2.3.1** Three Flashes or Below | **Supports** | Nothing flashes. |
| **2.4.1** Bypass Blocks | **Partially Supports** | There is **no skip link** — the product contains 0 in-page anchors. `<header>`, `<nav aria-label="Workflow stages">` and `<main>` landmarks are present, and every view begins with a heading, which are the landmark- and heading-based bypass mechanisms. However, the ~20-button workflow rail is re-traversed before pane content on every view, and a keyboard user has no single-keystroke way past it. |
| **2.4.2** Page Titled | **Supports** | `<title>Palisade v2.8</title>`. The generated report document also emits its own `<title>`. |
| **2.4.3** Focus Order | **Partially Supports** | Focus order within a view follows visual order. Two defects. (a) **Closed overlays remain in the tab order.** `.drawer` is hidden with `transform:translateX(102%)` and `.sheet` with `opacity:0`; neither removes the subtree from focus. Measured: 7 controls inside 4 closed overlays (`#helpDrawer` 2, `#hostDrawer` 1, `#glossSheet` 2, `#wizSheet` 2) accept keyboard focus while invisible, and they appeared in the live traversal. (b) **Focus is not moved into an overlay when it opens** — after activating Help, `document.activeElement` remains `BODY`, and it is not restored to the invoking control on close. (c) **`Escape` dismisses three of the four overlays but not the fourth.** A `keydown` handler closes `#helpDrawer`, `#glossSheet` and `#wizSheet`; `closeHostDetail()` is not in that handler, so the host detail drawer — the one reached most often, by clicking a host name — stays open. Verified by dispatching real `Escape` key events and reading the `open` class: help `drawer open → drawer`, glossary `sheet open → sheet`, host `drawer open → drawer open`. |
| **2.4.4** Link Purpose (In Context) | **Not Applicable** | The product renders 0 `<a href>` links. All navigation and activation is via `<button>`. |
| **2.5.1** Pointer Gestures | **Supports** | Dropping a file is an operating-system drag, not a path-based or multipoint gesture within the content, and a single-pointer alternative (the file-picker buttons) exists for every accepted type. |
| **2.5.2** Pointer Cancellation | **Supports** | All activation is on the default `click` (up-event); no down-event handlers execute functions. |
| **2.5.3** Label in Name | **Supports** | Buttons are named by their visible text content. Where a `title` is also present it is supplementary; per the accessible-name computation the visible text wins, so the accessible name contains the visible label. |
| **2.5.4** Motion Actuation | **Not Applicable** | No device-motion or user-motion actuation. |
| **3.1.1** Language of Page | **Supports** | `<html lang="en">`. The generated report document also emits `lang`. |
| **3.2.1** On Focus | **Supports** | Focus alone never changes context. |
| **3.2.2** On Input | **Supports** | Changing a value updates the view it belongs to; it does not move focus, open a window, or change context. |
| **3.3.1** Error Identification | **Partially Supports** | Ingest errors are described in text in the file list and the status bar, and unrecognised files report why they did not route — the description itself is good. However the status bar carries **no `role="status"` and no `aria-live`**, so an error surfaced there is not announced; a screen-reader user is not told an ingest failed. See 4.1.3. |
| **3.3.2** Labels or Instructions | **Partially Supports** | Visible labels and per-tab instructions are present throughout and are unusually thorough. Three defects: labels are not programmatically associated in the Settings `.field` pattern (49 controls); **two search fields — `#swFilter` and `#glossSearch` — are named by `placeholder` only**, which disappears once the user types; and **the ingest instruction names a control that does not exist under that name** — the drop zone says "or use **Load scan exports** above" while the button reads **Load scans**. A user searching the screen for the words they were given will not find them. |
| **4.1.1** Parsing | **Supports** | Recorded as Supports per the W3C erratum that obsoletes this criterion: as of the WCAG 2.1 errata and WCAG 2.2, 4.1.1 is always satisfied for content parsed by a browser. No duplicate `id` or unclosed-element defect was observed in the rendered DOM. |
| **4.1.2** Name, Role, Value | **Partially Supports** | Native elements supply correct roles and values throughout; the product uses real `<button>`, `<input>`, `<select>` and `<table>` rather than reimplementing them, which is why most of this criterion holds. Two defects. (a) **Controls with no accessible name from any source**: 485 on Software, 154 on Assets, 111 on PPSM, 49 on Settings, 13 on STIG (demo dataset). (b) **Elements carrying a role they do not declare**: the STIG matrix cells act as toggle buttons but expose `role="cell"` with no name, no `role="button"` and no `aria-pressed` state, so their on/off condition is not programmatically determinable. |

> **Note on drag-and-drop ingest, relevant to the 2.1.1 determination.** The drop target
> `<div id="drop">` has no `tabindex`, no `role` and no key handler, and is not keyboard
> focusable. It is **not** the only path. `Load scans` is a native `<button>` with `tabIndex` 0,
> visible, enabled and reachable by `Tab`; it drives `<input type="file" id="fileIn">` whose
> `accept` list — `.nessus,.xml,.csv,.tsv,.xlsx,.ckl,.cklb,.zip,.json` — covers **every** format
> the drop zone accepts. Nine further context-specific picker buttons exist (sessions, HW/SW
> listings, approvals, baselines, intel sheets, trend sessions, environment profiles), each a
> native keyboard-operable button. The drop zone's instruction text points the user at that
> button rather than leaving the alternative undiscoverable. Ingest is therefore keyboard-
> operable, and 2.1.1 fails on the STIG matrix, not on ingest. The instruction does name the
> button wrongly — it says "Load scan exports" where the visible label is "Load scans" — and
> that mismatch is recorded under 3.3.2.

---

## Table 2 — WCAG 2.1 Level AA

| Criterion | Conformance | Remarks and explanations |
|---|---|---|
| **1.2.4 / 1.2.5** Captions (Live), Audio Description | **Not Applicable** | No time-based media. |
| **1.3.4** Orientation | **Supports** | No orientation lock; layout is viewport-driven. |
| **1.3.5** Identify Input Purpose | **Not Applicable** | No `autocomplete` attributes are present, and none are required: the product collects no information *about the user*. Every input holds site configuration or scan-derived evidence, none of which maps to an Input Purpose token in the WCAG list. |
| **1.4.3** Contrast (Minimum) | **Partially Supports** | 2,781 visible text-bearing elements measured across 18 views. Every text colour token clears 4.5:1 with substantial margin — the lowest real text pair is `--bad` on `--panel` at **5.61:1**, and the CUI banner, held to 4.5:1 because 11.5px bold is not large text, measures **8.80:1**. **One pair fails: `.flowstrip .arr`, the `›` chevron between workflow steps, is `--line #29394a` on `--bg #0b1117` at 16px — 1.61:1**, affecting 3 elements on the Overview view. It is decorative but is rendered as real text and is not marked as decoration, so it is counted as a failure rather than excused. |
| **1.4.4** Resize Text | **Supports** | Measured at a 640 CSS px viewport, the equivalent of 200% browser zoom on a 1280px window: **no horizontal scrolling, no overflow, and the rail, heading and primary action all remain rendered**. *Advisory, not a failure:* all font sizes are declared in `px`, so Firefox's "zoom text only" mode does not scale them. SC 1.4.4 is satisfied by page zoom, which works. |
| **1.4.5** Images of Text | **Supports** | No images of text. All text is live text. |
| **1.4.10** Reflow | **Partially Supports** | At the 320 CSS px test width the **Overview view overflows by 155px** (document scroll width 475 against a 320 client width), producing two-dimensional scrolling. The data views do reflow: the Software view measured 320/320 with zero overflow at the same width. The failure is confined to the Overview layout. |
| **1.4.11** Non-text Contrast | **Partially Supports** | **Focus indicators pass and pass well.** `button:focus-visible` draws `2px solid var(--focus) #57c8de` at **9.69:1** against the page ground; text inputs, selects and in-table row controls change their border to `--accent #57c8de`, measured at **9.69:1** against the control fill and **8.78–9.69:1** against the surrounding surface. **Resting component boundaries fail.** Every text input, select and textarea is `background:var(--bg) #0b1117; border:1px solid var(--line) #29394a` sitting on `--panel #131c26`: the border measures **1.61:1** against the control's own fill and **1.46:1** against the card behind it, and the fill measures 1.10:1 against that card. The boundary that identifies an unfocused input is therefore well below the required 3:1. |
| **1.4.12** Text Spacing | **Supports** | Measured with the full WCAG text-spacing override applied: 38 components examined, 0 clipped, 0px document overflow introduced. |
| **1.4.13** Content on Hover or Focus | **Supports** | The only hover/focus content is the browser's native `title` tooltip, which is user-agent rendered and outside the author's control. No custom tooltips, popovers or hover panels exist. |
| **2.4.5** Multiple Ways | **Not Applicable** | Palisade is a single page. The criterion applies to sets of web pages. |
| **2.4.6** Headings and Labels | **Partially Supports** | Headings are descriptive and each view opens with one. Two defects. (a) **Labels** — see 3.3.2 and 4.1.2; many controls have no programmatic label. (b) **Heading outline** — one genuine level skip exists on the Reports view (`h2` "2 — What goes in it" → `h4` "Summary", with no `h3` between). On five further views (`stigcompliance`, `software`, `accounts`, `delta`, `trend`) a measured `h1 → h3` skip is produced not by the view's own content but by the `h3` headings inside the *closed* Help and Host drawers, which remain in the document outline — the same root cause as the 2.4.3 finding. Two `<h1>` elements render per view (the application title and the view title). |
| **2.4.7** Focus Visible | **Partially Supports** | Almost every keyboard-focusable control shows a strong visible focus indicator, verified by focusing each control class and diffing computed style. Buttons gain `2px solid #57c8de` (9.69:1). Inputs, selects and textareas replace `outline` with a border colour change from `#29394a` to `#57c8de` — a genuine, high-contrast visible change (the two colours differ by 6.03:1 from each other). *One narrow exception:* `<input type="number" id="staleDays">` carries neither class nor `.field` ancestry, so it falls through to the user-agent default outline, which Chromium draws as `auto 1px rgb(16,16,16)` — near-black on a dark ground, measured at **1.00:1** against the control fill and 1.11:1 against the surrounding surface. That single control's focus indicator is effectively invisible, so the criterion is recorded as Partially Supports rather than Supports, on the strength of the other 36 focusable controls on that view. |
| **3.1.2** Language of Parts | **Supports** | Content is wholly in English; no passages require a different `lang`. |
| **3.2.3** Consistent Navigation | **Supports** | The workflow rail is identical and in the same relative order on every view. |
| **3.2.4** Consistent Identification | **Supports** | Components with the same function carry the same label and icon throughout. |
| **3.3.3** Error Suggestion | **Partially Supports** | Where an input is rejected the tool says why and what the accepted shape is — an unrecognised file reports the reason rather than failing silently, and the configuration editors name the offending key. The suggestion text itself is good. It is delivered in the status bar with no live region, so it is not announced — the same defect as 3.3.1 and 4.1.3. |
| **3.3.4** Error Prevention (Legal, Financial, Data) | **Supports** | Destructive actions (`Clear all`) confirm before proceeding, and all work is reversible by re-loading a saved session file. No legal, financial or transactional commitments are made. |
| **4.1.3** Status Messages | **Does Not Support** *(see note)* | The product contains **0 `aria-live` attributes, 0 `role="status"`, 0 `role="alert"`, 0 `role="log"` and 0 `<output>` elements**. `<div class="statusbar" id="statusbar">` carries genuine status content — the measured value after loading demo data was *"Demo dataset loaded: 6 example hosts…"* — and it is updated in place without any mechanism to announce it. Ingest results, export completion and error text all surface here. **Determination note:** this is recorded as *Does Not Support* on the measured absence of any status-message mechanism. It was not confirmed with a screen reader, and the remediation is a single attribute. |

---

## Revised Section 508 Report

### Chapter 3 — Functional Performance Criteria (§ 302)

| Criterion | Conformance | Remarks |
|---|---|---|
| **302.1** Without Vision | **Partially Supports** | Semantic HTML, landmarks, heading structure and native controls give a screen-reader user most of the product. Blocked: the STIG applicability matrix cannot be reached or operated (2.1.1); 485+ row-level inputs have no accessible name (4.1.2); status and error messages are not announced (4.1.3). |
| **302.2** With Limited Vision | **Partially Supports** | Contrast is strong — every text token clears 4.5:1, most by 7:1 or better — and 200% zoom is clean. Limits: reflow breaks at 320 CSS px on Overview (1.4.10); resting input borders are at 1.46:1 (1.4.11); one focus indicator is invisible (2.4.7); text is sized in `px` so text-only zoom does not scale it. |
| **302.3** Without Perception of Color | **Partially Supports** | States generally pair colour with a glyph. The STIG "manual override" state is conveyed by a dashed outline alone with no text equivalent (1.4.1). |
| **302.4** Without Hearing | **Supports** | No audio output. |
| **302.5** With Limited Hearing | **Supports** | No audio output. |
| **302.6** Without Speech | **Supports** | No speech input. |
| **302.7** With Limited Manipulation | **Partially Supports** | Ingest, navigation, filtering, configuration and every export are keyboard-operable. The STIG matrix, host-name drill-down and host-count pills are pointer-only (2.1.1). Measured target sizes are generous — matrix cells 82×51 px, rail buttons 189×30 px, primary buttons 128×32 px. |
| **302.8** With Limited Reach and Strength | **Supports** | No sustained input, no simultaneous actions, no timed interactions. |
| **302.9** With Limited Language, Cognitive, and Learning Abilities | **Supports** | A first-run wizard, a workflow rail ordered by the stages of the task, a one-line description at the top of every view, plain-language per-view help, a searchable glossary and a demo dataset are all built in. Limitations are stated in the product's own documentation rather than left implicit. |

### Chapter 4 — Hardware (§ 402–415)

**Not Applicable.** Palisade is a software artifact — a single HTML file. It includes no
hardware component, no closed functionality, and no locked-down platform.

### Chapter 5 — Software (§ 501–504)

| Criterion | Conformance | Remarks |
|---|---|---|
| **501.1** Scope — incorporation of WCAG | **Partially Supports** | See Tables 1 and 2. |
| **502.2.1** User Control of Accessibility Features | **Supports** | The product neither disrupts nor overrides platform accessibility features. It honours `prefers-reduced-motion`. It sets no browser storage, installs nothing, and registers no global shortcut beyond `Escape`. |
| **502.2.2** No Disruption of Accessibility Features | **Supports** | It runs inside the browser's own sandbox with `default-src 'none'` and makes no network call, so it cannot interfere with assistive technology running on the platform. |
| **502.3.x** Accessibility Services / Platform Accessibility API | **Partially Supports** | The product relies on the browser's own mapping of standard HTML to the platform accessibility API and does not reimplement controls in script — which is why role and value are largely correct. Where it departs from standard elements (the `<td>`-based matrix toggles, the unlabelled row inputs) name, role and state are not exposed. See 4.1.2. |
| **502.4** Platform Accessibility Features | **Not Applicable** | Palisade is not a platform. |
| **503.2** User Preferences | **Supports** | The product does not override user or platform display settings; it defines its own palette but respects browser zoom and reduced-motion preferences. |
| **503.3** Alternative User Interfaces | **Not Applicable** | No alternative UI is provided that would need to meet 503.3. |
| **503.4** User Controls for Captions / Audio Description | **Not Applicable** | No media player. |
| **504.2** Authoring Tools — content creation | **Partially Supports** | Palisade generates a self-contained HTML report, so it functions as an authoring tool for that artifact. The generated document was measured: it declares `lang`, emits a `<title>`, uses a real heading hierarchy (`h1`, `h2`), marks its 3 chart `<svg>` with `role="img"` and an `aria-label`, contains 0 `<img>` (so no missing `alt`), and carries its own restrictive CSP `<meta>`. **Its 20 `<th>` carry no `scope` attribute** and its tables carry no `<caption>`. The preview is rendered in `<iframe title="Report preview" sandbox="allow-same-origin allow-modals">`. The product does not offer a mode that guarantees WCAG-conforming output. |
| **504.3** Prompts | **Not Applicable** | The product does not prompt for author-supplied alternative content, because the content it generates is derived from scan data rather than authored. |
| **504.4** Templates | **Partially Supports** | The report presets ship as data (named lists of section ids) rather than markup templates, so the same generator — with the `<th scope>` and `<caption>` gap noted in 504.2 — produces every preset. No preset is more or less accessible than another. |

### Chapter 6 — Support Documentation and Services (§ 601–603)

| Criterion | Conformance | Remarks |
|---|---|---|
| **602.2** Accessibility and Compatibility Features | **Supports** | This report documents them, including the keyboard-operable alternative to drag-and-drop ingest. |
| **602.3** Electronic Support Documentation | **Partially Supports** | All documentation is Markdown and plain text in the repository — inherently accessible as source and rendered by GitHub as semantic HTML. It has not itself been evaluated against WCAG 2.1 AA. |
| **602.4** Alternate Formats for Non-Electronic Support Documentation | **Not Applicable** | No non-electronic documentation exists. |
| **603.2 / 603.3** Support Services | **Not Applicable** | The product is MIT-licensed open source with no support contract. Issues are handled through the repository. |

---

## Remediation summary

Every item below is a specific, bounded change. None requires restructuring the product, and
none conflicts with the hard constraints the project holds itself to (single file, no
dependencies, no network, no browser storage, no build step). **Any edit to the script block
invalidates the CSP hash and renders the page inert until it is re-sealed with
`node tools/seal.mjs palisade.html --seal`.**

| # | Criterion | Defect, as measured | Remediation | Size |
|---|---|---|---|---|
| 1 | **2.1.1**, 4.1.2 | 138 STIG matrix cells are `<td data-click>` with `tabIndex -1`; 0 reachable in 260 `Tab` presses; no alternative path exists | Emit each cell as `<td><button type="button" role="switch" aria-pressed="…" aria-label="<product> on <host>">` , or add `tabindex="0" role="button" aria-pressed` plus an `Enter`/`Space` handler on the existing `<td>` | Small — one template string in `renderSTIG` plus one delegated key handler |
| 2 | **4.1.2**, 1.3.1, 3.3.2 | 485 / 154 / 111 / 49 row-level and settings controls resolve to no accessible name | Add `aria-label` built from the column header and the row key at the point each input is generated; add `for`/`id` to the `.field` label pattern | Small — a handful of generator sites |
| 3 | **4.1.3**, 3.3.1, 3.3.3 | 0 live regions anywhere; the status bar updates silently | `<div class="statusbar" id="statusbar" role="status" aria-live="polite">` | **One attribute pair** |
| 4 | **2.4.3**, 2.4.6 | 7 controls inside 4 closed overlays take keyboard focus; their `h3` headings pollute the outline of every view; `Escape` does not close the host drawer | Add `inert` to `.drawer`/`.sheet` when closed (or `visibility:hidden` in the closed state, with `visibility:visible` under `.open`); move focus into the overlay on open and restore it on close; add `closeHostDetail()` to the existing `Escape` handler | Small — 2 CSS rules, the open/close functions, and one call added to a handler that already exists |
| 5 | **1.4.11** | Resting input border `--line` on `--panel` = 1.46:1; on its own fill = 1.61:1 | Raise the resting border of `.inp`, `.sel`, `.field input`, `td input`, `td select`, `textarea.cfg` to a token at ≥3:1 against both the fill and the card — `--dim #95a9bc` measures 7.84:1 on `--bg` and 7.10:1 on `--panel` | One CSS token substitution |
| 6 | **1.4.3** | `.flowstrip .arr` at 1.61:1, 3 elements | Either mark it decorative (`aria-hidden="true"` and render via CSS `::after`), or raise it to `--dim` (7.84:1 on `--bg`) | One CSS rule |
| 7 | **1.4.10** | Overview overflows 155px at 320 CSS px | Allow the Overview card grid and the flow strip to wrap to one column below ~480px | One media query |
| 8 | **2.4.7** | `#staleDays` falls through to the UA default outline at 1.00:1 on a dark ground | Give it the `.inp` class, or extend the `:focus` rule to bare `input[type=number]` | One selector |
| 9 | **1.3.1**, 504.2 | 194 rendered `<th>` and 20 in the generated report carry no `scope`; 0 tables carry `<caption>` | Emit `scope="col"` on header cells and `scope="row"` on the host-name column; add a `<caption>` naming each table and its control mapping — which the exports already carry in their headers | Small, mechanical, and improves the generated report at the same time |
| 10 | **2.4.1** | 0 skip links; ~20 rail buttons re-traversed per view | Add a visually-hidden, focus-visible `<a href="#main">Skip to content</a>` as the first focusable element and `id="main"` on `<main>` | One element, one id |
| 11 | **1.1.1** | 4 decorative `<svg>` not marked hidden; chart `aria-label` names but does not describe | `aria-hidden="true"` on decorative icons; add `<desc>` to chart `<svg>` or `aria-describedby` pointing at the data table already rendered beside it | Small |
| 12 | **3.3.2** | The drop zone instructs the user to press "Load scan exports"; the button says "Load scans" | Make the two strings agree — change either one. The button's `title` ("Load .nessus or Tenable CSV exports") suggests the longer label was the intended one | One string |
| 13 | **1.4.1** | `.stigcell.manual` state is a dashed outline with no text equivalent | Add `title` and `aria-label` text, or a visible marker glyph, for the manual-override state | One template string |

Items 3, 5, 6, 8, 10 and 12 are single-line changes that between them clear or materially improve
five criteria. Items 1 and 2 are the substantive work.

---

## Scope, honesty and limits of this report

- **This is not a conformance claim.** Palisade v2.8 does not conform to WCAG 2.1 Level AA. The
  criteria that prevent it are named in Tables 1 and 2 with the measurements behind them.
- **No screen-reader testing was performed.** No JAWS, NVDA, VoiceOver or Orca session informs
  any determination here. Criteria whose real-world outcome depends on assistive-technology
  behaviour — particularly 1.1.1, 4.1.2 and 4.1.3 — are recorded from measured markup and
  structure. A determination reached by measurement can be wrong in the user's favour as well as
  against it; 4.1.3 in particular is recorded as *Does Not Support* on the absence of any live
  region, which is a property of the file, not an observed screen-reader outcome.
- **One browser engine.** All rendered-DOM measurement was performed in Chromium 150.0.7871.181
  on Linux. Firefox and Safari were not tested. Focus-indicator behaviour and the default
  user-agent outline noted under 2.4.7 are engine-specific.
- **The demo dataset, not production data.** Counts of rendered controls, table cells and text
  elements were taken with the built-in six-host synthetic dataset. Counts that scale with data
  volume — the 485 unlabelled Software inputs, the 194 `<th>`, the 138 matrix cells — will be
  larger against a real enclave scan. The *proportion* failing does not change.
- **Exported CSV, TXT and ZIP artifacts are out of scope.** They are data files, not web
  content. The generated HTML report **is** in scope and is assessed under 504.2.
- **The evaluated artifact is fixed by hash.** Any file whose SHA-256 is not
  `fd2f80e9da6b29bb8d1a0b19330bfe007ffe7361d3c1d83b358ced8136befa97` is not the artifact this
  report describes.

## Reproducing these measurements

Nothing here requires trusting this document. The regression gate in `baseline/harness.mjs`
drives the same Chromium instance over the same `file://` URL with no external packages. The
specific measurements above were produced by the same mechanism: load the file, dismiss the
first-run wizard, click the real **Load demo data** button, walk all 18 views, and read the
rendered DOM.

The contrast table can be checked without a browser at all — the token hex values are in the
`:root` block of the `<style>` element at the top of `palisade.html`, and the arithmetic is the
WCAG 2.1 formula reproduced in full above.

---

*VPAT® is a registered service mark of the Information Technology Industry Council (ITI). This
document follows the structure of VPAT 2.5 Rev INT. It is not endorsed by, or affiliated with,
ITI.*
