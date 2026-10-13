# sealdrop desktop: UI design brief (0.2)

Status: governs Task 15 (React screens). A frontend developer should be able to build all five screens from this file and the two CSS files without asking the designer anything.

Files this brief ships with:

- `apps/desktop/src/styles/tokens.css`: the fixed palette (verbatim from the Task 13 brief) plus appended type, spacing, elevation and accessibility tokens.
- `apps/desktop/src/styles/neu.css`: the fixed neumorphic classes (verbatim) plus appended layout, field, chip, badge, countdown, progress, list, dialog and accessibility classes.
- Reference images (style only, not layout): `docs/design/reference/reference-1.jpg`, `reference-2.jpg`.
- Source of truth for behaviour: `docs/superpowers/specs/2026-10-13-sealdrop-core-cli-desktop-design.md` section 9 (desktop app) and 5.5 (timed release). If this brief and the spec disagree, the spec wins; say so in the PR.

How to read it: section 1 is the visual system, section 2 defines the nine primitives, section 3 is the shell shared by all screens, sections 4 to 8 are the five screens (wireframe, components, copy, states, accessibility), section 9 is the global accessibility rules, section 10 is "what the app must never do", section 11 is the fixed backend contract: the Tauri commands the screens call and what they return.

Tone of the product: a quiet security tool. Whimsy lives in the shapes (soft tiles, round pills, a pastel palette), never in the copy. Sentence case, second person, no exclamation marks, no emoji, no jokes, no words like "secure", "safe", "unbreakable" or "guaranteed".

---

## 1. Visual system

### 1.1 Feel

Take from the references: warm off-white base, tiles and pills that look pressed out of the same material as the background, dusty pink, periwinkle blue and sage as the only colours, rounded sans type, small two-tone glyphs, one pink "slab" holding a big number (the clock in reference 1, the date in reference 2). Do not take from them: photo tiles, mascot faces, wavy dock, page dots, phone aspect ratio. sealdrop is a 1120 x 760 desktop window with real content, so most of the surface is quiet: tiles are calm containers, insets are where you type or drop, pills and buttons are the only raised, tappable things.

Material rule (this carries the whole style):

- Raised (dual outer shadow) means "container or something you can press": tiles, pills, buttons, nav items, the selected segment.
- Inset (dual inner shadow) means "receptive or current": fields, drop zone, toggle track, progress track, list rows, the current nav item, the countdown slab when expired.
- Pressing a raised thing swaps its shadow to the inset recipe and moves it down 1 px (already in `.neu-btn:active`).

### 1.2 Palette (hex, role, measured contrast)

All ratios are WCAG 2.x relative luminance, measured against the surface the colour is used on.

| Token | Hex | Role | Contrast / rule |
|---|---|---|---|
| `--bg` | `#EEEBE6` | Window and tile surface | base |
| `--bg-elev` | `#F4F2EE` | Reserved lighter surface; no screen uses it in 0.2 | ink on it 10.0:1 |
| `--ink` | `#3B3B40` | All body text, titles, numbers, text on accents | 9.4:1 on `--bg` |
| `--muted` | `#8A8A92` | Decoration, disabled text, icon details only | 2.9:1 on `--bg`: fails AA for text. Do not use for words. |
| `--muted-ac` | `#62626B` | Helper text, labels, notes, placeholders (added) | 5.1:1 on `--bg`, 4.9:1 on cream |
| `--pink` | `#E8A9AD` | Accent fill: pink chips, attention button, countdown slab (low), toggle knob (off) | ink on pink 5.7:1. White on pink 2.0:1: never. |
| `--pink-deep` | `#D98B90` | Glyph shading, off dot | decoration only; ink on it 4.3:1 so no text on it |
| `--blue` | `#8FA4C9` | Accent fill: blue chips, toggle knob (on) | ink on blue 4.4:1 (fails 4.5 for body text); white on blue 2.5:1 |
| `--blue-ac` | `#9DB0D2` | Blue fill that carries text: primary button, blue chip, info badge (added) | ink on it 5.1:1 |
| `--blue-deep` | `#6F87B3` | Focus ring, progress bar, focus outlines | 3.05:1 on `--bg` (meets the 3:1 non-text rule); white on it 3.6:1 (large text only), so still no text on it |
| `--sage` | `#A8C9B8` | Success tint: ok badge, ok notice, countdown (running) | ink on sage 6.2:1 |
| `--sage-deep` | `#7FAE98` | Status dot, glyph body | decoration only |
| `--cream` | `#F3E7D3` | Warning tint, first-run banner, word chips | ink on cream 9.1:1 |
| `--danger` | `#D9777C` | Glyph and fill only | 2.6:1 on `--bg`: not for text |
| `--danger-ac` | `#A8444A` | Error text (added) | 4.9:1 on `--bg` |
| `--danger-tint` | `#F2D3D4` | Error badge and error notice background (added) | ink on it 8.0:1 |

White-text rule, stated once: white text on pink or blue (or sage) is used nowhere in sealdrop. The fixed CSS defaults `.neu-btn--primary`, `.neu-btn--pink` and `.neu-chip` to white text, which is 2.0:1 on pink and 2.5:1 on blue. To avoid editing the fixed block, `neu.css` adds a mandatory layer: put `class="app aa"` on the root. Under `.aa`, chips, primary and pink buttons use `--ink`, primary and blue chips switch to `--blue-ac`, muted text uses `--muted-ac`, error text uses `--danger-ac`, and the focus ring is 3.05:1. Task 15 must set `aa` on the root and must not remove it. If you ever render without `aa`, white text on an accent is a defect.

Body text is always `--ink`. Pink and blue appear as fills, glyph colours and rings, never as text colour.

Dark theme (`#2B2B30` base in the fixed brief) is not part of 0.2. Do not add a dark toggle; keep all colours as tokens so it can be added later.

### 1.3 Type

Font: Nunito (variable). Bundle it locally (for example `@fontsource-variable/nunito`, imported in the app entry). No CDN, no Google Fonts: the CSP is `default-src 'self'` and the app makes no network calls of its own. Mono (keys, hashes, paths): system monospace via `--font-mono`.

| Role | Size / line | Weight | Class or token |
|---|---|---|---|
| Screen title (`h1`) | 28 / 36 | 700 | `.h1` |
| Dialog title, large headings | 20 / 28 | 700 | `.h2` |
| Success headline ("Sealed.") | 17 / 24 | 700 | `.lead` |
| Body, field text, button text | 15 / 22 | 400, buttons 700, emphasis 600 | `body` |
| Tile title (`h2` styled as label) | 13 / 18, uppercase, tracking .08em | 600 | `.label` |
| Helper, notes, notices | 13 to 14 / 18 to 20 | 400 | `.field__helper`, `.note`, `.notice` |
| Chip, badge | 13 / 16 | 600 to 700 | `.neu-chip`, `.badge` |
| Numbers (sizes, counts, times) | inherit | 700, tabular figures | `.num` |
| Countdown digits | 28 / 36 | 700, tabular | `.countdown__time` |
| Nav label | 12 / 16, tracking .04em | 600 | `.nav-label` |
| Keys, hashes, paths | 13 / 20 mono | 400 | `.mono` |

No text below 12 px. Respect browser text scaling: use `rem` for new sizes if the project already does, but never fixed-height text containers.

### 1.4 Spacing, radii, grid

- 8-pt grid: 8, 16, 24, 32, 48. 4 px is allowed inside chips and between a label and its field. The one off-grid value is the fixed tile padding of 20 px, kept from the spec. Gap between tiles and between fields in a tile is 16 px (`.stack`, `.cols-12` gap).
- Radii: tile 24 (`--radius-tile`), field 16 (`--radius-field`), nav item 20, pill / chip / toggle / button 999 (`--radius-pill`), list row 16.
- Window: 1120 x 760 minimum (set `minWidth`/`minHeight` in `tauri.conf.json`; the app is not designed below this). Layout is `.app`: 104 px nav column plus `.main` (padding 24 top and bottom, 28 left and right). Content width at the minimum size is 960 px.
- 12-column content grid: `.cols-12` (gap 16, so a column is about 65 px at 960). Standard splits: 7 + 5 (`.span-7` + `.span-5`, or `.two-col`) or one `.span-12`. The main area scrolls (`overflow: auto`); keep the primary action of each screen visible without scrolling at 1120 x 760.
- Wireframe scale used below: 1 character is 10 px wide, 1 line is 20 px tall, 112 x 38 characters is the 1120 x 760 window.

Wireframes abbreviate long copy to fit the character grid; the copy tables under each wireframe are authoritative.

Wireframe legend: `╭─╮` Tile, `┌╌┐` inset (Field or DropZone), `( x )` SoftButton or Pill (raised), `{ x }` selected segment (pressed), `[[ x ]]` primary SoftButton (blue fill), `‹ x ›` Chip, `[=o]` Toggle on (knob right), `[o=]` Toggle off (knob left), `(ok)` success glyph, `(!)` warning glyph, `v` disclosure chevron.

### 1.5 Elevation (shadow recipe)

| Level | Recipe | Used by |
|---|---|---|
| Tile | `8px 8px 18px var(--shadow-dark), -8px -8px 18px var(--shadow-light)` | `.neu-tile`, `.banner` |
| Pill / button | `6px 6px 14px ..., -6px -6px 14px ...` | `.neu-pill`, `.neu-btn`, `.neu-nav__item`, `.countdown` |
| Inset | `inset 4px 4px 10px ..., inset -4px -4px 10px ...` | `.neu-inset`, `.neu-drop`, `.neu-toggle`, `.seg`, nav current item |
| Small inset | `inset 3px 3px 7px/8px ...` | `.progress`, `.list__row`, `.qr` |
| Pressed | inset recipe plus `translateY(1px)` | `.neu-btn:active` |
| Selected segment | `4px 4px 10px ..., -4px -4px 10px ...` (raised, smaller) | `.seg__item[aria-checked="true"]` |
| Focus | outline 3 px `--blue-deep`, offset 2 to 3 px | all interactive elements; inputs add a 3 px ring to the inset shadow |

`--shadow-dark` is `rgba(163,177,198,0.45)` and `--shadow-light` is `rgba(255,255,255,0.9)`. Never use black shadows. Never stack a raised shadow on an inset surface.

Neumorphism has weak edges, so state is never carried by shadow or colour alone: every status has a word, every selection has a position or weight change, every toggle shows "On" or "Off" text. Fields are identified by their visible label above them, not only by the inset edge. In forced-colours mode `neu.css` adds 1 px borders.

### 1.6 Iconography

Rules:

- Simple two-tone rounded SVG glyphs, inline in the React components. No icon font, no icon library, no emoji.
- Two fills only: dusty pink `#E8A9AD` and periwinkle `#8FA4C9`. One of them is the body, the other is the accent; details (check marks, arrows, lines) are cut out in `--bg` (`#EEEBE6`). Corners are rounded (rx at least 25% of the shape); no sharp miters; strokes use `stroke-linecap="round"` and `stroke-linejoin="round"`.
- Nav glyphs: 32 x 32 viewBox, drawn at 32 px inside the 64 px pill. Inline glyphs: 20 px. Drop-zone glyph: 48 px.
- Glyphs are decoration. They are `aria-hidden="true"` and always sit next to a text label or an `aria-label` on the button. Pink and blue on `--bg` are 1.7:1 and 2.1:1, which is fine for decoration only; never make a glyph the only carrier of meaning.
- Status glyphs (ok, warning, error) use an ink mark on a tinted disc so they reach 4.5:1 or better on their own: sage disc with ink check, cream disc with ink "!", pink disc with ink cross. They are always followed by a text label.

Nav glyphs (copy these as the starting point; adjust only to taste, keep the rules above):

```html
<!-- Seal: envelope with a wax disc -->
<svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
  <rect x="4" y="8" width="24" height="17" rx="6" fill="#8FA4C9"/>
  <path d="M7 12.5 16 19l9-6.5" fill="none" stroke="#EEEBE6" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="22.5" cy="22" r="6" fill="#E8A9AD"/>
</svg>
<!-- Open: tray with a card dropping in -->
<svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
  <rect x="4" y="16" width="24" height="12" rx="5" fill="#8FA4C9"/>
  <rect x="9" y="4" width="14" height="15" rx="4" fill="#E8A9AD"/>
  <path d="M16 8v6m-3-2.5 3 3 3-3" fill="none" stroke="#EEEBE6" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
<!-- Verify: shield with a check disc -->
<svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
  <path d="M16 4.5 25.5 8v7.5c0 6-4.2 10.2-9.5 12-5.3-1.8-9.5-6-9.5-12V8z" fill="#8FA4C9" stroke="#8FA4C9" stroke-width="3" stroke-linejoin="round"/>
  <circle cx="16" cy="16" r="6.5" fill="#E8A9AD"/>
  <path d="m13 16.2 2.2 2.2 4-4.4" fill="none" stroke="#EEEBE6" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
<!-- Keys: round bow and a bit -->
<svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
  <circle cx="11" cy="16" r="7.5" fill="#E8A9AD"/>
  <circle cx="11" cy="16" r="2.8" fill="#EEEBE6"/>
  <rect x="16" y="13.8" width="13" height="4.6" rx="2.3" fill="#8FA4C9"/>
  <rect x="23" y="18" width="3.4" height="5.2" rx="1.5" fill="#8FA4C9"/>
</svg>
<!-- Settings: three sliders -->
<svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
  <rect x="4" y="6" width="24" height="4.4" rx="2.2" fill="#8FA4C9"/>
  <rect x="4" y="13.8" width="24" height="4.4" rx="2.2" fill="#8FA4C9"/>
  <rect x="4" y="21.6" width="24" height="4.4" rx="2.2" fill="#8FA4C9"/>
  <circle cx="11" cy="8.2" r="4.6" fill="#E8A9AD"/>
  <circle cx="21" cy="16" r="4.6" fill="#E8A9AD"/>
  <circle cx="13" cy="23.8" r="4.6" fill="#E8A9AD"/>
</svg>
```

Status glyphs (20 px):

```html
<!-- ok -->      <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#A8C9B8"/><path d="m7 12.5 3.2 3.2L17 9" fill="none" stroke="#3B3B40" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
<!-- warning --> <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#F3E7D3" stroke="#3B3B40" stroke-width="1.5"/><path d="M12 7v6.5M12 17v.2" fill="none" stroke="#3B3B40" stroke-width="2.4" stroke-linecap="round"/></svg>
<!-- error -->   <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#E8A9AD"/><path d="m8.5 8.5 7 7m0-7-7 7" fill="none" stroke="#3B3B40" stroke-width="2.4" stroke-linecap="round"/></svg>
```

Other glyphs to draw in the same style (one line each so the set stays small): folder (blue body, pink tab) for the drop zone and path rows; file (pink page, blue folded corner) for file rows; copy (two overlapping rounded squares, pink and blue); eye and eye-off (blue almond, pink pupil) for Show/Hide; clock (blue ring, pink hands) for timed chips; lock (blue body, pink shackle) for "sealed" headers; cross (a 12 px pink-on-ink x) for chip remove; chevron (blue, 12 px) for disclosures. The brand mark at the top of the nav is a pink disc with a blue droplet cut-out; it is not a button.

### 1.7 Motion

Only the transitions already in the CSS (button press .08 s, toggle knob .15 s) plus the progress bar. Indeterminate progress slides; under `prefers-reduced-motion: reduce` it becomes a static half-opacity bar and every transition is off (already in `neu.css`). Nothing bounces, nothing celebrates. The countdown ticks once per second with no animation.

---

## 2. Primitives and variants

Only these nine primitives exist. Every screen below is composed from them. A variant is a class or attribute on the same primitive, never a new component.

| Primitive | Class / element | Variants (defined here) | Semantics |
|---|---|---|---|
| **Nav** | `<nav class="neu-nav" aria-label="Main">` with `.neu-nav__item-wrap` > `button.neu-nav__item` + `.nav-label` | `item` current (`aria-current="page"`, inset). `logo` (`.neu-nav__logo`, not interactive). `spacer` pushes Settings to the bottom. | Five items: Seal, Open, Verify, Keys (top), Settings (bottom). Buttons, not links. Each has `aria-label` equal to its visible label. |
| **Tile** | `section.neu-tile[aria-labelledby]` | `tile` default. `well` (a `.neu-inset` block with padding 16 for read-only values and result lists). `banner` (`.banner`, cream, full width). `notice` (`.notice`, `--err`, `--ok`; inline message inside a tile). `dialog` (`.neu-tile.dialog` inside `.scrim`). `row` (`.list__row`, an inset row inside a list). | Tile title is `<h2 class="label">`. Tiles are landmarks only when they hold a form; otherwise plain `section`. |
| **Pill** | `.neu-pill` | `status` (dot + text, for example "Identity ready"). `seg` (`.seg` radiogroup of `.seg__item[role="radio"]`). `progress` (`.progress` track + `.progress__bar`, `role="progressbar"`). `toggle-label` (a plain row, see Toggle). | Status pills are not interactive. Segments are one tab stop; arrow keys move and select. |
| **Chip** | `.neu-chip` | `pink` (standard recipient), `blue` (post-quantum recipient), `sage` (plugin recipient), `cream` (word, advisory, "Non-standard"), `word` (`.neu-chip--word`), `removable` (chip + `.neu-chip__x`), `status` (`.badge` with `--ok`, `--warn`, `--err`, `--info`; always glyph + word). | Chip text is `--ink` under `.aa`. Removable chip's button has `aria-label="Remove recipient [short form]"`. |
| **SoftButton** | `button.neu-btn` | default (neutral), `--primary` (blue-ac, one per screen: the main action), `--pink` (attention or destructive: Replace identity, Skip verification), `--sm` (14 px, copy buttons and inline actions), `--block` (full width), `link` (`.link-btn`, underlined text button for Show, Hide, Remove, Clear, disclosures). | Unavailable buttons use `aria-disabled="true"`, not native `disabled`, so they stay focusable and their reason text (linked with `aria-describedby`) can be read; the click handler ignores them. See the rule under this table. |
| **Toggle** | `.toggle-row` > `button.neu-toggle[role="switch"][aria-checked]` + `.toggle-row__text` + `.toggle-row__state` | `with-note` (row plus `.field__helper` underneath, linked by `aria-describedby`). `unavailable` (`aria-disabled="true"`, opacity .5, ignores activation). | Always `role="switch"` with `aria-checked="true|false"`, labelled by the row text via `aria-labelledby`. Visible "On" / "Off" text in `.toggle-row__state`. Space and Enter toggle. The whole row is at least 44 px high; clicking the label text toggles too. |
| **Field** | `.field` > `label.label` + `.neu-inset` + `.field__helper` + `.field__error` | `text`, `password` (input + "Show" / "Hide" link button, `aria-pressed`), `number+unit` (`.field__row`: number input + `select.neu-inset.field__unit`), `path` (readonly input + "Choose…" button), `value` (readonly `textarea.neu-inset.mono`, `rows="2"`, for recipient string, signer key, hash; with a Copy button), `date` (text input, `YYYY-MM-DD`), `disclosure` (a `link-btn` with `aria-expanded` that shows more fields). | Label is always visible and associated (`for`/`id`). Helper and error are linked with `aria-describedby`. Invalid: `aria-invalid="true"` (adds a 2 px `--danger-ac` ring) and the message in `.field__error`. Errors appear on blur or on submit, not while typing the first time. Placeholders are examples, never instructions that disappear. |
| **DropZone** | `.neu-drop` (200 px) or `.neu-drop.neu-drop--sm` (120 px) with `.drop__inner` | `idle`, `active` (`data-active="true"` while a file is dragged over: dashed blue outline inside), `loaded` (the zone shows the chosen item inside itself: glyph, name, path; the Choose buttons stay so the item can be replaced), `error` (inline `.field__error` under it). | `role="group"` with an `aria-label`. It is not a tab stop. Keyboard alternative: the "Choose file…" and "Choose folder…" (or "Choose package…") SoftButtons inside it, which open the native dialog. Drag-and-drop gives the path to Rust; the WebView never reads the file. |
| **Countdown** | `.countdown[role="timer"]` > label text + `.countdown__time` | `running` (sage slab), `low` (pink slab, 25% of the window or less, or under 60 s), `expired` (inset slab with the word "expired"), `waiting` (cream slab, "not opened yet", used in Keys receipts). | Text always carries the meaning ("expires in 9 m 41 s", "expired"). Not announced every second; see the Open screen. Driven by the service clock, never a local deadline (section 5.4). |

**Unavailable controls (one rule).** Buttons, toggles and segment options that cannot be used right now carry `aria-disabled="true"` (neu.css dims them to .5 and removes the press effect). They stay in the tab order and the reason is in text linked by `aria-describedby`. Native `disabled` is used only for text inputs and selects while an operation is working. Never hide a control instead of explaining it.

**Attribute reference for the stateful primitives.**

| Primitive | Markup |
|---|---|
| Countdown | `<div class="countdown" role="timer" aria-label="Time left" data-state="low"><span class="label">expires in</span><span class="countdown__time">9 m 41 s</span></div>`. `data-state` is one of `low` (25% of the window or less, or under 60 s), `expired`, `waiting`; no attribute means running (sage slab). |
| Progress, determinate | `<div class="progress" role="progressbar" aria-label="Sealing" aria-valuemin="0" aria-valuemax="100" aria-valuenow="40" style="--p:40%"><div class="progress__bar"></div></div>`; the bar width is the CSS variable `--p`, keep it in sync with `aria-valuenow`. |
| Progress, indeterminate | Same element with `data-indeterminate="true"`, no `aria-valuenow` and no `--p`. The phase text beside it is the accessible name of the activity. |
| Segmented | `<div class="seg" role="radiogroup" aria-label="Delivery method"><button class="seg__item" role="radio" aria-checked="true">…</button>…</div>` |
| Nav current item | `aria-current="page"` on `.neu-nav__item`; its `.nav-label` becomes weight 700 (rule in neu.css). |

Text formats used everywhere: dates as `13 Oct 09:12 UTC` (add the year when it is not the current year: `13 Oct 2026 09:12 UTC`); sizes with one decimal (`48.2 MB`, `2 KB`); durations as `[n] seconds|minutes|hours|days` in sentences (singular for 1: `1 hour`) and compact `9 m 41 s`, `2 h 05 m`, `3 d 4 h`, `41 s` in the countdown.

---

## 3. Shell (shared by all screens)

### 3.1 Layout

```
<div class="app aa">
  <nav class="neu-nav" aria-label="Main"> ... </nav>
  <main class="main"><div class="page"> header, optional banner, content </div></main>
</div>
```

- Page header (`.page-head`): left `h1.h1` plus a one-line subtitle in `.muted`; right a status Pill.
- Status Pill (all screens): with an identity: sage dot + "Identity ready". Without: pink dot + "No identity". Not interactive, `role="status"` is not needed (it does not change while you are on a screen).
- Content: `.cols-12`. Each screen below gives the split.
- One `aria-live="polite"` region (`.sr-only`) at the root announces short outcomes ("Copied.", "Saved.", "alice is now trusted."). Visible inline confirmations carry the same text next to the control that caused them.
- Window title: "sealdrop". Do not put file names, keys or recipient data in the title.
- Switching screens keeps each screen's non-secret state (chosen file, recipient list) until the app closes; secrets are cleared as in section 10.

### 3.2 Nav

| Item | Position | `aria-label` / visible label | Glyph |
|---|---|---|---|
| Brand mark | top | none (decorative, `aria-hidden`) | pink disc, blue droplet |
| Seal | 1 | Seal | envelope with wax disc |
| Open | 2 | Open | tray with card |
| Verify | 3 | Verify | shield with check |
| Keys | 4 | Keys | round-bow key |
| Settings | bottom (after `.neu-nav__spacer`) | Settings | three sliders |

Each item: 64 x 64 px pill (`.neu-nav__item`), 12 px label below (`.nav-label`), current item inset with `aria-current="page"` and its label in weight 700. Keyboard: Tab reaches each item; Enter or Space activates. Optional shortcuts `Ctrl/Cmd + 1` to `5` switch screens; show nothing about them in the UI.

### 3.3 First-run banner

Shown on Seal, Open, Verify and Settings while there is no identity. Not shown on Keys (the Keys screen has its own empty state with the action). Placed between the page header and the content. Cream `Tile--banner`.

```

   (~~~)     Seal                                                                           ( o No identity )
             Lock a file or folder, sign it, and get a delivery record.
             ╭──────────────────────────────────────────────────────────────────────────────────────────────╮
             │  (!)  No identity yet — create one in Keys.                                  ( Go to Keys )  │
  ┌╌╌╌╌╌┐    ╰──────────────────────────────────────────────────────────────────────────────────────────────╯
  ┆ [@] ┆
  └╌╌╌╌╌┘
```

| Element | Copy |
|---|---|
| Banner text (verbatim) | No identity yet — create one in Keys. |
| Button (SoftButton, default) | Go to Keys |
| Accessibility | `role="region"` `aria-label="First run"`; text is in `--ink` on cream (9.1:1). The button moves to Keys and focuses "Create identity". The banner disappears the moment an identity exists, without a page reload. |

The banner (about 72 px with its margin) pushes the content down, so at 760 px the primary action of a screen may need a scroll while the banner is showing.

Without an identity: Seal's primary action is `aria-disabled` with the reason "Create your identity in Keys first." Open can still open passphrase packages; for a package that needs an identity key it shows "This package needs your identity key, and you haven't created one yet. Create one in Keys." Verify works fully.

### 3.4 Shared message copy

| Id | Where | Copy |
|---|---|---|
| G1 | Any unclassified failure (inline notice, `--err`) | Something went wrong: [reason from the core]. Nothing was changed. |
| G2 | Copy button success (inline next to the button and in the live region) | Copied. |
| G3 | Copy of a secret (passphrase) | Copied. Clear your clipboard once you have shared it. |
| G4 | Native dialog cancelled | (no message; the screen stays as it was) |
| G5 | Path not readable | sealdrop can't read that. Check that it still exists and that you can open it. |
| G6 | Path not writable | sealdrop can't write to that folder. Choose another one. |

Never auto-dismiss an error. Errors stay until the user changes the input or presses the action again.

---

## 4. Screen: Seal

Purpose: pick a file or folder, choose who can open it (recipients or a generated passphrase), optionally add timed release and details, and write the three delivery files.

### 4.1 Wireframe (a chosen folder, hardware-only recipients, timed release on)

```

   (~~~)     Seal                                                                        ( * Identity ready )
             Lock a file or folder, sign it, and get a delivery record.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ┌╌╌╌╌╌┐    │ WHAT TO SEND                                        │ │ TIMED RELEASE                   [=o] │
  ┆ [@] ┆    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │                                      │
  └╌╌╌╌╌┘    │ ┆                [ folder glyph ]                 ┆ │ │ ┌╌╌╌╌╌╌╌╌┐  ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
   Seal      │ ┆                    report-q3                    ┆ │ │ ┆ 10     ┆  ┆ minutes           v  ┆ │
             │ ┆        C:\Users\you\Documents\report-q3         ┆ │ │ └╌╌╌╌╌╌╌╌┘  └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  ╭─────╮    │ ┆                                                 ┆ │ │                                      │
  │ [v] │    │ ┆( Choose file... ) ( Choose folder... ) ( Clear )┆ │ │ The recipient can open this only     │
  ╰─────╯    │ ┆                                                 ┆ │ │ within 10 minutes after they first   │
   Open      │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ open it. This does not protect the   │
             ╰─────────────────────────────────────────────────────╯ │ contents once decrypted.             │
  ╭─────╮    ╭─────────────────────────────────────────────────────╮ │ Release service: release.example.org │
  │ [/] │    │ WHO CAN OPEN IT                                     │ ╰──────────────────────────────────────╯
  ╰─────╯    │ { To recipients }  ( With a passphrase )            │ ╭──────────────────────────────────────╮
  Verify     │                                                     │ │ Details (optional)                v  │
             │ RECIPIENTS                                          │ │ Classification, advisory date, armor │
  ╭─────╮    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐           │ │                                      │
  │[o-] │    │ ┆ Paste a recipient (age1...)           ┆  ( Add )  │ ╰──────────────────────────────────────╯
  ╰─────╯    │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘           │ ╭──────────────────────────────────────╮
   Keys      │                                                     │ │ SAVE TO                              │
             │ ‹ yubikey · age1yubikey1...c8  x ›                  │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
             │ ‹ tpm · age1tpm1...q2  x ›                          │ │ ┆ Documents (next to the source)   ┆ │
             │                                                     │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
             │ [o=]  Also encrypt to me   (disabled)               │ │ ( Choose... )                        │
             │       Not added to a timed release package, because │ │                                      │
             │       it would bypass the release service.          │ │ Accept the unrecoverable-package     │
             │                                                     │ │ warning or add a second recipient.   │
  ╭─────╮    │ (!)  Hardware keys can't be backed up. If the       │ │                                      │
  │ [=] │    │      key is lost or broken, this package can        │ │                                      │
  ╰─────╯    │      never be opened.                               │ │ [[              Seal              ]] │
 Settings    │ [o=]  I accept this package may become              │ │                                      │
             │       unrecoverable                                 │ │                                      │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
 sealdrop 0.2
```

Grid: left `.span-7` = tiles A ("What to send") and B ("Who can open it"); right `.span-5` = tiles C ("Timed release"), D ("Details"), E ("Save to" + the Seal action). The right column's last tile holds the primary button so it stays in view at 760 px high. The main area scrolls if recipient chips grow.

### 4.2 Components

| Tile | Primitives |
|---|---|
| A What to send | Tile, DropZone (large; `loaded` variant once an item is chosen: glyph, name, path), 2 x SoftButton ("Choose file…", "Choose folder…"), SoftButton link "Clear" |
| B Who can open it | Tile, Pill `seg` (To recipients / With a passphrase). Recipients mode: Field text + SoftButton "Add", Chip list (removable; pink x25519, blue post-quantum, sage `plugin:*`), Toggle "Also encrypt to me" (unavailable in timed release), Tile `notice` (hardware-only) + Toggle "I accept this package may become unrecoverable". Passphrase mode: Pill `seg` x2 (word list, key strength), Field number (word count), Chip cream ("Argon2id (non-standard)", only when enabled in Settings) |
| C Timed release | Tile, Toggle, Field number+unit, sentence (text), service line + SoftButton link |
| D Details | Tile, Field disclosure; revealed: Field text (classification), Field date (advisory expiry), Toggle (ASCII armor) |
| E Save to | Tile, Field path + SoftButton "Choose…", Pill `progress`, status text, SoftButton primary "Seal" |
| After success | Tile (Sealed), Tile (Sending it), Tile (Passphrase, passphrase mode), Tile (Timed release, timed only); SoftButton "Copy folder path", "Seal another", "Copy", "Hide"; Chip `word`; QR (see below) |

### 4.3 Copy

Header: title "Seal"; subtitle "Lock a file or folder, sign it, and get a delivery record."

**A. What to send**

| Element | Copy |
|---|---|
| Tile title | What to send |
| DropZone headline | Drop a file or folder here |
| DropZone connector | or |
| Buttons | Choose file… / Choose folder… |
| DropZone (drag over) | Release to add |
| Loaded zone | glyph, `[name]` (weight 700), full path in mono. No file count or size: the Seal input is not pre-scanned. |
| Clear (link) | Clear |
| Several items dropped | Seal one item at a time. Put several files in a folder first. |
| Unreadable | sealdrop can't read that. Check that it still exists and that you can open it. |

**B. Who can open it** (segment label for assistive tech: "Delivery method")

| Element | Copy |
|---|---|
| Tile title | Who can open it |
| Segment | To recipients / With a passphrase |
| Field label | Recipients |
| Placeholder | Paste a recipient (age1…, age1pq… or a plugin key) |
| Button | Add |
| Helper | Each recipient opens the package with their own key. |
| Chip text | `age1qx7k…f3k2` (first 8 and last 4 characters); plugin keys read `yubikey · age1yubikey1…c8` |
| Chip colour | pink: standard (`age1…`); blue: post-quantum (`age1pq…`); sage: plugin key |
| Chip remove (`aria-label`) | Remove recipient [short form] |
| Count line, none | No recipients yet. Add at least one, or choose a passphrase. |
| Count line | 1 recipient. / 3 recipients. / 3 recipients, plus you. |
| Toggle (default on) | Also encrypt to me |
| Toggle helper | Keeps a copy you can reopen with your own key. |
| Toggle, disabled in timed release | (same label, off, `aria-disabled`) helper: Not added to a timed release package, because it would bypass the release service. |
| Hardware-only notice (`notice`, warning glyph) | Hardware keys can't be backed up. If the key is lost or broken, this package can never be opened. |
| Hardware-only toggle | I accept this package may become unrecoverable |
| Hardware-only helper | Or add a second recipient that you can recover. |
| Hardware-only rule (not copy) | The notice shows when every added recipient has `kind` starting with `plugin:` and "Also encrypt to me" is off. With "Also encrypt to me" on, your own key is the recovery recipient. In timed release that toggle is unavailable, so a hardware-only set always needs the tick or a second non-plugin recipient. Until one of those holds, Seal is `aria-disabled` with the reason "Accept the unrecoverable-package warning or add a second recipient." The tick maps to `allow_unrecoverable`. |
| Error: not a recipient (`parse_recipient` fails) | Not a recipient string |
| Error: plugin not allowed (`allowed=false`) | Plugin [name] is not on the allow-list |
| Error: duplicate | That recipient is already in the list. |

Passphrase mode (the recipients area is replaced; the recipient list is kept in state, not shown):

| Element | Copy |
|---|---|
| Intro line | sealdrop generates a passphrase and shows it once. A passphrase package has one lock, so recipients are not used. |
| Intro line, when a recipient list exists | Your recipient list is kept and comes back if you switch to recipients. |
| Segment label | Word list |
| Segment | EFF large list / BIP-39 |
| Helper | EFF: at least 6 words, 12.9 bits each. BIP-39: at least 10 words, 11 bits each. |
| Field label | Number of words |
| Placeholder | Minimum (6) (becomes Minimum (10) for BIP-39) |
| Helper | Leave empty for the minimum. More words are stronger. |
| Error | Use at least 6 words. / Use at least 10 words. |
| Segment label | Key strength |
| Segment | Standard / High (slower) |
| Helper (scrypt) | High takes noticeably longer when sealing and when opening. |
| Helper (Argon2id) | High needs about 2 GiB of free memory to open. (Standard uses the compat profile, 256 MiB.) |
| Chip (only if Argon2id is on in Settings) | Argon2id (non-standard) |
| Note next to chip | Stock age tools can't open this package. Change this in Settings. (link-btn "Settings") |
| Error (policy) | A passphrase works alone. Switch to recipients, or remove them. |

**C. Timed release**

| Element | Copy |
|---|---|
| Tile title | Timed release |
| Toggle label | Timed release |
| Off text (replaces the fields) | Off. The package can be opened at any time. |
| Field label | Window |
| Placeholder | 10 |
| Unit select options | seconds / minutes / hours / days |
| Helper | The window starts when the recipient first opens the package. |
| Fixed sentence (verbatim; fill `[window]` live, for example `10 minutes`, `1 hour`, `3 days`; role `status`, updates as the user types) | The recipient can open this only within [window] after they first open it. This does not protect the contents once decrypted. |
| Service line | Release service: [host] (link-btn "Change in Settings") |
| Not configured (`notice`, warning; toggle `aria-disabled`) | No release service is set up. Add one in Settings to use timed release. (button "Open Settings") |
| No token | The release service needs a deposit token. Add it in Settings. |
| Error: window | Enter a whole number of at least 1. |

**D. Details** (collapsed summary: "Classification, advisory date, armor")

| Element | Copy |
|---|---|
| Disclosure | Details (optional) |
| Classification label / placeholder | Classification / e.g. confidential |
| Classification helper | A free-text label saved in the signed record. |
| Advisory date label / placeholder | Advisory expiry date / YYYY-MM-DD |
| Advisory date helper | Advisory only. No software enforces this date. |
| Advisory date error | Use the format YYYY-MM-DD. / Choose a date in the future. |
| Toggle | ASCII armor |
| Toggle helper | Writes text you can paste into a message. The file is larger. |

**E. Save to and action**

| Element | Copy |
|---|---|
| Tile title | Save to |
| Path field (default) | [folder of the source] (shown as the real path; helper below says "Next to the source.") |
| Button | Choose… |
| Helper | sealdrop writes three files here: the package, its manifest and its signature. |
| Error: inside source | The save folder can't be inside the folder you are sealing. |
| Error: not writable | sealdrop can't write to that folder. Choose another one. |
| Primary button | Seal |
| Button, working | Sealing… |
| Why disabled (text under the button, linked with `aria-describedby`; show the first unmet one) | Choose something to send. / Add a recipient or choose a passphrase. / Create your identity in Keys first. / Set up the release service in Settings first. / Accept the unrecoverable-package warning or add a second recipient. |
| Idle status (nothing missing) | Ready when you are. |
| Progress phases (aria-live polite, one at a time; map `progress` events: `packing`, `encrypted`, `contacting`, `done`) | `packing`: Packing and encrypting… / `encrypted`: Signing and writing the delivery record… / `contacting` (timed only): Placing the key with the release service… / `done`: success state |

**Success state**

| Element | Copy |
|---|---|
| Headline (`.lead`, ok glyph) | Sealed. |
| Sub line | [n] files written to [folder]. |
| Package row | Package · [file name] · Copy (copies the full path) |
| Other file rows | Manifest · [file name]; Signature · [file name] |
| Package id row | Package id · [uuid] |
| SHA-256 row | SHA-256 · first 8 and last 4 hex characters · Copy (copies the full hash) |
| Size row | Size · [size], [n] files |
| Note | The package, manifest and signature must stay together. |
| Buttons | Copy folder path / Seal another |
| Tile "Sending it", recipients | 1. Send all three files to your recipients. 2. They open the package in sealdrop (Open). Stock age tools can decrypt it too, but they won't check the signed record. |
| Tile "Sending it", passphrase | 1. Send all three files to your recipient. 2. Give them the passphrase another way, such as a phone call. Don't put both in one message. 3. They open the package in sealdrop (Open). |
| Added line, Argon2id | Packages made with Argon2id open only in sealdrop. |
| Added line, timed | Packages with timed release open only in sealdrop. |
| Passphrase tile title | Passphrase, shown once |
| Passphrase words | one `.neu-inset.passphrase` block (28 px, weight 700, letter-spacing .01em, line-height 1.4), each word in its own `<span>` followed by a plain space, with `<span class="passphrase__sep" aria-hidden="true"> · </span>` between words (the separator text is ` · `); wraps at the separators; selectable; `role="group"` `aria-label="Passphrase"`. Copy copies the space-joined words. |
| Entropy line (exact format, bits to one decimal) | [bits] bits — send it on a different channel (for example `77.5 bits — send it on a different channel`) |
| QR | Rendered client-side from the words with the `qrcode` npm package into a 168 px `<canvas>` inside `.qr` (dark modules on white, 4-module quiet zone), `aria-hidden`; the word block is the accessible version. Caption: Scan to read the passphrase. |
| Buttons | Copy / Hide |
| After Copy | Copied. Clear your clipboard once you have shared it. |
| Note (shown once per seal; navigating away clears it) | Shown once and not saved anywhere. Anyone with this passphrase and the package can open it. |
| Auto-clear note | Clears when you leave this screen. |
| After Hide (replaces the tile) | Passphrase hidden. It can't be shown again. If you haven't shared it, seal the file again. |
| Timed tile title | Timed release |
| Timed tile text | The recipient can open this only within [window] after they first open it. This does not protect the contents once decrypted. |
| Timed line | Timed release: [window] after first open. |
| Timed tile extra | Key placed with [host]. After it is first opened, check the receipt in Keys with this manifest. |

**Error state** (a `notice--err` above the button, error glyph, text in `--ink`; the failing field also gets `aria-invalid`)

| Cause | Copy |
|---|---|
| Release service unreachable | The release service didn't respond, so nothing was sealed. Check the address in Settings and try again. |
| Deposit token refused | The release service refused the deposit token. Check it in Settings. |
| Service address not allowed | The release service address must start with https:// (http:// is allowed only for this computer). |
| Policy refused (exit 3) | sealdrop refused to seal this: [policy reason]. |
| Hardware-only | Hardware keys alone can't be recovered. Add a second recipient or accept the warning. |
| Plugin binary missing (only knowable at seal time) | age-plugin-[name] wasn't found on this computer, so sealdrop can't use that key. |
| Empty folder | That folder is empty. There is nothing to seal. |
| Anything else | Couldn't seal: [reason]. No package was kept. |
| Button | Try again (SoftButton default) |

### 4.4 Success wireframe (passphrase mode, timed release)

After a successful seal the grid reorganises: left `.span-7` = the "Sealed" result tile over the "Passphrase" tile (words block with the QR canvas beside it); right `.span-5` = "Sending it" over "Timed release" (timed only; in a recipients-mode seal the passphrase tile is absent and the left column holds the result tile only).

```

   (~~~)     Seal                                                                        ( * Identity ready )
             Lock a file or folder, sign it, and get a delivery record.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ┌╌╌╌╌╌┐    │ SEALED                                              │ │ SENDING IT                           │
  ┆ [@] ┆    │ (ok) Sealed. 3 files written to Documents\sealed.   │ │                                      │
  └╌╌╌╌╌┘    │                                                     │ │ 1. Send all three files to your      │
   Seal      │ Package     report-q3.sealdrop.age        ( Copy )  │ │ recipient.                           │
             │ Manifest    report-q3.manifest.json                 │ │                                      │
  ╭─────╮    │ Signature   report-q3.manifest.json.minisig         │ │ 2. Give them the passphrase another  │
  │ [v] │    │                                                     │ │ way, such as a phone call. Do not    │
  ╰─────╯    │ Package id  3f2a91c0-7d44-4b0e-9a1f-c5d2e8b71e04    │ │ put both in one message.             │
   Open      │ SHA-256     9c1f...e0a4                  ( Copy )   │ │                                      │
             │ Size        48.3 MB, 12 files                       │ │ 3. They open the package in sealdrop │
  ╭─────╮    │                                                     │ │ (Open).                              │
  │ [/] │    │ ( Copy folder path )   ( Seal another )             │ │                                      │
  ╰─────╯    │ Package, manifest and signature stay together.      │ │                                      │
  Verify     ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ PASSPHRASE, SHOWN ONCE                              │ │ TIMED RELEASE                        │
  │[o-] │    │                                                     │ │                                      │
  ╰─────╯    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐  ┌──────────────────┐ │ │ Timed release: 10 minutes after      │
   Keys      │ ┆                           ┆  │                  │ │ │ first open.                          │
             │ ┆ abacus · cargo · drift ·  ┆  │  ████ ██ ██████  │ │ │                                      │
             │ ┆ eagle · fable · galaxy    ┆  │  ███  █ █ ███ █  │ │ │ The recipient can open this only     │
             │ ┆                           ┆  │  █ ██ ███ █████  │ │ │ within 10 minutes after they first   │
             │ ┆ (.passphrase, 28 px)      ┆  │  ███    █ ██ ██  │ │ │ open it. This does not protect the   │
             │ ┆                           ┆  │                  │ │ │ contents once decrypted.             │
             │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘  └──────────────────┘ │ │                                      │
             │                                                     │ │ Key placed with release.example.org. │
  ╭─────╮    │ 77.5 bits — send it on a different channel          │ │                                      │
  │ [=] │    │                                                     │ │ After it is first opened, check the  │
  ╰─────╯    │ ( Copy )  ( Hide )                                  │ │ receipt in Keys with this manifest.  │
 Settings    │ Shown once and not saved anywhere. Anyone with this │ │                                      │
             │ passphrase and the package can open it.             │ │                                      │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
 sealdrop 0.2
```

### 4.5 States

| State | What changes visually |
|---|---|
| Idle | Drop zone inset (empty, or showing the chosen item); chips and fields as entered; Seal is raised blue-ac but `aria-disabled="true"` (opacity .5) with the reason text beneath until every requirement is met. Timed tile shows "Off" text when the toggle is off. |
| Dragging | Drop zone gets `data-active="true"` (dashed blue-deep outline 12 px inside) and the headline reads "Release to add". |
| Working | Text inputs and selects in tiles A to E are natively `disabled`; buttons, toggles and segments are `aria-disabled="true"`; Seal reads "Sealing…"; a `progress` pill appears above the button (determinate when the core reports bytes, otherwise `data-indeterminate="true"`) with the phase text under it. No cancel in 0.2. |
| Success | The grid becomes the success layout in 4.4: result tile and passphrase tile on the left, "Sending it" and (timed) "Timed release" on the right. Focus moves to the "Sealed." heading (`tabindex="-1"`). "Seal another" resets everything, including clearing the passphrase from memory. |
| Error | `notice--err` above the button; inputs re-enabled; the relevant field has a danger-ac ring and `field__error`. The user's input is kept. |

### 4.6 Accessibility notes

- Tab order: nav, banner button (if shown), Choose file…, Choose folder…, Clear, delivery-method segment (one stop, arrow keys), recipient field, Add, each chip's remove button, "Also encrypt to me", hardware-only toggle (if shown), Timed release toggle, Window, unit, Details disclosure, revealed fields, Choose… (save), Seal. In passphrase mode the recipient controls are replaced by word list, word count, key strength.
- The drop zone has no unique keyboard function of its own: Choose file… and Choose folder… are the keyboard alternative and are always visible.
- The segment is `role="radiogroup"` with `aria-label`; each option `role="radio"` and `aria-checked`; arrow keys select; only the checked option is in the tab order.
- Toggles are `role="switch"`. The self-recipient toggle's disabled reason is in its helper, which `aria-describedby` points to.
- Adding a recipient with Enter keeps focus in the field and announces "Recipient added." in the live region; removing one announces "Recipient removed." and moves focus to the next remove button or the field.
- Passphrase tile: when it appears, focus moves to its title and the live region says "Passphrase shown. It is shown once." Words are real text (selectable, readable by a screen reader); the QR is `aria-hidden`.
- Text on pink, blue-ac and sage chips is `--ink`. The sentence "The recipient can open this only within…" is body text in `--ink`, not muted, because it is the honesty copy.
- Contrast: all text 4.5:1 or better; focus ring 3.05:1; the progress bar (`--blue-deep` on its track) 3:1 and always paired with text.

---

## 5. Screen: Open

Purpose: choose a package, see its signed delivery record, unlock it (passphrase or your key; timed packages contact the release service once), and restore it safely.

### 5.1 Wireframe (package loaded, timed release)

```

   (~~~)     Open                                                                        ( * Identity ready )
             Check, unlock and restore a package.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ PACKAGE                                             │ │ TIMED PACKAGE                        │
  │ [@] │    │ report-q3.sealdrop.age                              │ │                                      │
  ╰─────╯    │ 48.3 MB · sealed 13 Oct 2026 09:00 UTC              │ │ This package expires 10 minutes      │
   Seal      │                                                     │ │ after first open (service clock).    │
             │ ‹ confidential ›  ‹ timed release ›                 │ │ The window starts the first time     │
  ┌╌╌╌╌╌┐    │                                                     │ │ anyone opens it.                     │
  ┆ [v] ┆    │ ( Choose another package... )                       │ │                                      │
  └╌╌╌╌╌┘    │ Or drop a .sealdrop.age file anywhere on this tile. │ │ Expiry applies to the encrypted      │
   Open      │                                                     │ │ package only; nothing can recall a   │
             │                                                     │ │ file after it has been decrypted.    │
  ╭─────╮    │                                                     │ │                                      │
  │ [/] │    ╰─────────────────────────────────────────────────────╯ │ Opening it contacts [host].          │
  ╰─────╯    ╭─────────────────────────────────────────────────────╮ │                                      │
  Verify     │ DELIVERY RECORD                                     │ ╰──────────────────────────────────────╯
             │                                                     │ ╭──────────────────────────────────────╮
  ╭─────╮    │ (ok) Signature valid. Signed by alice (trusted).    │ │ UNLOCK                               │
  │[o-] │    │ (ok) Package matches its signed hash.               │ │                                      │
  ╰─────╯    │ (!)  Advisory date 2026-12-31, not enforced.        │ │ Opens with your identity key.        │
   Keys      │                                                     │ │ No passphrase needed.                │
             │ Package id      3f2a91c0-...-b71e                   │ ╰──────────────────────────────────────╯
             │ Sealed with     sealdrop 0.2.0                      │ ╭──────────────────────────────────────╮
             │ Opens with      your identity key, after the release│ │ RESTORE INTO                         │
             │                 service allows it (timed)           │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
             │                                                     │ │ ┆ Temporary folder                 ┆ │
             │ Expected signer (optional)                          │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
             │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │ ( Save to... )                       │
  ╭─────╮    │ ┆ Paste a signer key (starts with RWQ)            ┆ │ │ Removed when you close sealdrop      │
  │ [=] │    │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ (best effort; copies you made        │
  ╰─────╯    │                                                     │ │ elsewhere are not touched).          │
 Settings    │ v  More options                                     │ │ [[ Open and start the clock ]]       │
             │                                                     │ │                                      │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
 sealdrop 0.2
```

After a successful open of a timed package:

```

   (~~~)     Open                                                                        ( * Identity ready )
             Check, unlock and restore a package.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ OPENED                                              │ │ TIMED PACKAGE                        │
  │ [@] │    │ (ok) Opened. 12 files restored.                     │ │                                      │
  ╰─────╯    │ (ok) Contents match the signed record.              │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
   Seal      │                                                     │ │ ┆ expires in                       ┆ │
             │ Temp\sealdrop-3f2a\report-q3                        │ │ ┆ [    9 m 41 s    ]               ┆ │
  ┌╌╌╌╌╌┐    │                                                     │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  ┆ [v] ┆    │ ( Copy folder path )   ( Save to... )               │ │                                      │
  └╌╌╌╌╌┘    │                                                     │ │ First opened 13 Oct 09:12 UTC        │
   Open      │ Saved to a temporary folder. It is removed when you │ │ (service clock)                      │
             │ close sealdrop (best effort; copies you made        │ │                                      │
  ╭─────╮    │ elsewhere are not touched).                         │ │ Expiry applies to the encrypted      │
  │ [/] │    │ ( Open another package )                            │ │ package only; nothing can recall a   │
  ╰─────╯    │                                                     │ │ file after it has been decrypted.    │
  Verify     │                                                     │ │                                      │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
  ╭─────╮    ╭─────────────────────────────────────────────────────╮
  │[o-] │    │ FILES                                               │
  ╰─────╯    │                                                     │
   Keys      │ report-q3/                                          │
             │   summary.pdf                              2.1 MB   │
             │   data/                                             │
             │     q3-raw.csv                            31.4 MB   │
             │     q3-clean.csv                          12.9 MB   │
             │   notes.txt                                  4 KB   │
             │   ...and 6 more                                     │
             │                                                     │
  ╭─────╮    │                                                     │
  │ [=] │    │                                                     │
  ╰─────╯    │                                                     │
 Settings    │                                                     │
             │                                                     │
             ╰─────────────────────────────────────────────────────╯
 sealdrop 0.2
```

Grid: left `.span-7` = "Package" and "Delivery record"; right `.span-5` = "Timed package" (only when the manifest has `release`), "Unlock", "Restore into" with the action. For a non-timed package the "Timed package" tile is absent and Unlock moves up. With nothing chosen, the Package tile is the large DropZone and the other tiles are hidden.

### 5.2 Components

| Tile | Primitives |
|---|---|
| Package (empty) | Tile, DropZone (large), SoftButton "Choose package…" |
| Package (loaded) | Tile, text rows, Chip (classification cream, "Timed release" blue, "Passphrase" sage), SoftButton link "Choose another package…" |
| Delivery record | Tile, Chip `status` rows, `value` rows, Field text (expected signer), Field `disclosure` ("More options": Toggle "Replace existing files", Toggle "Skip verification", with a pink SoftButton style on the warning), SoftButton "Trust this signer…" (unknown signer) |
| Timed package | Tile, text |
| Unlock | Tile, Field password + "Show"/"Hide" (passphrase packages) or text (key packages) |
| Restore into | Tile, Field path + SoftButton "Choose…" / "Save to…", Pill `progress`, SoftButton primary |
| Result | Tile (Opened), Tile (Files), Tile (Timed package with Countdown) |

### 5.3 Copy

Header: title "Open"; subtitle "Check, unlock and restore a package."

**Package**

| Element | Copy |
|---|---|
| Tile title | Package |
| DropZone headline | Drop a .sealdrop.age package here |
| Connector / button | or / Choose package… |
| Helper | Keep the .manifest.json and .minisig files in the same folder. |
| Checking | Checking [name]… |
| Summary | [name] · [size] · sealed [date] UTC |
| Chips | [classification] (cream), Timed release (blue-ac), Passphrase / Passphrase (Argon2id) (sage) |
| Link | Choose another package… |
| Error: not a package | That doesn't look like a sealdrop package. Choose a file that ends in .sealdrop.age. |
| Error: sidecar missing | The manifest or signature file isn't next to the package. Keep the .sealdrop.age, .manifest.json and .minisig files together. |

**Delivery record** (rows: status badge or glyph, then text)

| Element | Copy |
|---|---|
| Tile title | Delivery record |
| OK row | Signature valid. Signed by [name] (trusted). |
| OK row | Package matches its signed hash. |
| Unknown signer row (warning) | Signed by a key you haven't trusted: [short key]. Check it with the sender, then trust it to continue. |
| Button | Trust this signer… (opens the Name field and "Trust this signer", same copy as Verify) |
| Failed row (error) | This package failed verification. It may have been changed after it was sealed. Don't open it. |
| Advisory row (warning glyph) | Advisory date [date]. No software enforces it. |
| Detail labels | Package id / Sealed with / Opens with |
| Opens with values | your identity key / a passphrase / a passphrase (Argon2id) / your identity key, after the release service allows it (timed) |
| Field label / placeholder | Expected signer (optional) / Paste a signer key (starts with RWQ) |
| Field helper | Only needed for a signer you haven't trusted. |
| Disclosure | More options |
| Toggle | Replace existing files |
| Toggle helper | Overwrites files with the same names in the folder you choose. |
| Toggle | Skip verification |
| Toggle helper (warning style) | Not recommended. Decryption still checks the data, but the signer and the delivery record won't be checked. |

**Timed package** (tile appears only for timed packages; text in `--ink`, not muted)

| Element | Copy |
|---|---|
| Tile title | Timed package |
| Paragraph 1 | This package expires [window] after first open (service clock). The window starts the first time anyone opens it. |
| Paragraph 2 (verbatim) | Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted. |
| Paragraph 3 (the service named inside the package; the tile is visible before the call) | Opening it contacts [host]. |

**Unlock**

| Element | Copy |
|---|---|
| Tile title | Unlock |
| Key package | Opens with your identity key. No passphrase needed. |
| No identity | This package needs your identity key, and you haven't created one yet. Create one in Keys. (button "Go to Keys") |
| Passphrase package: label / placeholder | Passphrase / Type or paste the passphrase |
| Show / Hide (link-btn, `aria-pressed`) | Show / Hide |
| Helper | Kept only until the package is opened. |
| Wrong passphrase | That passphrase didn't open the package. Check it and try again. |
| Not a recipient | Your key isn't one of this package's recipients. Ask the sender to seal it to your recipient string (Keys). |

**Restore into and action**

| Element | Copy |
|---|---|
| Tile title | Restore into |
| Path default, normal package | [folder of the package] (helper: Next to the package.) |
| Path default, timed package | Temporary folder |
| Buttons | Choose… (normal) / Save to… (timed) |
| Helper, timed | Removed when you close sealdrop (best effort; copies you made elsewhere are not touched). |
| Helper, Save to… | Saving to a folder unlocks the package a second time, inside the window. |
| Primary button, normal | Open |
| Primary button, timed | Open and start the clock |
| Primary button, working | Opening… |
| Why disabled | Choose a package first. / Enter the passphrase. / Trust the signer or enter their key first. / Create your identity in Keys first. |
| Progress phases (map `progress` events: `verifying`, `contacting`, `extracting`, `done`) | `verifying`: Verifying… / `contacting`: Contacting [host]… / `extracting`: Decrypting and restoring… / `done`: success state |

**Success**

| Element | Copy |
|---|---|
| Headline (ok glyph) | Opened. |
| Sub line | [n] files restored to [path]. |
| Integrity line (ok glyph; `verified: true`) | Contents match the signed record. |
| Integrity line when Skip verification was on (`verified: false`; hide the line above; warn badge) | Signature NOT verified — you chose to skip verification. |
| Temporary folder note | Saved to a temporary folder. It is removed when you close sealdrop (best effort; copies you made elsewhere are not touched). |
| Buttons | Copy folder path / Save to… (temporary only) / Open another package |
| Files tile title | Files |
| File list | tree of the first 8 entries with sizes, then `…and [n] more` |
| Timed tile title | Timed package |
| Countdown | expires in 9 m 41 s |
| First open line | First opened [date] UTC (service clock) |
| Sentence (verbatim) | Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted. |
| Extra line | Files you have already restored are not removed when the timer ends. |
| Countdown, expired | expired |
| Expired line | The window has ended. The package can't be opened again. |

**Error state** (`notice--err` in the Restore tile, above the button; error glyph; text in `--ink`)

| Cause | Copy |
|---|---|
| Verification failed (exit 2) | This package failed verification. It may have been changed after it was sealed. Don't open it. |
| Expired | This package has expired. The release service no longer holds the key, so it can't be opened. |
| Service unreachable | Couldn't reach [host]. A timed package can't be opened offline. |
| Service refused | The release service refused this package. The sender may need to seal it again. |
| Files exist | Some files already exist in that folder. Choose another folder, or turn on “Replace existing files” under More options. |
| Unsafe contents | This package contains something sealdrop won't extract, such as a link or an unsafe path. Nothing was written. |
| Too much work | This package asks for more time or memory than sealdrop allows. Nothing was opened. |
| Integrity failure | The data failed its integrity check. Nothing was kept. |
| Not writable | sealdrop can't write to that folder. Choose another one. |
| Anything else | Couldn't open the package: [reason]. Nothing was written. |

### 5.4 Countdown (timed packages) behaviour

- The pill reads `expires in [time]` and is a `role="timer"` with `aria-label="Time left"`. It is not a live region.
- Colour is a secondary cue: `running` sage slab; `low` pink slab when 25% of the window or less remains or under 60 s; `expired` inset slab reading "expired". The word and the digits always carry the meaning.
- A separate visually hidden live region (`aria-live="polite"`) announces only at thresholds: "10 minutes left", "1 minute left", "30 seconds left", "The window has ended." (when the window is shorter than a threshold, skip it).
- The value is derived from the service's `remaining_secs` sample (read on the service clock when `open_package` or `receipt_fetch` responds) and advanced with a monotonic timer, never from `expires_at` minus the local clock. `expires_at` and `first_unlock` are display-only timestamps ("First opened [date] UTC"). Display ticks once per second with no animation. The display never extends a window: it can only count down and then read "expired".

### 5.5 States

| State | What changes visually |
|---|---|
| Idle | Large DropZone only; nothing else rendered. |
| Checking | DropZone replaced by the Package summary; Delivery record tile shows a small indeterminate progress and "Checking [name]…". |
| Ready | Delivery record rows filled; primary button raised blue-ac; if something blocks opening, it is `aria-disabled` with the reason text. |
| Working | Inputs disabled; `progress` pill; phase text; button "Opening…" (or "Contacting [host]…" for the network step). |
| Success | Package and Delivery tiles collapse to the "Opened" tile; Files tile and (timed) Countdown tile appear; focus moves to "Opened.". |
| Error | `notice--err` above the button; inputs re-enabled; passphrase field keeps its text but is masked again and has the danger-ac ring. |

### 5.6 Accessibility notes

- Tab order: nav, banner button, Choose package…, Choose another package… (when loaded), Trust this signer…, Expected signer, More options, its toggles, Passphrase, Show/Hide, Choose… / Save to…, Open. Countdown pill is not focusable.
- Passphrase input is `type="password"` by default, `autocomplete="off"`, `spellcheck="false"`; Show/Hide is a `link-btn` with `aria-pressed`. The value is cleared on success, on leaving the screen and after 5 minutes idle.
- The "Skip verification" toggle sits in a warning-tinted row (cream `notice`) and its helper is in `--ink`; it is off by default and resets to off on each new package.
- The honesty paragraph in "Timed package" is in `--ink`, 15 px, never in a tooltip or a collapsed region.
- Status rows use glyph + word; the unknown-signer row is a warning, not an error, and it blocks opening until resolved.

---

## 6. Screen: Verify

Purpose: check a package's signature and ciphertext hash without decrypting anything, add a signer to the trusted list, and check a saved receipt.

### 6.1 Wireframe (package loaded, signer not yet trusted)

```

   (~~~)     Verify                                                                      ( * Identity ready )
             Check a package without opening it.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ PACKAGE                                             │ │ SIGNER                               │
  │ [@] │    │ report-q3.sealdrop.age                              │ │                                      │
  ╰─────╯    │ 48.3 MB                                             │ │ ‹ ! Signer not trusted ›             │
   Seal      │                                                     │ │                                      │
             │ ( Choose package... )   or drop one here            │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
  ╭─────╮    │                                                     │ │ ┆ RWQf6LRCGA9i53mlYecO4IzT...      ┆ │
  │ [v] │    ╰─────────────────────────────────────────────────────╯ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  ╰─────╯    ╭─────────────────────────────────────────────────────╮ │                                      │
   Open      │ RESULT                                              │ │ Name                                 │
             │                                                     │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
  ┌╌╌╌╌╌┐    │ ‹ ! Signer not trusted ›                            │ │ ┆ e.g. alice                       ┆ │
  ┆ [/] ┆    │                                                     │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  └╌╌╌╌╌┘    │ (ok) Manifest signature matches the signer key.     │ │                                      │
  Verify     │ (ok) Ciphertext hash matches the manifest.          │ │ ( Trust this signer )                │
             │ (!)  Signer is not in your trusted list.            │ │                                      │
  ╭─────╮    │                                                     │ ╰──────────────────────────────────────╯
  │[o-] │    │ This confirms which key signed the package and that │ ╭──────────────────────────────────────╮
  ╰─────╯    │ it has not changed. It does not show what is        │ │ CHECK A RECEIPT                      │
   Keys      │ inside.                                             │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
             │ Package id      3f2a91c0-...-b71e                   │ │ ┆    Drop a .receipt.json here     ┆ │
             │ Sealed          13 Oct 2026 09:00 UTC               │ │ ┆      ( Choose receipt... )       ┆ │
             │ Classification  confidential                        │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
             │ Advisory date   2026-12-31 (not enforced)           │ │                                      │
             │ Recipients      1 (x25519)                          │ │ Service key (optional)               │
             │ SHA-256         9c1f...e0a4   ( Copy )              │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
             │ Timed release   10 minutes after first open         │ │ ┆ Paste the service key            ┆ │
  ╭─────╮    │                 release.example.org                 │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  │ [=] │    │                                                     │ │ Enter the service key from the       │
  ╰─────╯    │                                                     │ │ sealed manifest to pin it.           │
 Settings    │                                                     │ │ (!) Signature valid — service key    │
             │                                                     │ │     not checked                      │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
 sealdrop 0.2
```

Grid: left `.span-7` = "Package" and "Result"; right `.span-5` = "Signer" and "Check a receipt".

### 6.2 Components

| Tile | Primitives |
|---|---|
| Package | Tile, DropZone (large when empty), SoftButton "Choose package…" |
| Result | Tile, Chip `status` (ok / warn / err), glyph rows, `value` rows, SoftButton `--sm` "Copy" |
| Signer | Tile, Chip `status`, Field `value` (read-only key), Field text (name), SoftButton "Trust this signer", Field text (alternative key), SoftButton "Check" |
| Check a receipt | Tile, DropZone `--sm`, SoftButton "Choose receipt…", Field text (service key), Chip `status`, text |

### 6.3 Copy

Header: title "Verify"; subtitle "Check a package without opening it."

| Element | Copy |
|---|---|
| Package tile title | Package |
| DropZone headline | Drop a .sealdrop.age package here |
| Connector / button | or / Choose package… |
| Helper | Keep the .manifest.json and .minisig files in the same folder. |
| Result tile title | Result |
| Empty state (before a package is chosen) | Choose a package to check it. Nothing is decrypted. |
| Working | Checking the signature and hash… |
| Headline chip, ok | Signature valid |
| Headline chip, warning | Signer not trusted |
| Headline chip, error | Verification failed |
| Row, ok | Manifest signature matches the signer key. |
| Row, ok | Ciphertext hash matches the manifest. |
| Row, ok | Signer is in your trusted list ([name]). |
| Row, warning | Signer is not in your trusted list. |
| Row, error | The manifest signature doesn't match. The record may have been altered. |
| Row, error | The package doesn't match the hash in its manifest. It may have been changed or damaged. |
| Closing line | This confirms which key signed the package and that it hasn't changed. It doesn't show what is inside. |
| Detail labels | Package id / Sealed / Created with / Classification / Advisory date / Recipients / SHA-256 / Timed release |
| Classification empty | None |
| Advisory date value | [date] (not enforced) |
| Recipients value | [n] ([kinds]); kinds: x25519, post-quantum, plugin, passphrase (scrypt), passphrase (Argon2id), timed release |
| SHA-256 value | first 8 and last 4 hex characters, with a Copy button |
| Timed release value | [window] after first open · [host] |
| Timed release sentence (verbatim; shown only for timed packages) | Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted. |
| Error: sidecar missing | The manifest or signature file isn't next to the package. Keep the .sealdrop.age, .manifest.json and .minisig files together. |
| Error: not a package | That doesn't look like a sealdrop package. Choose a file that ends in .sealdrop.age. |

Signer tile:

| Element | Copy |
|---|---|
| Tile title | Signer |
| Trusted | [name] (trusted) · key shown in mono · link-btn "Manage in Keys" |
| Untrusted chip | Signer not trusted |
| Unknown helper | Check this key with the sender by another route before you trust it. |
| Name label / placeholder | Name / e.g. alice |
| Name helper | Letters, digits, - and _ only. |
| Button | Trust this signer |
| Success | [name] is now trusted. (also in the live region; the chip becomes "Trusted as [name]" and the result re-runs) |
| Name errors | Use letters, digits, - and _ only. / A signer named “[name]” already exists. |
| Alternative label / placeholder | Or check against a key you were given / Paste a signer key (starts with RWQ) |
| Alternative button | Check |
| Alternative error | That isn't a valid signer key. |
| Alternative mismatch | This package was signed by a different key than the one you entered. |

Receipt tile:

| Element | Copy |
|---|---|
| Tile title | Check a receipt |
| DropZone headline | Drop a .receipt.json here |
| Button | Choose receipt… |
| Field label / placeholder | Service key (optional) / Paste the service key from the manifest |
| Field helper (shown while the field is empty) | Enter the service key from the sealed manifest to pin it. |
| Success with a service key entered (`pinned: true`; ok chip) | Receipt verified. First opened [date] UTC, window ends [date] UTC, opened [n] time(s). |
| Success without a service key (`pinned: false`; warn chip) | Signature valid — service key not checked. First opened [date] UTC, window ends [date] UTC, opened [n] time(s). |
| Not opened (either chip, as above) | The package has not been opened yet. |
| Error | The receipt signature doesn't match. Don't rely on it. |
| Error: key mismatch | The receipt wasn't signed by the service key you entered. |
| Error: unreadable | That doesn't look like a sealdrop receipt. |

### 6.4 States

| State | What changes visually |
|---|---|
| Idle | Package tile shows the DropZone; Result shows the empty-state sentence; Receipt tile shows its small DropZone. |
| Working | Package summary row replaces the DropZone; Result shows an indeterminate `progress` pill and "Checking the signature and hash…". |
| Success | Result headline chip sage "Signature valid"; three ok rows; details list. Signer tile shows "[name] (trusted)". |
| Warning | Headline chip cream "Signer not trusted"; the signature row is ok, the signer row has the warning glyph; Signer tile shows the trust form. |
| Error | Headline chip pink-tint "Verification failed"; failing rows with the error glyph and the exact reason; trust form hidden (do not invite trusting a failed package). |

### 6.5 Accessibility notes

- Tab order: nav, banner button, Choose package…, Copy (SHA-256), Name, Trust this signer, alternative key, Check, Choose receipt…, Service key.
- The result headline chip is the first element after the Result title and is announced with the live region when it appears ("Signature valid." / "Signer not trusted." / "Verification failed.").
- Rows use glyph + text; the glyph is `aria-hidden`.
- Hash and key values are selectable monospace text; Copy buttons announce "Copied.".

---

## 7. Screen: Keys

Purpose: create or replace your identity, manage trusted signers, and see receipts for timed packages you sent.

### 7.1 Wireframe

```

   (~~~)     Keys                                                                        ( * Identity ready )
             Your identity, trusted signers and receipts.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ YOUR IDENTITY                                       │ │ RECEIPTS                             │
  │ [@] │    │ Recipient: give this to people who send to you      │ │ Pick the manifest of a package you   │
  ╰─────╯    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │ sealed.                              │
   Seal      │ ┆ age1qx7k4m...9d4m0s3f                           ┆ │ │ ( Choose manifest... )               │
             │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │                                      │
  ╭─────╮    │ ( Copy recipient )                                  │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
  │ [v] │    │ Signer key: people add this to check what you send  │ │ ┆ report-q3                        ┆ │
  ╰─────╯    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │ ┆ ‹ Opened 13 Oct 09:12 UTC ›      ┆ │
   Open      │ ┆ RWQf6LRCGA9i53mlYecO4Izt...                     ┆ │ │ ┆ [ expires in 4 m 10 s ]          ┆ │
             │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ ┆ Opened 2 times                   ┆ │
  ╭─────╮    │ ( Copy signer key )   ( Replace identity... )       │ │ ┆ (ok) Receipt verified            ┆ │
  │ [/] │    │                                                     │ │ ┆ ( Check now )                    ┆ │
  ╰─────╯    │ Stored in C:\Users\you\.sealdrop. The private keys  │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  Verify     │ never leave this computer.                          │ │                                      │
             ╰─────────────────────────────────────────────────────╯ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
  ┌╌╌╌╌╌┐    ╭─────────────────────────────────────────────────────╮ │ ┆ payroll-oct                      ┆ │
  ┆[o-] ┆    │ TRUSTED SIGNERS                                     │ │ ┆ Opened 10 Oct 15:02 UTC, expired ┆ │
  └╌╌╌╌╌┘    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │ ┆ Opened 1 time                    ┆ │
   Keys      │ ┆ alice   RWQf6LRCGA...3xK                 Remove ┆ │ │ ┆ (ok) Receipt verified            ┆ │
             │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ ┆ ( Check now )                    ┆ │
             │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
             │ ┆ bob     RWQa91Zc7p...Qm2                 Remove ┆ │ │                                      │
             │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │
             │                                                     │ │ ┆ site-plans                       ┆ │
             │ Add a signer                                        │ │ ┆ ‹ Waiting: not opened yet ›      ┆ │
             │ ┌╌╌╌╌╌╌╌╌╌╌╌╌┐  ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐            │ │ ┆ (ok) Receipt verified            ┆ │
  ╭─────╮    │ ┆ Name       ┆  ┆ Signer key (RWQ...)  ┆  ( Trust ) │ │ ┆ ( Check now )                    ┆ │
  │ [=] │    │ └╌╌╌╌╌╌╌╌╌╌╌╌┘  └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘            │ │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
  ╰─────╯    │                                                     │ │                                      │
 Settings    │ Letters, digits, - and _ only.                      │ │ Not saved. Gone when you close       │
             │                                                     │ │ sealdrop.                            │
             ╰─────────────────────────────────────────────────────╯ ╰──────────────────────────────────────╯
 sealdrop 0.2
```

Grid: left `.span-7` = "Your identity" over "Trusted signers"; right `.span-5` = "Receipts" (tall). Without an identity the first tile becomes the empty state and the Receipts and Trusted tiles still render (trusted signers can be added without an identity).

### 7.2 Components

| Tile | Primitives |
|---|---|
| Your identity (none) | Tile, text, SoftButton primary "Create identity" |
| Your identity (present) | Tile, Field `value` x2 (recipient, signer key), SoftButton `--sm` "Copy recipient", "Copy signer key", SoftButton `--pink` "Replace identity…", Tile `dialog` (Replace) |
| Trusted signers | Tile, list of Tile `row` (name, short key, link-btn "Remove"), Field text x2, SoftButton "Trust signer" |
| Receipts | Tile, SoftButton "Choose manifest…", list of Tile `row` (session only) with Chip `status`, Countdown (running / low / expired / waiting), SoftButton `--sm` "Check now", text |

### 7.3 Copy

Header: title "Keys"; subtitle "Your identity, trusted signers and receipts."

**Your identity**

| Element | Copy |
|---|---|
| Tile title | Your identity |
| Empty text | You don't have an identity yet. An identity is a key pair for opening packages sent to you, plus a signing key that proves packages came from you. It stays on this computer. |
| Create button | Create identity |
| Working | Creating your keys… |
| Success (inline, live) | Identity created. |
| Recipient label | Recipient |
| Recipient helper | Give this to people who send to you. |
| Signer key label | Signer key |
| Signer key helper | People add this to their trusted signers so they can check what you send. |
| Buttons | Copy recipient / Copy signer key |
| Storage note | Stored in [dir]. The private keys never leave this computer. |
| Replace button | Replace identity… |
| Dialog title | Replace your identity? |
| Dialog body | This creates new keys and deletes the old ones. Packages sealed to your old recipient string can no longer be opened, and people who trust your old signer key will need your new one. |
| Dialog field label / placeholder | Type REPLACE to confirm / REPLACE |
| Dialog buttons | Keep my identity (default focus) / Replace identity (pink, `aria-disabled` until the word matches) |
| Error | Couldn't create the keys: [reason]. Your existing identity was not changed. |

**Trusted signers**

| Element | Copy |
|---|---|
| Tile title | Trusted signers |
| Empty text | No trusted signers yet. Packages from a signer you haven't trusted need their key each time you open or verify them. |
| Row | [name] · `RWQf6LRCGA…3xK` · link-btn Remove |
| Remove confirm (inline, in the row) | Remove [name]? Packages signed by this key will need the key entered again. (buttons Remove / Keep) |
| Add heading (label) | Add a signer |
| Name placeholder | Name, e.g. alice |
| Key placeholder | Signer key (starts with RWQ) |
| Button | Trust signer |
| Helper | Letters, digits, - and _ only. |
| Success | [name] is now trusted. |
| Errors | Use letters, digits, - and _ only. / A signer named “[name]” already exists. / That isn't a valid signer key. |

**Receipts**

| Element | Copy |
|---|---|
| Tile title | Receipts |
| Lead | Pick the manifest of a package you sealed. |
| Button | Choose manifest… |
| Row button | Check now |
| Row, not opened (Countdown `waiting`) | [name] · Waiting: not opened yet · Receipt verified |
| Row, window running (Countdown `running`/`low`, ticking from `remaining_secs`) | [name] · Opened [date] UTC · expires in [time] · Opened [n] time(s) · Receipt verified |
| Row, window over | [name] · Opened [date] UTC, expired · Receipt verified |
| Verified badge (`pinned: true`; `receipt_fetch` always pins to the service key in the manifest) | Receipt verified |
| Pinned key note | Receipts are checked against the service key recorded in the signed manifest of the package you sealed. |
| Footer note | Receipts are signed by the release service, and the service clock decides the times shown here. |
| Session note | Receipts you check here are not saved. They are gone when you close sealdrop. |
| Empty | No receipts checked yet. Choose the manifest of a timed package you sealed to see when it was opened. |
| Updated (live region) | Receipt updated. |
| Error: unreachable | Couldn't reach the release service. The row keeps its last result from this session. |
| Error: no service | No release service is set up. Add one in Settings to check receipts. |
| Error: mismatch | This receipt doesn't match the service key saved when you sealed the package. Don't rely on it. |

### 7.4 States

| State | What changes visually |
|---|---|
| No identity | Identity tile is the empty state with the primary "Create identity"; the page header pill says "No identity"; no banner on this screen. |
| Creating | Button reads "Creating your keys…", `aria-disabled`, `progress` pill indeterminate. |
| Identity present | Two `value` fields (inset, mono, selectable) with Copy buttons. |
| Copy | Button label briefly adds "Copied." beside it (inline text, live region); the label itself does not change. |
| Replace dialog | Scrim over the window, centered `Tile--dialog`; focus trapped; Esc and "Keep my identity" close it. |
| Receipts refreshing | "Check now" is `aria-disabled` with the text "Checking…"; rows keep their last state. |
| Error | `notice--err` inside the affected tile; nothing else changes. |

### 7.5 Accessibility notes

- Tab order: nav, Create identity (or Copy recipient, Copy signer key, Replace identity…), each signer's Remove, Name, Signer key, Trust signer, Choose manifest…, then each receipt row's Check now.
- The Replace dialog is `role="alertdialog"` with `aria-labelledby` (title) and `aria-describedby` (body); focus starts on "Keep my identity"; Tab is trapped; Esc closes; focus returns to "Replace identity…".
- Receipt rows are list items; the Countdown inside each uses the same `role="timer"` rule, with threshold announcements disabled in this list (too noisy); the text carries the state.
- The destructive button is pink with `--ink` text (5.7:1), and its meaning is in the label, not the colour.

---

## 8. Screen: Settings

Purpose: set the release service and deposit token, choose passphrase options (with the honest Argon2id note), and set defaults. These settings are stored locally. The release service address below is the only address sealdrop will contact on your behalf; see Network.

### 8.1 Wireframe

```

   (~~~)     Settings                                                                    ( * Identity ready )
             Release service, passphrase options and output.

             ╭─────────────────────────────────────────────────────╮ ╭──────────────────────────────────────╮
  ╭─────╮    │ RELEASE SERVICE                                     │ │ OUTPUT                               │
  │ [@] │    │ Used when you seal a timed package or check a       │ │ [o=]  ASCII armor                    │
  ╰─────╯    │ receipt.                                            │ │       Writes text instead of binary. │
   Seal      │                                                     │ │       The file is larger.            │
             │ Release service address                             │ │                                      │
  ╭─────╮    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐ │ ╰──────────────────────────────────────╯
  │ [v] │    │ ┆ https://release.example.org                     ┆ │ ╭──────────────────────────────────────╮
  ╰─────╯    │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │ │ NETWORK                              │
   Open      │                                                     │ │                                      │
             │ Deposit token                                       │ │ sealdrop makes network requests only │
  ╭─────╮    │ ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐            │ │ to: the release service you          │
  │ [/] │    │ ┆ ••••••••••••••••••••                 ┆  ( Show )  │ │ configure here (when you seal a      │
  ╰─────╯    │ └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘            │ │ timed package or check a receipt)    │
  Verify     │                                                     │ │ and the release service named inside │
             │ [[ Save ]]    Saved.     Clear service settings     │ │ a timed package you open (shown to   │
  ╭─────╮    ╰─────────────────────────────────────────────────────╯ │ you before the call).                │
  │[o-] │    ╭─────────────────────────────────────────────────────╮ │                                      │
  ╰─────╯    │ PASSPHRASES                                         │ │ Release service: release.example.org │
   Keys      │                                                     │ │                                      │
             │ [o=]  Use Argon2id for passphrases ‹Non-standard›   │ ╰──────────────────────────────────────╯
             │       Adds little over scrypt and breaks            │ ╭──────────────────────────────────────╮
             │       interoperability with stock age tools. Off    │ │ ABOUT                                │
             │       by default.                                   │ │                                      │
             │                                                     │ │ sealdrop 0.2.0                       │
             │ Default key strength                                │ │ Packages made for recipients or with │
             │ { Standard }  ( High, slower )                      │ │ a standard passphrase open in stock  │
  ┌╌╌╌╌╌┐    │                                                     │ │ age.                                 │
  ┆ [=] ┆    │ Standard is scrypt 2^18 (Argon2id: 256 MiB). High   │ │ Keys: C:\Users\you\.sealdrop         │
  └╌╌╌╌╌┘    │ is scrypt 2^20 (Argon2id: 2 GiB).                   │ ╰──────────────────────────────────────╯
 Settings    │                                                     │
             │                                                     │
             ╰─────────────────────────────────────────────────────╯
 sealdrop 0.2
```

Grid: left `.span-7` = "Release service" over "Passphrases"; right `.span-5` = "Output", "Network", "About".

### 8.2 Components

| Tile | Primitives |
|---|---|
| Release service | Tile, Field text (address), Field password (token) + "Show"/"Hide", SoftButton "Save", status text, SoftButton link "Clear" |
| Passphrases | Tile, Toggle `with-note` (Argon2id) + Chip cream "Non-standard", Pill `seg` (default key strength) |
| Output | Tile, Toggle (ASCII armor) |
| Network | Tile, text, status Pill |
| About | Tile, text |

### 8.3 Copy

Header: title "Settings"; subtitle "Release service, passphrase options and output."

**Release service**

| Element | Copy |
|---|---|
| Tile title | Release service |
| Lead | Used when you seal a timed package or check a receipt. |
| Address label / placeholder | Release service address / https://release.example.org |
| Address helper | Must start with https://. http:// works only for this computer (localhost). |
| Token label / placeholder | Deposit token / Paste the token your operator gave you |
| Token helper | Saved in sealdrop's settings on this computer. When you seal, sealdrop signs the manifest and then deposits the key with the service you configured. When you open a timed package or check a receipt, sealdrop verifies the manifest signature first and sends the deposit token only to the service named in that signed manifest. |
| Show / Hide | Show / Hide |
| Button | Save |
| Saved | Saved. |
| Clear (link-btn) | Clear service settings |
| Errors | That address isn't valid. Use https://host, or http://localhost. / Use https:// for a service on another computer. / Enter the address before the token. |

**Passphrases**

| Element | Copy |
|---|---|
| Tile title | Passphrases |
| Toggle label (default off) | Use Argon2id for passphrases |
| Chip (cream, next to the label, always visible) | Non-standard |
| Honesty note (verbatim, always visible under the toggle, `--ink`, 13 px, never in a tooltip) | Adds little over scrypt and breaks interoperability with stock age tools. Off by default. |
| Extra line when on | Packages made this way open only in sealdrop. |
| Segment label | Default key strength |
| Segment | Standard / High (slower) |
| Helper | Standard is scrypt 2^18 (Argon2id: 256 MiB). High is scrypt 2^20 (Argon2id: 2 GiB). |
| Saved (inline, live) | Saved. |

**Output** (the app persists exactly five settings: `release_service`, `release_token`, `scrypt_log_n` (18 or 20), `armor`, `argon2id`; nothing else, so there are no other defaults to show)

| Element | Copy |
|---|---|
| Tile title | Output |
| Toggle (default off) | ASCII armor |
| Helper | Writes text instead of binary. The file is larger. |

**Network**

| Element | Copy |
|---|---|
| Tile title | Network |
| Text (verbatim) | sealdrop makes network requests only to: the release service you configure here (when you seal a timed package or check a receipt) and the release service named inside a timed package you open (shown to you before the call). |
| Status pill | Release service: [host] / Release service: not set |

**About**

| Element | Copy |
|---|---|
| Tile title | About |
| Version | sealdrop 0.2.0 |
| Text | Packages made for recipients or with a standard passphrase open in stock age tools. Argon2id and timed release packages need sealdrop. |
| Key store | Keys are stored in [dir]. |

### 8.4 States

| State | What changes visually |
|---|---|
| Idle | Fields show saved values; token is masked. |
| Editing service fields | "Save" becomes enabled (raised, blue-ac); until then `aria-disabled`. |
| Saving | "Save" reads "Saving…" and is `aria-disabled`; on success the text "Saved." appears beside it and in the live region for 4 seconds, then stays as the field state. |
| Toggles and segments | Apply immediately; "Saved." appears next to the changed control. No Save button for them. |
| Error | `field__error` under the field, `aria-invalid`; the old saved value stays in effect. |

### 8.5 Accessibility notes

- Tab order: nav, banner button, address, token, Show, Save, Clear, Argon2id toggle, strength segment, ASCII armor.
- The Argon2id toggle is `role="switch"` with `aria-describedby` pointing at the honesty note, so a screen reader reads the note with the switch.
- The token field is `type="password"`, `autocomplete="off"`, never echoed back into the DOM as plain text unless Show is pressed; Show state resets when you leave the screen.
- "Non-standard" chip: ink on cream (9.1:1); the same word is in the note, so colour is not required.

---

## 9. Accessibility rules that apply everywhere

- Target: WCAG 2.2 AA. All body text is `--ink` on `--bg` or an accent tint at 4.5:1 or better (measured in section 1.2). Muted text is `--muted-ac` (5.1:1). Large decorative digits are also in `--ink`.
- White text on pink, blue or sage is used nowhere. Pink and blue are fills, glyphs and rings. Class `aa` on the root (mandatory) enforces this for the fixed CSS.
- Focus: every interactive element has a visible 3 px `--blue-deep` ring (3.05:1 on `--bg`). Fields show it as a ring around the inset. Never remove an outline without replacing it. Focus order follows visual order (left column then right column, top to bottom).
- Hit targets: nav 64 px, buttons about 45 px high (`--sm` buttons about 36 px), toggle rows 44 px high (the switch itself is 52 x 30 and the row is the target), chip remove buttons 24 px (minimum for WCAG 2.2 target size) with spacing, `link-btn` 28 px high with 6 px side padding.
- Toggles are `role="switch"` with `aria-checked`; segmented choices are `role="radiogroup"` with arrow-key selection; disclosures use `aria-expanded`; dialogs use `role="alertdialog"` with a focus trap and Esc; the countdown is `role="timer"`.
- Drop zone: not a tab stop; the buttons inside it are the keyboard alternative and are always visible.
- Live regions: one polite region for outcomes; progress phase text is `aria-live="polite"` and replaces itself (no stacking); errors use `role="alert"` once, when they appear. The passphrase is never put in a live region.
- Status is never colour alone: word + glyph + tint. Toggles show On/Off text and knob position.
- Motion: `prefers-reduced-motion` removes transitions and the sliding progress. Forced-colours mode gets 1 px `CanvasText` borders (already in `neu.css`).
- Text scaling to 200%: tiles grow, nothing has a fixed height except the nav pills and the 200 px drop zone's minimum; wireframes show the default size.
- Language: the root has `lang="en"`. Dates use the format in section 2 and include UTC where the service clock is involved.

---

## 10. What the app must never do

Network

- Make any network request other than those in this sentence, which is also shown in Settings: "sealdrop makes network requests only to: the release service you configure here (when you seal a timed package or check a receipt) and the release service named inside a timed package you open (shown to you before the call)." All of them are made by Rust, never by the WebView. No telemetry, analytics, update checks, crash reporting, font or icon CDNs, remote images, or link previews.
- Let the WebView fetch anything. CSP is `default-src 'self'`; fonts and glyphs are bundled; the WebView has no `http`, `shell` or `fs` plugin. All file access goes through Rust commands with paths from native dialogs or drag-and-drop.
- Send the deposit token anywhere except the service recorded in the package's own signed manifest (the backend checks the manifest signature first). Never use the Settings address for a token that belongs to a package's service. Never put it in a URL, a title, a log or an error message.

Secrets

- Keep a secret in UI state longer than needed. The generated passphrase lives only in the Seal success state: it is cleared when the user presses Hide, leaves the Seal screen, starts another seal, or after 5 minutes idle, and it is never written to `localStorage`, `sessionStorage`, IndexedDB, the URL, the window title or the console. A passphrase typed in Open is cleared on success, on leaving the screen and after 5 minutes idle. The deposit token is shown masked and only revealed while Show is on. Private keys are never sent to the WebView (`get_identity` returns the public recipient and signer strings only).
- Show the passphrase more than once. After Hide there is no way to bring it back, and the copy says so.
- Offer a QR code for anything except the generated passphrase.
- Log, persist or display secrets in crash output. Ship release builds without dev tools.

Honesty

- Say or imply that expiry removes decrypted content. The Seal sentence appears on Seal; the expiry sentence appears on Open and Verify. Never write "self-destruct", "revoke", "erase" or "secure" about a package.
- Decide expiry from the local clock. The countdown is a display of the service's `expires_at`; the service is the authority.
- Treat an unknown signer as fine. It is a warning that blocks opening until the user trusts the key or enters the expected key.
- Hide the Argon2id caveat. The note is always visible next to the toggle and again wherever Argon2id is used.

Files

- Open or run anything it extracted; extract without verifying (unless the user turns on "Skip verification", which is off by default); overwrite existing files unless "Replace existing files" is on; write outside the chosen folder; or follow links in a package (the core refuses them; the UI shows the error).
- Seal into a folder inside the source folder.

Interface

- Auto-dismiss an error, use confetti or celebration, use exclamation marks or emoji, or put white text on pink or blue.
- Use a modal for anything that is not destructive (only "Replace identity" uses one).

---

## 11. Backend contract

Fixed facts, decided after design review. These are the Tauri commands the screens call. Every command returns a result or an error string (`Result<T, String>`); the UI shows the error string inside the copy patterns above (for example "Couldn't seal: [reason]."). There is no `http`, `shell` or `fs` plugin: the WebView never talks to the network and never reads files; all file and network work happens in Rust.

### 11.1 Commands

| Command | Returns | Used by |
|---|---|---|
| `get_identity()` | `{ exists, recipient?, signer?, dir }` (`dir` is the key-store path shown in Keys and Settings) | shell (status pill, banner), Keys |
| `generate_identity(force)` | same shape as `get_identity` | Keys ("Create identity"; "Replace identity" calls it with `force = true`) |
| `parse_recipient(s)` | `{ kind, fingerprint, plugin: string \| null, allowed: bool }` | Seal, at add-time. Failure (error string) shows "Not a recipient string". `allowed = false` shows "Plugin [name] is not on the allow-list". Chip colour from `kind`; hardware-only rule from `kind` starting with `plugin:`. "Plugin binary missing" cannot be known here: it surfaces as the Seal error. |
| `seal(args)` | `{ package, manifest, package_id, ciphertext_sha256, files, bytes, passphrase?, entropy_bits?, release?: { service, window_secs } }` | Seal. `passphrase` and `entropy_bits` are present only in passphrase mode; `release` only for timed release. |
| `probe(path)` | `{ needs_passphrase, timed_release?: { service, release_id } }` | Open, for `.sealdrop.age` files only. Decides whether the Unlock tile asks for a passphrase and whether the Timed package tile shows. The Seal input is never probed or pre-scanned: the Seal DropZone shows the chosen path and nothing else (no "[n] files · [size]"). |
| `verify(path, signer?)` | `{ ok, untrusted_signer?, package_id?, signer?, trusted_as?, created?, classification?, expires?, recipients?: [{ kind, fingerprint }], release?: { service, window_secs }, ciphertext_sha256? }` | Verify and the Delivery record in Open. `ok = false` with `untrusted_signer` set is the "Signer not trusted" state; the "Trust this signer" mini-form (name field) uses that key with `add_trusted`. Any other failure is an error string and shows the failed state. `signer` (second argument) is the expected-key field. |
| `open_package(args)` with `args` including `temp: boolean` and `out_dir?: string` (plus `path`, `passphrase?`, `signer?`, `overwrite?`, `skip_verify?`, mirroring the CLI) | `{ root, files, bytes, signer?, trusted_as?, verified: bool, first_unlock?, expires_at?, remaining_secs? }` | Open. `verified = false` means "Skip verification" was on: show "Signature NOT verified — you chose to skip verification." (warn badge) and hide "Contents match the signed record." For timed packages `remaining_secs` (service clock) drives the Countdown. |
| `list_trusted()` / `add_trusted(name, key)` / `remove_trusted(name)` | trusted signers `[{ name, key }]` / ok / ok | Keys, Verify, Open |
| `get_settings()` / `set_settings(s)` | exactly `{ release_service?, release_token?, scrypt_log_n (18 \| 20), armor, argon2id }` | Settings. These five fields ARE the app defaults; nothing else is persisted (no default word list, save folder or "Also encrypt to me" default; those reset per session). `scrypt_log_n` 18 is "Standard", 20 is "High (slower)"; `armor` is the ASCII armor toggle; `argon2id` is the Settings toggle. |
| `receipt_fetch(manifest_path)` | `{ release_id, first_unlock?, expires_at?, remaining_secs?, unlock_count, service_key, pinned: true, saved_to }` | Keys (Receipts: "Choose manifest…", then "Check now" per row). The key is pinned to the service key recorded in the manifest, so the chip is always "Receipt verified". `remaining_secs` is the service-clock remaining time at the moment of the response. |
| `receipt_verify(receipt_path, service_key?)` | same as `receipt_fetch` without `saved_to`, with `pinned: bool` | Verify ("Check a receipt"). `pinned = true` (a service key was entered and matched): "Receipt verified". `pinned = false`: warn chip "Signature valid — service key not checked" plus the helper "Enter the service key from the sealed manifest to pin it." |

Receipt chips: Keys rows come from `receipt_fetch`, which is always pinned (to the service key recorded in the signed manifest), so they always read "Receipt verified". Verify's receipt check depends on `pinned`: `true` shows "Receipt verified" (ok badge); `false` shows "Signature valid — service key not checked" (warn badge) and the helper text above.

Opening "Save to…" after a temporary open is a second `open_package` call with `temp = false` and an `out_dir`. It is a second unlock inside the window, and the helper under the button says so ("Saving to a folder unlocks the package a second time, inside the window.").

### 11.2 Progress event

One event, `progress { kind, detail }`, with `kind` one of `packing`, `encrypted`, `contacting`, `verifying`, `extracting`, `done`. Phase labels map as follows (the UI shows one label at a time and keeps `detail` out of the label unless it is a count or a host).

| `kind` | Seal label | Open label |
|---|---|---|
| `packing` | Packing and encrypting… | (not used) |
| `encrypted` | Signing and writing the delivery record… | (not used) |
| `contacting` | Placing the key with the release service… (timed only) | Contacting [host]… (timed only) |
| `verifying` | (not used) | Verifying… |
| `extracting` | (not used) | Decrypting and restoring… |
| `done` | success state | success state |

### 11.3 Countdown clock

The Countdown on Open and in each Keys receipt row is driven by `remaining_secs`, which is read on the service clock at the moment of the response. The UI advances it with a monotonic timer (never the system wall clock) from that sample: displayed = `remaining_secs - elapsed_since_response`, clamped at 0, then "expired". The Keys row ticks the same way from the `receipt_fetch` sample; "Check now" takes a new sample. Nothing is ever extended, and no deadline is stored locally.

### 11.4 Rules the backend enforces (the UI relies on them)

- When you seal, sealdrop signs the manifest and then deposits the key with the service you configured. When you open a timed package or check a receipt, sealdrop verifies the manifest signature first and sends the deposit token only to the service named in that signed manifest.
- Argon2id: Standard is the compat profile (256 MiB); High is the desktop profile (2 GiB). The Seal helper for High with Argon2id reads "High needs about 2 GiB of free memory to open." For scrypt, `scrypt_log_n` 18 or 20.
- The QR is rendered client-side from the words with the `qrcode` npm package into a canvas. Nothing is sent anywhere to make it.
- `parse_recipient` is the only recipient validation the UI does; it makes no network call.
- Window rule for the UI: nothing in the WebView stores secrets (see section 10); `get_identity` returns public strings only.
- Fonts: bundle Nunito Variable locally (see 1.3) so the CSP and the network rule hold.