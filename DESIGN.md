---
name: CYBERGUARD AI
description: AI-driven cyber threat intelligence and risk analytics platform — an ice-lit public surface over a midnight-navy watch floor of electric-blue glass.
colors:
  void: "#06101F"
  abyss: "#081A2E"
  hull: "#0C1F36"
  steel: "#0A1729"
  deck: "#102A45"
  hairline: "rgba(150, 195, 235, 0.13)"
  hairline-strong: "rgba(160, 210, 255, 0.26)"
  ink: "#EEF6FF"
  mist: "#A9C1D8"
  dim: "#6F8AA4"
  pulse: "#49B8FF"
  ion: "#64D8FF"
  crystal: "#8BE4FF"
  violet: "#9A8CFF"
  critical: "#FF4D5E"
  high: "#FF963D"
  medium: "#FFD166"
  low: "#42C98A"
  info: "#78B7FF"
  ice: "#DCEAF4"
  pale: "#B9CFE0"
  slateblue: "#627C94"
  midnight: "#0A1728"
  terrain: "#050A11"
  frost: "#F2F7FA"
  glacier: "#8FD4F5"
typography:
  statement:
    fontFamily: "Barlow Condensed, Public Sans, sans-serif"
    fontSize: "clamp(3.7rem, 8.8vw, 8.8rem)"
    fontWeight: 600
    lineHeight: 0.8
    letterSpacing: "-0.012em"
    textTransform: "uppercase"
  display:
    fontFamily: "Bricolage Grotesque, Public Sans, sans-serif"
    fontSize: "clamp(2.6rem, 5vw, 4.6rem)"
    fontWeight: 500
    lineHeight: 0.94
    letterSpacing: "-0.055em"
  headline:
    fontFamily: "Barlow Condensed, Public Sans, sans-serif"
    fontSize: "clamp(1.95rem, 2.9vw, 2.9rem)"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.012em"
    textTransform: "uppercase"
  title:
    fontFamily: "Barlow Condensed, Public Sans, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "0.018em"
    textTransform: "uppercase"
  body:
    fontFamily: "Public Sans, Segoe UI, sans-serif"
    fontSize: "13.5px"
    fontWeight: 400
    lineHeight: 1.75
    letterSpacing: "0"
  label:
    fontFamily: "JetBrains Mono, Cascadia Code, monospace"
    fontSize: "10px"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.15em"
rounded:
  chip: "5px"
  control-sm: "8px"
  control: "9px"
  quiet: "14px"
  panel: "16px"
  overlay: "12px"
  capsule: "999px"
spacing:
  hair: "4px"
  tight: "8px"
  snug: "12px"
  base: "16px"
  roomy: "20px"
  section: "24px"
  gutter: "32px"
components:
  button-primary:
    backgroundColor: "linear-gradient(180deg, #8BE4FF, #2D8FE8)"
    textColor: "#031220"
    rounded: "{rounded.control}"
    padding: "0 15px"
    height: "39px"
    typography: "{typography.title}"
  button-primary-hover:
    backgroundColor: "linear-gradient(180deg, #A3ECFF, #3D9DF0)"
    textColor: "#031220"
  button-ghost:
    backgroundColor: "rgba(12, 30, 52, 0.62)"
    textColor: "#CFE1F2"
    rounded: "{rounded.control}"
    padding: "0 15px"
    height: "39px"
  button-danger:
    backgroundColor: "rgba(255, 77, 94, 0.10)"
    textColor: "#FF98A6"
    rounded: "{rounded.control}"
    padding: "0 15px"
    height: "39px"
  chip:
    backgroundColor: "rgba(100, 216, 255, 0.06)"
    textColor: "#B8D4EA"
    rounded: "{rounded.chip}"
    padding: "0 8px"
    height: "23px"
    typography: "{typography.label}"
  field:
    backgroundColor: "rgba(4, 12, 24, 0.72)"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "39px"
    typography: "{typography.body}"
  nav-item-active:
    backgroundColor: "linear-gradient(90deg, rgba(73, 184, 255, 0.17), rgba(100, 216, 255, 0.045) 62%, rgba(154, 140, 255, 0.05))"
    borderColor: "rgba(255, 255, 255, 0.09)"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    height: "34px"
---

# Design System: CYBERGUARD AI

## Overview

**Creative North Star: "Cold Light, Deep Water"**

CyberGuard AI is one product with two related climates. The public surface is a cinematic ice field: pale glacier light behind an enormous condensed statement, a faceted glass cube turning in cold air, dark mountain terrain below, and floating evidence cards. The authenticated console is the watch floor at night: midnight-navy glass, a diffused blue glow from the left, fine illuminated hairlines and dense instrumentation. The transition from ice to midnight is the brand gesture — daylight clarity at the door, deep-focus operations inside.

Both climates share one grammar: oversized condensed uppercase statements, small wide-tracked telemetry mono, glass surfaces with real depth, and data that is never decorative. The landing moves between pale and dark bands so each section has its own light; the console stays dark so analysts can read tables for hours. The glass cube is the single authored kinetic sculpture — it appears in the hero and behind the authentication stage. The global threat map and correlation graph remain the analytical stages.

**Key Characteristics:**
- Midnight-navy foundation (#06101F) with electric blue (#49B8FF) for action and data, signal cyan (#64D8FF) for focus and live state.
- Pale glacier marketing bands (#DCEAF4, #E7EEF5) carrying near-black condensed type (#0A1728); terrain silhouettes shift from #0B1622 to #050A11.
- Frosted glass panels — `rgba(19,43,71,0.62)` to `rgba(5,14,26,0.92)` with an 18px blur, 1px blue hairline, inset top sheen and an optional moving gloss.
- A diffused blue glow field behind the console, biased to the left rail, plus a 26px dot lattice and a faint film grain on marketing.
- Barlow Condensed for statements, headlines and panel titles; Bricolage Grotesque for numeric display; Public Sans for prose; JetBrains Mono for labels.
- Severity colour is semantic and scarce; violet still marks provenance.
- Authored data scenes: rotating crystal cube with a procedural bee specimen, procedural terrain, count-scaled geographic map, correlation wall.

## Colors

A midnight instrument palette: blue-black ground, electric-blue action, cyan signal, violet provenance, and a five-step severity scale that is never decorative.

### Primary
- **Electric Blue** (#49B8FF): the action and data colour. Chart bars, marker cores, ranking bars, links, table hover wash, and the darker counterpoint inside the glass cube.
- **Signal Cyan** (#64D8FF): the instrument light. Focus rings, active rails, selected states, live dots, map labels, and the inner light of the cube.
- **Crystal** (#8BE4FF): the brightest highlight, reserved for marker highlights, the cube core and the primary-button top stop.
- **Provenance Violet** (#9A8CFF): provenance badges, tertiary series, map caveat corner, and one panel tick. Never used for warnings or primary action.

### Public Surface (Ice)
- **Ice** (#DCEAF4): the landing hero field and the light half of the brand.
- **Frost** (#F2F7FA): floating cards and light statement surfaces.
- **Pale** (#B9CFE0) and **Slate Blue** (#627C94): secondary copy on light bands.
- **Midnight** (#0A1728): statements and body copy on ice.
- **Terrain** (#050A11): the procedural foreground silhouette; glacier accents use **Glacier** (#8FD4F5).

### Neutral
- **Void** (#06101F): page background and the outer night.
- **Abyss** (#081A2E): rails, sticky toolbars, drawer chrome.
- **Hull** (#0C1F36): panel base and raised surface.
- **Steel** (#0A1729): quiet inset surfaces and field fills.
- **Deck** (#102A45): hover plates, selected rows, map ocean highlights.
- **Ink** (#EEF6FF): primary text and numeric readouts.
- **Mist** (#A9C1D8): body copy and secondary values.
- **Dim** (#6F8AA4): labels, metadata, timestamps and axis text.
- **Hairline** (rgba(150,195,235,0.13)): every divider, panel border and table rule; **Hairline Strong** (0.26) only for overlay edges, hover emphasis and focused fields.

### Semantic
- **Critical** (#FF4D5E), **High** (#FF963D), **Medium** (#FFD166), **Low** (#42C98A), **Info** (#78B7FF). Each appears as a 21px badge, a 1–2px rail, a dot, or a chart series — never as a panel fill larger than 10% of a screen.

### Named Rules
**The Instrument Light Rule.** Cyan marks what is alive or focused. If an element does not indicate live state, focus, or the active route, it is not cyan.

**The Semantic Severity Rule.** Red, orange, amber and green-low mean risk and health, nothing else. Decorative use of severity hues is a defect, not a style choice.

**The Midnight Glass Rule.** Surfaces are built from blue-black neutrals with a real blur behind them. Glass is a material, not a decoration: every raised panel is translucent, hairline-bordered, and lit by a single cool sheen. No green undertone survives.

**The Honest Map Rule.** A marker exists only when a stored record carries source-supplied coordinates. Marker area encodes a real count; the pulse encodes presence, never live activity. Location is never rendered as attribution.

## Typography

**Display Font:** Bricolage Grotesque (numeric display, with Public Sans fallback)
**Statement / Headline Font:** Barlow Condensed 500/600/700, self-hosted (with Public Sans fallback)
**Body Font:** Public Sans (with Segoe UI, sans-serif)
**Label/Mono Font:** JetBrains Mono (with Cascadia Code, monospace)

**Character:** A very condensed, uppercase statement face carries the public argument and every console headline; a tight grotesque carries numeric readouts; a neutral humanist carries prose; a telemetry mono carries labels. The condensed `.condensed` utility fixes uppercase, 0.86 line-height and −0.012em tracking so statements stay architectural rather than shouty.

### Hierarchy
- **Statement** (600, clamp(3.7rem, 8.8vw, 8.8rem), 0.8, uppercase): public hero and closing CTA.
- **Section** (600, clamp(2.6rem, 5.2vw, 5rem), 0.86, uppercase): DETECT./CORRELATE./PRIORITISE. and light-band claims.
- **Headline** (600, clamp(1.95rem, 2.9vw, 2.9rem), 1, uppercase, condensed): console page titles.
- **Title** (600, 16px, 1, 0.018em, uppercase, condensed): panel heads.
- **Numeric** (600, 28–36px, 1, −0.02em, Bricolage): KPI and metric-card values.
- **Body** (400, 13.5px, 1.75): page descriptions and prose, capped near 74ch; tables at 13px.
- **Label** (500, 8.5–10px, 0.14–0.22em, uppercase, mono): kickers, column headers, chips, coordinates and units.

### Named Rules
**The Mono-for-Machines Rule.** If the value came from the system — counts, timestamps, hashes, CVSS, confidence, coordinates — set it in JetBrains Mono with tabular numerals. Human sentences stay in Public Sans.

**The Statement Rule.** Condensed uppercase is for the argument, never for body copy or table cells. One statement per section; supporting copy returns to Public Sans.

## Layout

The landing is a sequence of climate changes rather than one continuous dark page. A floating capsule nav sits over a pale hero (#DCEAF4): a two-line condensed statement ("SEE THE THREATS."), a risk sub-statement, real dataset readouts and a floating glass evidence card on the left; a faceted glass cube turning on a cold environment stage on the right, with one white floating card for collection health. The hero holds for a full viewport and parallaxes the cube upward on scroll. A data ticker bridges into a dark doctrine band (#071320) with procedural mountain terrain, the three-line DETECT./CORRELATE./PRIORITISE. statement and two evidence cards. A pale watch-floor band (#E7EEF5) follows with a dark operational panel showing real distributions, source state and an analyst briefing. The module rail, the cold "COLD, CALCULATED, SECURITY." statement, role solutions, the six-stage pipeline with a sticky artifact viewer, the analytics preview (distribution, ranked bars, a globe marked "interface preview"), the provenance ledger and the closing "INTELLIGENCE BEFORE IMPACT." CTA follow on alternating dark and pale grounds. Content sits in a max-width 1460px column; sections use 24–32px gutter rhythm, with a faint film grain fixed over the whole page. A desktop section dock with a progress rail floats at the bottom centre.

The console is a 248px fixed sidebar (76px collapsed) plus a 62px top bar; the rail carries a diffused blue wash biased to its top-left corner and a hairline of light down its right edge. Content sits in a max-width 1560px column with 16/20/24/32px responsive gutters and 20–28px vertical rhythm. The command centre opens with "TOTAL VISIBILITY. TOTAL CONTROL." over a five-card metric band (new vulnerabilities, critical threats, high-risk assets, active warnings, awaiting verification), each card click-through and each value animated from a real API figure. Panels use a 12-column internal grid collapsed to one column below 1024px. On mobile the sidebar becomes a 270px drawer over a scrim, KPI grids drop four → two → one, and wide tables stay in horizontally scrollable shells rather than hiding columns.

The global threat map is a map workspace, not a dashboard card: a toolbar with country search and render modes, a dominant map canvas (≈72% of the row at `xl`), and a contextual intelligence rail for the selected country or origin ranking. Both the map and the correlation graph expand to a near-viewport overlay (`inset-2`, `100dvh − 1rem`, `Escape` to close) where the canvas takes the remaining height and the surrounding chrome drops away. In full screen the map keeps a 300px docked country-intelligence rail at `xl` (classes, sources, top records, provenance caveat) and a compact floating readout below that breakpoint. Below 1024px the ranking stacks under the map and the callout collapses into the detail panel.

The correlation page is an investigation wall: the graph fills the page at `clamp(540px, 100vh − 330px, 860px)`, with a collapsible inspector rail, cluster listing beneath, in-canvas zoom/pan/fit, search dimming, and a two-record path tracer that walks retained edges only. It shares the same full-screen overlay behavior as the map, and the inspector comes back as a 352px rail whenever a node is selected in full screen.

Spacing follows a 4px base with 8/12/16/20/24/32 steps. Panel heads are 14px 18px; table cells 12px 14px; dense stat rows 10–12px gaps.

## Elevation & Depth

Tonal layering first, shadow second. The page is flat; panels are raised by the four-step navy scale, a 1px hairline, an inset top highlight (8% pale blue) and a large soft black shadow, with an 18px backdrop blur. A single radial sheen at 10%/-22% gives each panel a cool curve. Nothing floats unless it is interactive, modal, or one of the authored scenes.

### Shadow Vocabulary
- **Panel lift** (`0 26px 70px -38px rgba(0,0,0,0.95), inset 0 1px 0 rgba(185,225,255,0.08)`): every `.panel`.
- **Panel hover** (adds `0 0 34px -22px rgba(73,184,255,0.45)` and a cyan border): interactive panels only.
- **Overlay lift** (`0 24px 70px -30px rgba(0,6,15,0.92), 0 2px 10px rgba(0,0,0,0.35)`): floating nav, dropdowns, notification trays, mobile drawer, map callout.
- **Action glow** (`0 12px 34px -14px rgba(73,184,255,0.65)`): the single primary button on a view.
- **Scene bloom** (`0 0 0 1px rgba(73,184,255,0.18), 0 18px 60px -20px rgba(73,184,255,0.28)`): hero cube stage, authentication stage, map stage.

### Named Rules
**The Hairline-Before-Shadow Rule.** Separate surfaces with a 1px hairline first. Add shadow only when the element must escape the page plane.

**The Single Accent Bloom Rule.** Blue bloom appears only on the primary action and the three data scenes. Panels are lit by sheen, not by coloured glow.

## Shapes

Corners are controlled, not soft: 18px metric cards, 16px panels, 14px quiet panels, 12px overlays, 9px controls, 8px small controls and 5px chips. Borders are always 1px. The public surface adds a 999px capsule nav, dock and pill-shaped carousel controls — the one deliberate exception to the console's radius discipline. Corner ticks appear only on operational panels (`.panel-ticks`) and the auth form as 9–12px cyan/violet angle brackets. Circles are reserved for live dots, risk rings, map markers, the cube's orbital rings and its core.

## Components

### Buttons
- **Shape:** 9px radius, 39px height, 15px horizontal padding, 13px/600 label.
- **Primary:** pale ice gradient #F4FAFF → #C9E2F2 with near-black text (#07131F), a white edge and a cool ambient shadow; used once per view for the main action. On ice bands it reads as cut glass; on midnight it is the one bright object.
- **Hover / Focus:** gradient lightens one step; 2px cyan focus ring at 2px offset; active state translates 1px down.
- **Ghost:** translucent navy fill (rgba(12,30,52,0.62)) with hairline border; **Quiet:** text-only; **Danger:** 10% critical tint with critical border; **Small:** 31px height, 8px radius, 11.5px label.

### Chips
- **Style:** 23px height, 5px radius, mono 10px uppercase at 0.07em, hairline border, 6% cyan fill, #B8D4EA text.
- **Filter chips:** the map's class chips use the same shape; the active chip takes a cyan border, 10% cyan fill and cyan text.
- **Semantic variants:** severity badges are 21px with a 4px dot and tinted background at 8–14% of the semantic hue; records whose origin is not a connector retrieval take the violet-outline provenance chip.

### Cards / Containers
- **Corner Style:** 16px panels; 18px metric cards; 14px quiet variant.
- **Background:** a 16% top-left blue sheen over a 152–158° glass gradient from rgba(24,45,72,0.62) through rgba(10,20,34,0.90) to rgba(6,13,23,0.96), blurred 18px and saturated 124%.
- **Border:** 1px hairline; strong hairline for overlays and hover states. Interactive panels gain a cyan border and soft blue bloom on hover; metric cards lift 3px and pass a gloss sheen.
- **Internal Padding:** 14px 18px for heads, 16–20px for bodies, 14px 18px for dense footers.

### Inputs / Fields
- **Style:** 39px height, 9px radius, rgba(4,12,24,0.72) fill, hairline border, 13px text, dim placeholder (#5D7690).
- **Focus:** cyan border at 60% plus a 3px rgba(73,184,255,0.12) ring; no outline doubling.
- **Labels:** mono 10px uppercase at 0.13em, 6px below.

### Navigation
The public nav is a floating capsule of blurred navy glass with a cyan status dot and one primary action; below `md` it collapses to a logo, a menu plate and a full-height scrollable drawer. The console rail is 248px on a blue-washed abyss gradient with 34px items, 9px radius, dim text and 15–16px Lucide icons. Active items take a bordered glass plate (73,184,255 at 17% fading to violet at 5%), ink text, a 2px cyan rail inset 6px from the left and an inset top sheen. Counts sit as 17px mono capsules. The collapsed state is icon-only at 76px with tooltips; below 1024px the whole rail becomes a 270px drawer over a scrim. Top bar is 62px with a gradient hairline along its top edge, a posture cluster (active / critical), a 32→250px search plate and a UTC clock at `xl`.

### Tables
13px cells, 12px 14px padding, 9.5px mono uppercase sticky headers on rgba(5,14,26,0.95) with 8px blur. Rows are clickable, hover to a 6% electric-blue wash, and never zebra-stripe more than one step of steel. Numbers are tabular and right-aligned where compared.

### Signature: The Glass Cube, The Terrain & The Threat Map
The glass cube is the brand sculpture: a 2.42-unit crystal block with a clearcoat glass face, an additive reflection shell, a Fresnel rim, cyan edge beams, a geodesic containment cage, three orbital rings, sparse dust and soft halos. Inside, a fully procedural bee specimen — striped abdomen texture, thorax, head, antennae, six legs, four veined wings and a stinger — hovers and flaps while the cube turns around it. It uses a custom equirectangular studio environment, ACES tone mapping, pointer parallax, `IntersectionObserver` pause, `prefers-reduced-motion` freeze and an inline SVG fallback on WebGL failure. It anchors the landing hero and the authentication stage.

The terrain is a three-layer procedural SVG ridge system (`range` and `flanks` variants, `night` and `ice` tones). It gives the doctrine band and the authentication floor a horizon without pretending to be imagery; marketing labels the hero scene "procedural scene / not live imagery".

The authentication page is a split cinematic stage: terrain and glass cube on the left, a giant condensed "THE WATCH FLOOR IS OPEN." statement, two floating fact cards (role-scoped access, zero automated containment), and a frosted glass form panel on the right with an inner blue bloom, corner ticks and a real credential form. Below `lg` the stage collapses to the form with its facts.

The global threat map is the only scene made of real records. It layers an ocean gradient, a 30° graticule with an emphasised equator, and a dot-matrix landmask. Markers scale with the source-supplied indicator count and brighten from electric blue toward crystal; a cyan pulse reads as presence, not activity. Two render modes are honest views of the same data: **Markers** shows discrete countries, **Density** shows count-weighted blooms. Hovering reveals a country readout; selecting draws crosshair ticks, a dashed ring, a docked country card, and filters the evidence table. In-map telemetry repeats the total, country count and record count, and the map floor labels the data as location estimates, not attribution.

The correlation graph is a fourth, analytical scene: a dark plot with concentric range rings, dot lattice and a soft core glow; nodes are risk-coloured, sized by degree, and connected by curved weighted edges. Selection dims unrelated nodes, search dims non-matches, and a traced path animates its edges with a dash flow. Neither canvas invents a node or an edge.

The original particle globe survives only as a visibly labelled "interface preview" in the landing analytics section; it is never presented as live geography.

### Motion

The public surface animates in staged beats: a clip-reveal on the hero statement, staggered hero paragraphs, a slow cube rotation with pointer parallax, a marquee data ticker, scroll-parallax lift and fade on the cube, and `whileInView` rises for section content. The console is quieter: a fixed aurora drifts behind it (38s), panels rise once on mount (520ms), hovered panels pass a single gloss sheen, metric numbers count up, map markers breathe and traced correlation edges flow. Route changes are opacity-only so fixed full-screen workspaces stay anchored to the viewport. Every one of these is disabled under `prefers-reduced-motion`; only the interactive map and graph capture wheel events.

## Do's and Don'ts

### Do:
- **Do** keep the console on void, panels on hull glass with a real backdrop blur, and separators at the 13% hairline.
- **Do** let the landing alternate ice and midnight bands; the climate change is the identity.
- **Do** set every system-provided number in JetBrains Mono with tabular numerals.
- **Do** show the violet provenance chip wherever a flagged record appears.
- **Do** use one primary button per view and reserve the pale-ice gradient for it.
- **Do** give focus a 2px cyan ring and keep all dialogs keyboard-operable.
- **Do** keep the glass cube, terrain, threat map and correlation graph as the only large authored scenes.
- **Do** let the glow field, dot lattice, film grain and corner ticks stay below 10% opacity.
- **Do** state map scope in the interface: source-supplied location, record ceiling, and what the data cannot support.
- **Do** use condensed uppercase for statements and headlines only.

### Don't:
- **Don't** reintroduce green, lime or forest chrome; the navy palette is closed.
- **Don't** use critical red for hover, decoration, or emphasis that is not risk.
- **Don't** raise panels with saturated glows; use hairlines, sheen and the neutral panel shadow.
- **Don't** fill cards with gradients of severity colour or turn tables into card grids.
- **Don't** use fully rounded cards or radii above 16px (the public capsule nav, dock and carousel controls are the only pills).
- **Don't** add decorative numbering or ghost index numerals; numbering appears only where order is real.
- **Don't** invent map points, counts or live-feed claims to make a stage look busier.
- **Don't** animate ambient elements continuously in the console; motion must indicate state or entrance.
