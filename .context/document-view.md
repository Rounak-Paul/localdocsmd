# Document View Page — Context

## Stack
- C backend (mongoose HTTP, md4c markdown, cJSON)
- Plain JS frontend — no framework, no bundler
- `web/templates/document.html` is the only template for document view
- `web/js/app.js` holds shared helpers (theme, font, modal, toast)
- `build/web/` mirrors `web/` — copy manually: `cp web/templates/X.html build/web/templates/X.html`

## Document view template structure (`document.html`)
- All document-specific HTML, CSS, and JS lives in one file (no separate JS file)
- Wrapped in an IIFE at the bottom: `(function() { ... })();`
- CDN deps: marked, marked-highlight, highlight.js, html2pdf.js, katex, morphdom
- Mermaid loaded on-demand via dynamic `import()` from jsDelivr

## PDF Export (`downloadPdf`) — synchronous
- Uses html2pdf.js (loaded synchronously from CDN)
- A4 multi-page format (`jsPDF: { format: 'a4', orientation: 'portrait' }`)
- Mermaid SVG sizing strategy: measures from `viewBox` attribute in live DOM (not
  `getBoundingClientRect` which returns clipped scroll bounds). Measurements stored in
  `mermaidTargets[]` array, indexed 1:1 with `.mermaid` elements.
- Applies dimensions inside `html2canvas.onclone` callback — modifies the clone html2canvas
  renders internally, so the live DOM is never mutated. No restore loop needed.
- `onclone` also sets `clonedContent.style.overflowX = 'visible'` to prevent #doc-content
  from clipping wide SVGs during capture.
- Only live DOM mutation: `contentEl.style.background` (temporary, restored in `.then/.catch`)

## HTML Export (`downloadHtml`) — async
- Fetches each `<link rel="stylesheet">` via `fetch()` and inlines the CSS text as a single
  `<style>` block — file is fully self-contained, works offline
- Rewrites relative `url(...)` references in fetched CSS to absolute URLs so fonts/assets
  (e.g. KaTeX fonts via relative paths in katex.min.css) resolve when opened from disk
- Falls back to comment `/* could not inline URL */` if fetch fails
- Appends all inline `<style>` blocks from the live document after fetched CSS

## Mermaid
- Rendered async via `renderMermaid()` using `window._mermaid.render(id, src)`
- After render: click handler added to `.mermaid` div → opens zoom/pan lightbox
- SVG cloned, sized from viewBox to fit 90% viewport, shown in lightbox
- Theme-aware: on first load, reads current `data-theme` and calls `mermaidThemeFor()` from `app.js`
- On theme switch: `setTheme()` in `app.js` calls `rethemeMermaid()` to re-render all `.mermaid[data-processed]` divs

## Plotly
- Rendered via `renderPlots()` / `renderSinglePlot()` — reads CSS vars (`--card-bg`, `--text-color`, `--border-color`) at render time
- On theme switch: `setTheme()` in `app.js` calls `rethemePlots()` → `Plotly.relayout()` on all `[id^="plot-"]` elements

## Theming System
- `app.js` exports:
  - `mermaidConfigFor(theme)` — returns full Mermaid `initialize()` config with `themeVariables` per theme (not just a token); ensures diagrams match each palette
  - `plotColorsFor(theme)` — returns `{ bg, text, grid, tick, line }` as solid hex colours per theme; used at initial render and on re-theme
  - `rethemeMermaid(mConfig)` — re-renders all `.mermaid[data-processed]` with new config
  - `rethemePlots(theme)` — `Plotly.relayout()` all `[id^="plot-"]` with full axis/legend/font colours
- `setTheme()` calls both after switching `data-theme`
- `renderPlots()` / `renderSinglePlot()` now accept a `colors` object (not raw CSS var strings) for reliable Plotly rendering (rgba strings silently fail in Plotly)
- Themes: 66 total; 10 background renderers (none, particles, waves, matrix, aurora, starfield, metaballs, flowfield, fireflies, circuit, voronoi)
- Navbar picker HTML generated in `src/routes.c` → `set_navbar()` (buffer: 16384 bytes, well within)
- `markdown-body pre` uses `var(--code-bg)` / `var(--code-border)` (not hardcoded dark colors)

## JS Module Structure (load order)
1. `web/js/themes.js` — THEMES array, `mermaidConfigFor(theme)`, `plotColorsFor(theme)` — pure data, no DOM
2. `web/js/backgrounds.js` — `_themeRGB()`, `_glProgram()`, BACKGROUNDS array, `setBg(id)`, `initBgList()`, `_drawBgSwatch()`
3. `web/js/app.js` — fonts, theme switching, nav popup, modal, toast, `debounce()`, `formatRelativeTime()`, `api()`, `rethemeMermaid()`, `rethemePlots()`, `_attachMermaidInteraction()`
   - All three are classic `<script>` tags (not ES modules), loaded in order from `layout.html`
   - To add a new module: create `web/js/<name>.js`, expose globals needed by app.js, add `<script>` before `app.js` in layout.html

## Mermaid (document.html)
- Loaded from CDN: `mermaid@11` (ESM import, on demand) — supports all diagram types
- `MERMAID_CDN` constant at top of inline `<script>` block
- `_loadMermaid()` — loads + initialises once with active theme config
- `_sanitizeMermaidSrc(src)` — strips CRLF, zero-width chars, smart quotes before render
- `renderMermaid()` — processes all `.mermaid:not([data-processed])` divs; calls `_attachMermaidInteraction(div)` from app.js
- `_attachMermaidInteraction(div)` (app.js) — inline pan/zoom (mousewheel + drag + pinch), floating toolbar (zoom in/out/reset/fullscreen)
- `rethemeMermaid(mConfig)` (app.js) — re-renders all `.mermaid[data-processed]` on theme change, re-attaches interaction
- Errors shown inline with source for debugging
- SVG responsive: width/height attributes removed after render, maxWidth:100%

## Image Zoom
- Click handlers added to all `img` elements in `postProcess()`
- Opens zoom/pan lightbox with a cloned Image element

## Zoom/Pan Lightbox (`#zoom-lightbox`)
- State: `_lbScale`, `_lbOffX`, `_lbOffY`, `_lbDragging`, `_lbDragMoved`
- SVG mode: zoom updates `width`/`height` attributes (forces browser re-render at new res)
- Image mode: zoom uses CSS `transform: scale()` 
- Mouse wheel: zooms toward cursor (pivot: `offX = mx - (mx - offX) * (newScale/oldScale)`)
- Mouse drag: pan with mousedown/mousemove/mouseup on document
- `_lbDragMoved` flag prevents backdrop-click close after a drag
- Escape key closes lightbox (separate keydown listener in IIFE)
- `openLightbox(node)` / `closeLightbox()` — events attached/removed to avoid leaks

## Live View (WS subscriber)
The view page connects to `/ws/documents/{uuid}` as a read-only subscriber alongside the editor.

**Flow:**
1. On `DOMContentLoaded`: `liveConnect()` and HTTP fetch run in parallel
2. WS `init` → overwrite content with live in-memory canonical version, render, show "Live" indicator
3. WS `ops` → `applyOps()` on `rawMarkdown`, debounced re-render (300 ms)
4. WS `replace` → immediate full re-render
5. HTTP fetch → only renders if WS init hasn't arrived yet (fallback for no active session)
6. WS close → hide indicator, retry after 5 s (longer than editor's 3 s to deprioritise)
7. `pagehide` → `liveDisconnect()` (clean close, no reconnect timer)
8. `pageshow(persisted)` → `liveDisconnect()` + `liveConnect()` (BFCache restore)

**No ops are ever sent** — the view WS is purely read-only. Server auth is session-cookie only (same as editor). Any authenticated user with access can subscribe.

**Live indicator**: `#live-indicator` pulse dot + "Live" text shown when WS is connected.

**Key functions:**
| Function | Purpose |
|---|---|
| `liveConnect()` | Open WS, handle init/ops/replace messages |
| `liveDisconnect()` | Clean close, cancel timers |
| `applyOps(text, ops)` | Apply OT op array to text string |
| `scheduleLiveRender()` | 300 ms debounced renderMarkdown call |
| `setLiveIndicator(on)` | Show/hide the live pulse indicator |

## Key functions
| Function | Location | Purpose |
|---|---|---|
| `downloadPdf` | document.html ~869 | PDF export (A4, mermaid sized via onclone) |
| `downloadHtml` | document.html ~950 | Self-contained HTML export (inlines all CSS) |
| `postProcess` | document.html ~1000 | Adds copy btns, image click handlers |
| `renderMermaid` | document.html ~1060 | Renders mermaid, adds lightbox click |
| `openLightbox` | document.html ~1780 | Opens zoom/pan lightbox |
| `closeLightbox` | document.html ~1795 | Closes and cleans up lightbox |
