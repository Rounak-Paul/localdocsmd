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

## Key functions
| Function | Location | Purpose |
|---|---|---|
| `downloadPdf` | document.html ~869 | PDF export (A4, mermaid sized via onclone) |
| `downloadHtml` | document.html ~950 | Self-contained HTML export (inlines all CSS) |
| `postProcess` | document.html ~1000 | Adds copy btns, image click handlers |
| `renderMermaid` | document.html ~1060 | Renders mermaid, adds lightbox click |
| `openLightbox` | document.html ~1780 | Opens zoom/pan lightbox |
| `closeLightbox` | document.html ~1795 | Closes and cleans up lightbox |
