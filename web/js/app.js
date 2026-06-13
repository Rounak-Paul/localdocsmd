// app.js — Application coordinator.
//
// MODULE STRUCTURE (load order matters — classic scripts, not ES modules):
//   1. themes.js     — THEMES array, mermaidConfigFor(), plotColorsFor()
//   2. backgrounds.js — _themeRGB(), _glProgram(), BACKGROUNDS, setBg(), initBgList()
//   3. app.js        — fonts, theme switching, nav, modal, toast, util (this file)
//
// TO ADD A MODULE: create web/js/<name>.js, expose globals on window if needed,
// add a <script src="/js/<name>.js"> in layout.html before app.js.
// THEMES data lives in themes.js. Background renderers live in backgrounds.js.
// Mermaid rendering lives in document.html (page-scoped, uses mermaidConfigFor from themes.js).

// ============================================================
// Fonts
// ============================================================

const UI_MONO_FONTS = {
    'departure-mono': "'DepartureMono Nerd Font','DepartureMono NF','Departure Mono',monospace",
    'cascadia-cove':  "'CaskaydiaCove Nerd Font','CaskaydiaCove NF','Cascadia Code',monospace",
    'jetbrains-mono': "'JetBrainsMono Nerd Font','JetBrainsMono NF','JetBrains Mono',monospace",
};

const READING_FONTS = {
    'inter': "'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif",
    'ibm-plex-sans': "'IBM Plex Sans','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif",
    'open-sans': "'Open Sans','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif",
    'nunito': "'Nunito','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif",
    'source-serif': "'Source Serif 4','Iowan Old Style','Palatino Linotype','Book Antiqua',Palatino,serif",
    'departure-mono': "'DepartureMono Nerd Font','DepartureMono NF','Departure Mono',monospace",
    'cascadia-cove': "'CaskaydiaCove Nerd Font','CaskaydiaCove NF','Cascadia Code',monospace",
    'jetbrains-mono': "'JetBrainsMono Nerd Font','JetBrainsMono NF','JetBrains Mono',monospace",
};

/**
 * Applies a UI monospace font stack to the root CSS variables.
 * @param {string} stack - Full CSS font-family value
 */
function applyUiMonoFont(stack) {
    document.documentElement.style.setProperty('--font-ui', stack);
    document.documentElement.style.setProperty('--font-mono', stack);
}

/**
 * Applies a reading/prose font stack to the root CSS variables.
 * @param {string} stack - Full CSS font-family value
 */
function applyReadingFont(stack) {
    document.documentElement.style.setProperty('--font-sans', stack);
    document.documentElement.style.setProperty('--font-reading', stack);
}

// ============================================================
// Theme list
// ============================================================

/**
 * Populates #theme-list with buttons from THEMES (defined in themes.js), marks
 * the active entry, and attaches hover-preview and click listeners.
 */
function initThemeList() {
    const list = document.getElementById('theme-list');
    if (!list) return;
    list.innerHTML = THEMES.map(t =>
        `<button class="nav-popup-item nav-theme-item" data-theme="${t.id}">`+
        `<span class="theme-swatch" style="background:${t.swatch};border-color:${t.swatchBorder}"></span>`+
        `${t.label}</button>`
    ).join('');
    const saved = localStorage.getItem('ldmd-theme') || 'midnight';
    list.querySelectorAll('.nav-theme-item').forEach(b => {
        b.classList.toggle('active', b.dataset.theme === saved);
        b.addEventListener('mouseenter', () => {
            document.documentElement.setAttribute('data-theme', b.dataset.theme);
        });
        b.addEventListener('mouseleave', () => {
            const current = localStorage.getItem('ldmd-theme') || 'midnight';
            document.documentElement.setAttribute('data-theme', current);
        });
        b.addEventListener('click', () => setTheme(b.dataset.theme));
    });
}

/**
 * Filters the theme list to entries whose label matches the query (case-insensitive).
 * @param {string} q - Search query
 */
function filterThemes(q) {
    const list = document.getElementById('theme-list');
    if (!list) return;
    const lq = q.trim().toLowerCase();
    let visible = 0;
    list.querySelectorAll('.nav-theme-item').forEach(b => {
        const match = !lq || b.textContent.trim().toLowerCase().includes(lq);
        b.style.display = match ? '' : 'none';
        if (match) visible++;
    });
    let noRes = list.querySelector('.theme-no-results');
    if (!visible) {
        if (!noRes) { noRes = document.createElement('div'); noRes.className = 'theme-no-results'; list.appendChild(noRes); }
        noRes.textContent = 'No themes match "' + q.trim() + '"';
        noRes.style.display = '';
    } else if (noRes) {
        noRes.style.display = 'none';
    }
}

// ============================================================
// Plotly re-theming
// ============================================================

/**
 * Applies current theme colours to all rendered Plotly charts on the page.
 * @param {string} [theme] - UI theme id; reads data-theme attribute if omitted
 */
function rethemePlots(theme) {
    if (typeof Plotly === 'undefined') return;
    const t = theme || document.documentElement.getAttribute('data-theme') || 'midnight';
    const { bg, text, grid, tick, line } = plotColorsFor(t);
    const axisCommon = {
        gridcolor: grid, zerolinecolor: grid,
        tickcolor: tick, linecolor: line,
        tickfont: { color: tick }, title: { font: { color: text } },
    };
    document.querySelectorAll('[id^="plot-"]').forEach(el => {
        try {
            Plotly.relayout(el.id, {
                paper_bgcolor: bg, plot_bgcolor: bg,
                'font.color': text,
                'legend.font.color': text, 'legend.bgcolor': bg, 'legend.bordercolor': grid,
                xaxis: axisCommon, yaxis: axisCommon,
                'scene.bgcolor': bg,
                'scene.xaxis.gridcolor': grid, 'scene.xaxis.backgroundcolor': bg,
                'scene.xaxis.tickcolor': tick, 'scene.xaxis.linecolor': line,
                'scene.yaxis.gridcolor': grid, 'scene.yaxis.backgroundcolor': bg,
                'scene.yaxis.tickcolor': tick, 'scene.yaxis.linecolor': line,
                'scene.zaxis.gridcolor': grid, 'scene.zaxis.backgroundcolor': bg,
                'scene.zaxis.tickcolor': tick, 'scene.zaxis.linecolor': line,
            });
        } catch(_) {}
    });
}

/**
 * Re-renders all Mermaid diagrams that have already been processed, applying
 * theme variables matching the active UI theme. window._mermaid must be loaded.
 * @param {object} mConfig - Mermaid initialize options from mermaidConfigFor()
 */
async function rethemeMermaid(mConfig) {
    if (!window._mermaid) return;
    window._mermaid.initialize({ startOnLoad: false, securityLevel: 'loose', suppressErrors: true, ...mConfig });
    const divs = document.querySelectorAll('.mermaid[data-processed]');
    for (const div of divs) {
        const src = div.getAttribute('data-source');
        if (!src) continue;
        try {
            const id = 'mermaid-retheme-' + Math.random().toString(36).slice(2);
            const { svg } = await window._mermaid.render(id, src);
            const prevInter = div._mermaidInteractive;
            div.innerHTML = svg;
            if (prevInter) _attachMermaidInteraction(div);
        } catch(_) {}
    }
}

// ============================================================
// Theme switching
// ============================================================

/**
 * Switches the active UI theme, persists to localStorage, re-themes diagrams/plots.
 * @param {string} theme - Theme id from THEMES registry
 */
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ldmd-theme', theme);
    document.querySelectorAll('.nav-theme-item').forEach(b =>
        b.classList.toggle('active', b.dataset.theme === theme));
    rethemeMermaid(mermaidConfigFor(theme));
    rethemePlots(theme);
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
}

// ============================================================
// Nav
// ============================================================

/**
 * Toggles a nav popup menu open/closed. Closes all others first.
 * @param {string} id - Element id of the popup menu
 */
function toggleNavPopup(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const wasOpen = el.classList.contains('open');
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
    if (!wasOpen) {
        el.classList.add('open');
        el.previousElementSibling.classList.add('active');
        if (id === 'theme-dd') {
            const inp = document.getElementById('theme-search');
            if (inp) { inp.value = ''; filterThemes(''); inp.focus(); }
        }
    }
}

/**
 * Sets the UI monospace font, persists selection, updates nav state.
 * @param {string} key - Font key from UI_MONO_FONTS
 */
function setAppFont(key) {
    const stack = UI_MONO_FONTS[key] || UI_MONO_FONTS['departure-mono'];
    applyUiMonoFont(stack);
    localStorage.setItem('ldmd-font', key);
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === key));
}

/**
 * Sets the reading/prose font, persists selection, updates nav state.
 * @param {string} key - Font key from READING_FONTS
 */
function setReadingFont(key) {
    const stack = READING_FONTS[key] || READING_FONTS['inter'];
    applyReadingFont(stack);
    localStorage.setItem('ldmd-reading-font', key);
    document.querySelectorAll('.nav-reading-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.readingFont === key));
}

window.setTheme    = setTheme;
window.setAppFont  = setAppFont;
window.setReadingFont = setReadingFont;

// ============================================================
// Boot — apply persisted settings before first paint
// ============================================================

(function() {
    const savedTheme = localStorage.getItem('ldmd-theme');
    if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    applyUiMonoFont(UI_MONO_FONTS[savedFont] || UI_MONO_FONTS['departure-mono']);

    const savedReadingFont = localStorage.getItem('ldmd-reading-font') || 'inter';
    applyReadingFont(READING_FONTS[savedReadingFont] || READING_FONTS['inter']);
})();

document.addEventListener('DOMContentLoaded', function() {
    initThemeList();
    initBgList();  // defined in backgrounds.js

    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === savedFont));

    const savedReadingFont = localStorage.getItem('ldmd-reading-font') || 'inter';
    document.querySelectorAll('.nav-reading-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.readingFont === savedReadingFont));

    const savedBg = localStorage.getItem('ldmd-bg');
    if (savedBg && savedBg !== 'none') setBg(savedBg);  // setBg defined in backgrounds.js

    if (typeof hljs !== 'undefined') hljs.highlightAll();
});

// ============================================================
// Modal / auth
// ============================================================

/**
 * Escapes HTML special characters.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Shows a modal by id.
 * @param {string} id - Modal element id
 */
function showModal(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'flex';
}

/**
 * Hides a modal by id.
 * @param {string} id - Modal element id
 */
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

/**
 * Logs out the current user and redirects to the login page.
 */
async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch(_) {}
    window.location.href = '/login';
}

/**
 * Toggles the user dropdown menu.
 * @param {Event} e
 */
function toggleUserMenu(e) {
    e.stopPropagation();
    const menu = document.getElementById('user-dropdown');
    if (!menu) return;
    const isOpen = menu.classList.contains('open');
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
    if (!isOpen) menu.classList.add('open');
}

/**
 * Opens the change-password modal.
 */
function openChangePassword() {
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    showModal('change-password-modal');
}

/**
 * Submits the change-password form.
 * @param {Event} e
 */
async function submitChangePassword(e) {
    e.preventDefault();
    const form  = e.target;
    const cur   = form.querySelector('#current-password').value;
    const next  = form.querySelector('#new-password').value;
    const conf  = form.querySelector('#confirm-password').value;
    const msgEl = form.querySelector('#password-change-msg');

    if (next !== conf) {
        msgEl.textContent = 'New passwords do not match.';
        msgEl.className   = 'form-msg error';
        return;
    }
    try {
        const res = await fetch('/api/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: cur, new_password: next }),
        });
        const data = await res.json();
        if (res.ok) {
            msgEl.textContent = 'Password changed successfully.';
            msgEl.className   = 'form-msg success';
            setTimeout(() => closeModal('change-password-modal'), 1500);
        } else {
            msgEl.textContent = data.error || 'Failed to change password.';
            msgEl.className   = 'form-msg error';
        }
    } catch(_) {
        msgEl.textContent = 'Network error. Please try again.';
        msgEl.className   = 'form-msg error';
    }
}

// ============================================================
// API helper
// ============================================================

/**
 * Thin fetch wrapper that adds JSON content-type and parses the response.
 * Throws on non-2xx responses with the server's error message if available.
 * @param {string} endpoint - URL path
 * @param {RequestInit} [options]
 * @returns {Promise<any>}
 */
async function api(endpoint, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const res = await fetch(endpoint, { ...options, headers });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch(_) { data = text; }
    if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
    return data;
}

// ============================================================
// Utilities
// ============================================================

/**
 * Formats a Unix timestamp as a human-readable relative time string.
 * @param {number} timestamp - Unix seconds
 * @returns {string}
 */
function formatRelativeTime(timestamp) {
    const seconds = Math.floor(Date.now() / 1000) - timestamp;
    if (seconds < 60)     return 'just now';
    if (seconds < 3600)   return Math.floor(seconds / 60)    + 'm ago';
    if (seconds < 86400)  return Math.floor(seconds / 3600)  + 'h ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
    return new Date(timestamp * 1000).toLocaleDateString();
}

/**
 * Returns a debounced version of func that fires after wait ms of inactivity.
 * @param {Function} func
 * @param {number} wait - Milliseconds
 * @returns {Function}
 */
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

// ============================================================
// Toast
// ============================================================

const _toastStyle = document.createElement('style');
_toastStyle.textContent = `
@keyframes ldmd-slideIn  { from { transform:translateX(100%); opacity:0; } to { transform:translateX(0); opacity:1; } }
@keyframes ldmd-slideOut { from { transform:translateX(0); opacity:1; } to { transform:translateX(100%); opacity:0; } }
`;
document.head.appendChild(_toastStyle);

/**
 * Shows a transient toast notification.
 * @param {string} message
 * @param {'info'|'success'|'error'} [type]
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    const bg = type === 'error' ? '#dc2626' : type === 'success' ? '#16a34a' : '#2563eb';
    toast.style.cssText = `position:fixed;bottom:20px;right:20px;padding:12px 24px;`+
        `background:${bg};color:#fff;border-radius:4px;box-shadow:0 4px 12px rgba(0,0,0,.15);`+
        `z-index:10000;animation:ldmd-slideIn .3s ease;`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'ldmd-slideOut .3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ============================================================
// Mermaid interaction helper (used by document.html + rethemeMermaid)
// ============================================================

/**
 * Attaches inline pan/zoom interaction to a rendered .mermaid container.
 * Stores state on div._mermaidPZ so it survives re-theme re-renders.
 * @param {HTMLElement} div - The .mermaid container with an <svg> child
 */
function _attachMermaidInteraction(div) {
    const svg = div.querySelector('svg');
    if (!svg) return;
    div._mermaidInteractive = true;

    let scale = 1, tx = 0, ty = 0;
    let dragging = false, dragMoved = false;
    let ox = 0, oy = 0;

    svg.style.cssText = 'display:block;cursor:grab;touch-action:none;user-select:none;';

    function applyTransform() {
        svg.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`;
        svg.style.transformOrigin = '0 0';
    }

    function onWheel(e) {
        e.preventDefault();
        const rect = div.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const factor  = e.deltaY < 0 ? 1.12 : 1 / 1.12;
        const newScale = Math.min(8, Math.max(0.15, scale * factor));
        tx = mx - (mx - tx) * (newScale / scale);
        ty = my - (my - ty) * (newScale / scale);
        scale = newScale;
        applyTransform();
    }

    function onMousedown(e) {
        if (e.button !== 0) return;
        dragging  = true;
        dragMoved = false;
        ox = e.clientX - tx;
        oy = e.clientY - ty;
        svg.style.cursor = 'grabbing';
        e.preventDefault();
    }

    function onMousemove(e) {
        if (!dragging) return;
        tx = e.clientX - ox;
        ty = e.clientY - oy;
        dragMoved = true;
        applyTransform();
    }

    function onMouseup() {
        if (!dragging) return;
        dragging = false;
        svg.style.cursor = 'grab';
    }

    // Touch: single-finger pan, two-finger pinch-zoom
    let lastTouches = null;
    function onTouchstart(e) {
        lastTouches = e.touches;
        e.preventDefault();
    }
    function onTouchmove(e) {
        e.preventDefault();
        if (e.touches.length === 1 && lastTouches && lastTouches.length === 1) {
            const dx = e.touches[0].clientX - lastTouches[0].clientX;
            const dy = e.touches[0].clientY - lastTouches[0].clientY;
            tx += dx; ty += dy;
            applyTransform();
        } else if (e.touches.length === 2 && lastTouches && lastTouches.length === 2) {
            const prevDist = Math.hypot(
                lastTouches[0].clientX - lastTouches[1].clientX,
                lastTouches[0].clientY - lastTouches[1].clientY,
            );
            const newDist = Math.hypot(
                e.touches[0].clientX - e.touches[1].clientX,
                e.touches[0].clientY - e.touches[1].clientY,
            );
            if (prevDist > 0) {
                const rect   = div.getBoundingClientRect();
                const midX   = ((e.touches[0].clientX + e.touches[1].clientX) / 2) - rect.left;
                const midY   = ((e.touches[0].clientY + e.touches[1].clientY) / 2) - rect.top;
                const factor = newDist / prevDist;
                const newScale = Math.min(8, Math.max(0.15, scale * factor));
                tx = midX - (midX - tx) * (newScale / scale);
                ty = midY - (midY - ty) * (newScale / scale);
                scale = newScale;
                applyTransform();
            }
        }
        lastTouches = e.touches;
    }
    function onTouchend(e) { lastTouches = e.touches; }

    div.addEventListener('wheel', onWheel, { passive: false });
    svg.addEventListener('mousedown', onMousedown);
    document.addEventListener('mousemove', onMousemove);
    document.addEventListener('mouseup', onMouseup);
    div.addEventListener('touchstart', onTouchstart, { passive: false });
    div.addEventListener('touchmove',  onTouchmove,  { passive: false });
    div.addEventListener('touchend',   onTouchend);

    // Reset button + fullscreen button in a floating toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'mermaid-toolbar';
    toolbar.innerHTML =
        `<button class="mermaid-tb-btn" data-action="zoomin"  title="Zoom in">+</button>`+
        `<button class="mermaid-tb-btn" data-action="zoomout" title="Zoom out">−</button>`+
        `<button class="mermaid-tb-btn" data-action="reset"   title="Reset view">⊙</button>`+
        `<button class="mermaid-tb-btn" data-action="full"    title="Fullscreen">⛶</button>`;
    toolbar.addEventListener('click', e => {
        const action = e.target.dataset.action;
        if (!action) return;
        e.stopPropagation();
        if (action === 'zoomin')  { const f=1.3; const r=div.getBoundingClientRect(); const cx=r.width/2,cy=r.height/2; const ns=Math.min(8,scale*f); tx=cx-(cx-tx)*(ns/scale); ty=cy-(cy-ty)*(ns/scale); scale=ns; applyTransform(); }
        if (action === 'zoomout') { const f=1/1.3; const r=div.getBoundingClientRect(); const cx=r.width/2,cy=r.height/2; const ns=Math.max(0.15,scale*f); tx=cx-(cx-tx)*(ns/scale); ty=cy-(cy-ty)*(ns/scale); scale=ns; applyTransform(); }
        if (action === 'reset')   { scale=1; tx=0; ty=0; applyTransform(); }
        if (action === 'full' && typeof openLightbox === 'function') {
            const clone = svg.cloneNode(true);
            clone.style.cssText = 'display:block;cursor:default';
            openLightbox(clone);
        }
    });
    div.style.position = 'relative';
    div.style.overflow = 'hidden';
    div.appendChild(toolbar);
}
