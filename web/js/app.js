// LocalDocsMD - Application JavaScript

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

function applyUiMonoFont(stack) {
    document.documentElement.style.setProperty('--font-ui', stack);
    document.documentElement.style.setProperty('--font-mono', stack);
}

function applyReadingFont(stack) {
    document.documentElement.style.setProperty('--font-sans', stack);
    document.documentElement.style.setProperty('--font-reading', stack);
}

/**
 * Mermaid initialize config per UI theme. Uses themeVariables so colours
 * match the active palette exactly rather than relying on Mermaid's own
 * built-in dark/default tokens which ignore our CSS variables.
 * @param {string} theme - UI theme name
 * @returns {object} Mermaid initialize options object
 */
function mermaidConfigFor(theme) {
    const configs = {
        'daylight': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#f5ede0', primaryTextColor: '#2c1a0a',
                primaryBorderColor: '#c2610a', lineColor: '#7a5535',
                secondaryColor: '#fdf8f0', tertiaryColor: '#fffcf7',
                background: '#fdf8f0', mainBkg: '#fffcf7',
                nodeBorder: '#c2610a', clusterBkg: '#f0e4d0',
                titleColor: '#2c1a0a', edgeLabelBackground: '#fffcf7',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'hc-light': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#dbeafe', primaryTextColor: '#000000',
                primaryBorderColor: '#000000', lineColor: '#000000',
                secondaryColor: '#f0fdf4', tertiaryColor: '#fffbeb',
                background: '#ffffff', mainBkg: '#ffffff',
                nodeBorder: '#000000', clusterBkg: '#f0f0f0',
                titleColor: '#000000', edgeLabelBackground: '#ffffff',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'midnight': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#0d1628', primaryTextColor: '#e8eef8',
                primaryBorderColor: '#60a5fa', lineColor: '#7890b8',
                secondaryColor: '#080c18', tertiaryColor: '#06080f',
                background: '#06080f', mainBkg: '#0a0e1a',
                nodeBorder: '#60a5fa', clusterBkg: '#0a0e1a',
                titleColor: '#e8eef8', edgeLabelBackground: '#0a0e1a',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'catppuccin': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#313244', primaryTextColor: '#cdd6f4',
                primaryBorderColor: '#cba6f7', lineColor: '#a6adc8',
                secondaryColor: '#1e1e2e', tertiaryColor: '#11111b',
                background: '#1e1e2e', mainBkg: '#181825',
                nodeBorder: '#cba6f7', clusterBkg: '#181825',
                titleColor: '#cdd6f4', edgeLabelBackground: '#181825',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'oled': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#0a1a1a', primaryTextColor: '#e8e8e8',
                primaryBorderColor: '#00e5ff', lineColor: '#808080',
                secondaryColor: '#050505', tertiaryColor: '#020202',
                background: '#000000', mainBkg: '#0a0a0a',
                nodeBorder: '#00e5ff', clusterBkg: '#050505',
                titleColor: '#e8e8e8', edgeLabelBackground: '#0a0a0a',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'obsidian': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#2a2139', primaryTextColor: '#dcddde',
                primaryBorderColor: '#7c6f9e', lineColor: '#8e8ea0',
                secondaryColor: '#1e1a2e', tertiaryColor: '#16131f',
                background: '#1a1625', mainBkg: '#242038',
                nodeBorder: '#7c6f9e', clusterBkg: '#1e1a2e',
                titleColor: '#dcddde', edgeLabelBackground: '#242038',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
        'hc-dark': {
            theme: 'base',
            themeVariables: {
                primaryColor: '#1a1a00', primaryTextColor: '#ffffff',
                primaryBorderColor: '#ffff00', lineColor: '#ffffff',
                secondaryColor: '#0d0d00', tertiaryColor: '#000000',
                background: '#000000', mainBkg: '#0d0d0d',
                nodeBorder: '#ffff00', clusterBkg: '#0d0d0d',
                titleColor: '#ffffff', edgeLabelBackground: '#0d0d0d',
                fontFamily: 'inherit', fontSize: '13px',
            },
        },
    };
    return configs[theme] || configs['midnight'];
}

/**
 * Returns Plotly layout colours tuned for readability in the given theme.
 * Solid opaque colours are required — Plotly ignores rgba for some properties.
 * @param {string} theme - UI theme name
 * @returns {{ bg: string, text: string, grid: string, tick: string, line: string }}
 */
function plotColorsFor(theme) {
    const map = {
        // theme:     [bg,        text,      grid,      tick,      axis-line ]
        'daylight':  ['#fffcf7', '#2c1a0a', '#e8d5bc', '#7a5535', '#d4b896'],
        'hc-light':  ['#ffffff', '#000000', '#767676', '#000000', '#000000'],
        'midnight':  ['#0a0e1a', '#e8eef8', '#162030', '#7890b8', '#1e2d40'],
        'catppuccin':['#181825', '#cdd6f4', '#313244', '#a6adc8', '#45475a'],
        'oled':      ['#0a0a0a', '#e8e8e8', '#1a1a1a', '#808080', '#2a2a2a'],
        'obsidian':  ['#242038', '#dcddde', '#2e2a40', '#8e8ea0', '#3a3550'],
        'hc-dark':   ['#0d0d0d', '#ffffff', '#767676', '#ffffff', '#767676'],
    };
    const d = map[theme] || map['midnight'];
    return { bg: d[0], text: d[1], grid: d[2], tick: d[3], line: d[4] };
}

/**
 * Applies current theme colours to all rendered Plotly charts on the page.
 * @param {string} [theme] - UI theme name; reads data-theme attribute if omitted
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
 * theme variables matching the active UI theme.
 * @param {object} mConfig - Mermaid initialize options from mermaidConfigFor()
 */
async function rethemeMermaid(mConfig) {
    if (!window._mermaid) return;
    window._mermaid.initialize({ startOnLoad: false, securityLevel: 'loose', ...mConfig });
    const divs = document.querySelectorAll('.mermaid[data-processed]');
    for (const div of divs) {
        const src = div.getAttribute('data-source');
        if (!src) continue;
        try {
            const id = 'mermaid-retheme-' + Math.random().toString(36).slice(2);
            const { svg } = await window._mermaid.render(id, src);
            div.innerHTML = svg;
        } catch(_) {}
    }
}

// Theme management
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ldmd-theme', theme);
    document.querySelectorAll('.nav-theme-item').forEach(b =>
        b.classList.toggle('active', b.dataset.theme === theme));
    rethemeMermaid(mermaidConfigFor(theme));
    rethemePlots(theme);
}

// Nav popup toggle (click-based)
function toggleNavPopup(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const wasOpen = el.classList.contains('open');
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
    if (!wasOpen) {
        el.classList.add('open');
        el.previousElementSibling.classList.add('active');
    }
}

// Global font setter
function setAppFont(key) {
    const stack = UI_MONO_FONTS[key] || UI_MONO_FONTS['departure-mono'];
    applyUiMonoFont(stack);
    localStorage.setItem('ldmd-font', key);
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === key));
}

function setReadingFont(key) {
    const stack = READING_FONTS[key] || READING_FONTS['inter'];
    applyReadingFont(stack);
    localStorage.setItem('ldmd-reading-font', key);
    document.querySelectorAll('.nav-reading-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.readingFont === key));
}

window.setTheme = setTheme;
window.setAppFont = setAppFont;
window.setReadingFont = setReadingFont;

// Initialize theme and font from localStorage
(function() {
    const savedTheme = localStorage.getItem('ldmd-theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    const monoStack = UI_MONO_FONTS[savedFont] || UI_MONO_FONTS['departure-mono'];
    applyUiMonoFont(monoStack);

    const savedReadingFont = localStorage.getItem('ldmd-reading-font') || 'inter';
    const readingStack = READING_FONTS[savedReadingFont] || READING_FONTS['inter'];
    applyReadingFont(readingStack);
})();

// Mark active theme/font once the DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('ldmd-theme');
    if (savedTheme) {
        document.querySelectorAll('.nav-theme-item').forEach(b =>
            b.classList.toggle('active', b.dataset.theme === savedTheme));
    }
    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === savedFont));

    const savedReadingFont = localStorage.getItem('ldmd-reading-font') || 'inter';
    document.querySelectorAll('.nav-reading-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.readingFont === savedReadingFont));
});

// Helper functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showModal(id) {
    document.getElementById(id).style.display = 'flex';
}

function closeModal(id) {
    document.getElementById(id).style.display = 'none';
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (err) {
        console.error('Logout error:', err);
    }
    window.location.href = '/login';
}

// User menu dropdown
function toggleUserMenu(e) {
    e.stopPropagation();
    const dropdown = document.getElementById('user-dropdown');
    if (!dropdown) return;
    const isVisible = dropdown.style.display !== 'none';
    dropdown.style.display = isVisible ? 'none' : 'block';
}

// Open change-password modal from user dropdown
function openChangePassword() {
    const dropdown = document.getElementById('user-dropdown');
    if (dropdown) dropdown.style.display = 'none';
    const fields = ['cp-current', 'cp-new', 'cp-confirm'];
    fields.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    showModal('change-password-modal');
}

async function submitChangePassword(e) {
    e.preventDefault();
    const current = document.getElementById('cp-current').value;
    const newPass = document.getElementById('cp-new').value;
    const confirm = document.getElementById('cp-confirm').value;

    if (newPass !== confirm) {
        showToast('New passwords do not match', 'error');
        return false;
    }

    const btn = document.getElementById('cp-submit-btn');
    btn.disabled = true;
    btn.textContent = 'Changing...';

    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: current, new_password: newPass })
        });
        const data = await response.json();
        if (response.ok) {
            closeModal('change-password-modal');
            showToast(data.message || 'Password changed successfully', 'success');
        } else {
            showToast(data.error || 'Failed to change password', 'error');
        }
    } catch (err) {
        showToast('Connection error', 'error');
    }

    btn.disabled = false;
    btn.textContent = 'Change Password';
    return false;
}

// Close modal on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }
});

// Close modal on backdrop click; also close user dropdown and nav popups when clicking outside
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        e.target.style.display = 'none';
    }
    const menu = document.getElementById('user-menu');
    if (menu && !menu.contains(e.target)) {
        const dropdown = document.getElementById('user-dropdown');
        if (dropdown) dropdown.style.display = 'none';
    }
    if (!e.target.closest('.nav-popup-wrap')) {
        document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
        document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
    }
});

// API helper
async function api(endpoint, options = {}) {
    const defaults = {
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    const response = await fetch(endpoint, { ...defaults, ...options });
    const data = await response.json();
    
    if (!response.ok) {
        throw new Error(data.error || 'Request failed');
    }
    
    return data;
}

// Format relative time
function formatRelativeTime(timestamp) {
    const seconds = Math.floor((Date.now() / 1000) - timestamp);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
    
    return new Date(timestamp * 1000).toLocaleDateString();
}

// Debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Toast notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 24px;
        background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#16a34a' : '#2563eb'};
        color: white;
        border-radius: 4px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize highlight.js if available
document.addEventListener('DOMContentLoaded', function() {
    if (typeof hljs !== 'undefined') {
        hljs.highlightAll();
    }
});
