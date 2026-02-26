// LocalDocsMD - Application JavaScript

// Nerd Font stacks
const NERD_FONTS = {
    'departure-mono': "'DepartureMono Nerd Font','DepartureMono NF','Departure Mono',monospace",
    'cascadia-cove':  "'CaskaydiaCove Nerd Font','CaskaydiaCove NF','Cascadia Code',monospace",
    'jetbrains-mono': "'JetBrainsMono Nerd Font','JetBrainsMono NF','JetBrains Mono',monospace",
};

// Theme management
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ldmd-theme', theme);
    document.querySelectorAll('.nav-theme-item').forEach(b =>
        b.classList.toggle('active', b.dataset.theme === theme));
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
    const stack = NERD_FONTS[key] || NERD_FONTS['departure-mono'];
    document.documentElement.style.setProperty('--font-ui', stack);
    localStorage.setItem('ldmd-font', key);
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === key));
}

// Initialize theme and font from localStorage
(function() {
    const savedTheme = localStorage.getItem('ldmd-theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    const stack = NERD_FONTS[savedFont];
    if (stack) document.documentElement.style.setProperty('--font-ui', stack);
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
