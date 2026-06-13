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
 * Full theme registry. Each entry drives: the navbar swatch, mermaid themeVariables,
 * and Plotly colour palette. Add new themes here + a matching CSS [data-theme] block.
 * Fields: id, label, swatch (bg hex), swatchBorder (hex),
 *   mermaid { mainBkg, nodeBorder, lineColor, textColor, clusterBkg, edgeLabelBg },
 *   plot { bg, text, grid, tick, line }
 */
const THEMES = [
    { id:'midnight',       label:'Midnight',        swatch:'#06080f', swatchBorder:'#60a5fa',
      mermaid:{ mainBkg:'#0a0e1a', nodeBorder:'#60a5fa', lineColor:'#7890b8', textColor:'#e8eef8', clusterBkg:'#0a0e1a', edgeLabelBg:'#0a0e1a' },
      plot:{ bg:'#0a0e1a', text:'#e8eef8', grid:'#162030', tick:'#7890b8', line:'#1e2d40' } },

    { id:'daylight',       label:'Daylight',        swatch:'#fdf8f0', swatchBorder:'#c2610a',
      mermaid:{ mainBkg:'#fffcf7', nodeBorder:'#c2610a', lineColor:'#7a5535', textColor:'#2c1a0a', clusterBkg:'#f0e4d0', edgeLabelBg:'#fffcf7' },
      plot:{ bg:'#fffcf7', text:'#2c1a0a', grid:'#e8d5bc', tick:'#7a5535', line:'#d4b896' } },

    { id:'catppuccin',     label:'Catppuccin',      swatch:'#1e1e2e', swatchBorder:'#cba6f7',
      mermaid:{ mainBkg:'#181825', nodeBorder:'#cba6f7', lineColor:'#a6adc8', textColor:'#cdd6f4', clusterBkg:'#181825', edgeLabelBg:'#181825' },
      plot:{ bg:'#181825', text:'#cdd6f4', grid:'#313244', tick:'#a6adc8', line:'#45475a' } },

    { id:'obsidian',       label:'Obsidian',        swatch:'#1a1625', swatchBorder:'#7c6f9e',
      mermaid:{ mainBkg:'#242038', nodeBorder:'#7c6f9e', lineColor:'#8e8ea0', textColor:'#dcddde', clusterBkg:'#1e1a2e', edgeLabelBg:'#242038' },
      plot:{ bg:'#242038', text:'#dcddde', grid:'#2e2a40', tick:'#8e8ea0', line:'#3a3550' } },

    { id:'oled',           label:'OLED',            swatch:'#000000', swatchBorder:'#00e5ff',
      mermaid:{ mainBkg:'#0a0a0a', nodeBorder:'#00e5ff', lineColor:'#808080', textColor:'#e8e8e8', clusterBkg:'#050505', edgeLabelBg:'#0a0a0a' },
      plot:{ bg:'#0a0a0a', text:'#e8e8e8', grid:'#1a1a1a', tick:'#808080', line:'#2a2a2a' } },

    { id:'dracula',        label:'Dracula',         swatch:'#282a36', swatchBorder:'#bd93f9',
      mermaid:{ mainBkg:'#21222c', nodeBorder:'#bd93f9', lineColor:'#6272a4', textColor:'#f8f8f2', clusterBkg:'#21222c', edgeLabelBg:'#21222c' },
      plot:{ bg:'#21222c', text:'#f8f8f2', grid:'#44475a', tick:'#6272a4', line:'#44475a' } },

    { id:'nord',           label:'Nord',            swatch:'#2e3440', swatchBorder:'#88c0d0',
      mermaid:{ mainBkg:'#3b4252', nodeBorder:'#88c0d0', lineColor:'#9099aa', textColor:'#eceff4', clusterBkg:'#3b4252', edgeLabelBg:'#3b4252' },
      plot:{ bg:'#3b4252', text:'#eceff4', grid:'#434c5e', tick:'#9099aa', line:'#4c566a' } },

    { id:'gruvbox',        label:'Gruvbox',         swatch:'#282828', swatchBorder:'#fabd2f',
      mermaid:{ mainBkg:'#282828', nodeBorder:'#fabd2f', lineColor:'#928374', textColor:'#ebdbb2', clusterBkg:'#3c3836', edgeLabelBg:'#282828' },
      plot:{ bg:'#282828', text:'#ebdbb2', grid:'#3c3836', tick:'#928374', line:'#504945' } },

    { id:'solarized-light',label:'Solarized Light', swatch:'#fdf6e3', swatchBorder:'#268bd2',
      mermaid:{ mainBkg:'#eee8d5', nodeBorder:'#268bd2', lineColor:'#839496', textColor:'#657b83', clusterBkg:'#e8e2d0', edgeLabelBg:'#fdf6e3' },
      plot:{ bg:'#eee8d5', text:'#657b83', grid:'#d3cbb8', tick:'#839496', line:'#b9b2a0' } },

    { id:'solarized-dark', label:'Solarized Dark',  swatch:'#002b36', swatchBorder:'#268bd2',
      mermaid:{ mainBkg:'#073642', nodeBorder:'#268bd2', lineColor:'#657b83', textColor:'#839496', clusterBkg:'#073642', edgeLabelBg:'#073642' },
      plot:{ bg:'#073642', text:'#839496', grid:'#073642', tick:'#657b83', line:'#0a4050' } },

    { id:'tokyo-night',    label:'Tokyo Night',     swatch:'#1a1b26', swatchBorder:'#7aa2f7',
      mermaid:{ mainBkg:'#24283b', nodeBorder:'#7aa2f7', lineColor:'#565f89', textColor:'#c0caf5', clusterBkg:'#1f2335', edgeLabelBg:'#24283b' },
      plot:{ bg:'#24283b', text:'#c0caf5', grid:'#292e42', tick:'#565f89', line:'#3b4261' } },

    { id:'monokai',        label:'Monokai',         swatch:'#272822', swatchBorder:'#a6e22e',
      mermaid:{ mainBkg:'#1e1f1a', nodeBorder:'#a6e22e', lineColor:'#75715e', textColor:'#f8f8f2', clusterBkg:'#1e1f1a', edgeLabelBg:'#1e1f1a' },
      plot:{ bg:'#1e1f1a', text:'#f8f8f2', grid:'#3e3d32', tick:'#75715e', line:'#49483e' } },

    { id:'github-light',   label:'GitHub Light',    swatch:'#ffffff', swatchBorder:'#0969da',
      mermaid:{ mainBkg:'#f6f8fa', nodeBorder:'#0969da', lineColor:'#656d76', textColor:'#1f2328', clusterBkg:'#eaeef2', edgeLabelBg:'#ffffff' },
      plot:{ bg:'#f6f8fa', text:'#1f2328', grid:'#d0d7de', tick:'#656d76', line:'#8c959f' } },

    { id:'github-dark',    label:'GitHub Dark',     swatch:'#0d1117', swatchBorder:'#58a6ff',
      mermaid:{ mainBkg:'#161b22', nodeBorder:'#58a6ff', lineColor:'#8b949e', textColor:'#e6edf3', clusterBkg:'#161b22', edgeLabelBg:'#161b22' },
      plot:{ bg:'#161b22', text:'#e6edf3', grid:'#30363d', tick:'#8b949e', line:'#30363d' } },

    { id:'forest',         label:'Forest',          swatch:'#0f1c0f', swatchBorder:'#4caf50',
      mermaid:{ mainBkg:'#162416', nodeBorder:'#4caf50', lineColor:'#7ea87e', textColor:'#dcedc8', clusterBkg:'#132113', edgeLabelBg:'#162416' },
      plot:{ bg:'#162416', text:'#dcedc8', grid:'#1c2e1c', tick:'#7ea87e', line:'#243c24' } },

    { id:'rose',           label:'Rose',            swatch:'#1a0a0e', swatchBorder:'#f43f5e',
      mermaid:{ mainBkg:'#220d12', nodeBorder:'#f43f5e', lineColor:'#be7b86', textColor:'#ffe4e6', clusterBkg:'#1a0a0e', edgeLabelBg:'#220d12' },
      plot:{ bg:'#220d12', text:'#ffe4e6', grid:'#2e1018', tick:'#be7b86', line:'#3a1420' } },

    { id:'sunset',         label:'Sunset',          swatch:'#18100a', swatchBorder:'#f97316',
      mermaid:{ mainBkg:'#201408', nodeBorder:'#f97316', lineColor:'#c07040', textColor:'#fff7ed', clusterBkg:'#180e05', edgeLabelBg:'#201408' },
      plot:{ bg:'#201408', text:'#fff7ed', grid:'#2a1c0e', tick:'#c07040', line:'#3a2810' } },

    { id:'ocean',          label:'Ocean',           swatch:'#061820', swatchBorder:'#06b6d4',
      mermaid:{ mainBkg:'#0a2233', nodeBorder:'#06b6d4', lineColor:'#4e9aaa', textColor:'#cffafe', clusterBkg:'#061820', edgeLabelBg:'#0a2233' },
      plot:{ bg:'#0a2233', text:'#cffafe', grid:'#0e2d42', tick:'#4e9aaa', line:'#163a50' } },

    { id:'aurora',         label:'Aurora',          swatch:'#0c0a1a', swatchBorder:'#a78bfa',
      mermaid:{ mainBkg:'#13102a', nodeBorder:'#a78bfa', lineColor:'#7c6aa6', textColor:'#ede9fe', clusterBkg:'#0c0a1a', edgeLabelBg:'#13102a' },
      plot:{ bg:'#13102a', text:'#ede9fe', grid:'#1a1636', tick:'#7c6aa6', line:'#24205a' } },

    { id:'slate',          label:'Slate',           swatch:'#0f172a', swatchBorder:'#94a3b8',
      mermaid:{ mainBkg:'#1e293b', nodeBorder:'#94a3b8', lineColor:'#64748b', textColor:'#e2e8f0', clusterBkg:'#0f172a', edgeLabelBg:'#1e293b' },
      plot:{ bg:'#1e293b', text:'#e2e8f0', grid:'#263244', tick:'#64748b', line:'#334155' } },

    { id:'copper',         label:'Copper',          swatch:'#1a1208', swatchBorder:'#b87333',
      mermaid:{ mainBkg:'#221608', nodeBorder:'#b87333', lineColor:'#a07840', textColor:'#fef3e2', clusterBkg:'#180f05', edgeLabelBg:'#221608' },
      plot:{ bg:'#221608', text:'#fef3e2', grid:'#2e1e0c', tick:'#a07840', line:'#3c2a10' } },

    { id:'sakura',         label:'Sakura',          swatch:'#fdf2f8', swatchBorder:'#e879a0',
      mermaid:{ mainBkg:'#fce7f3', nodeBorder:'#e879a0', lineColor:'#a0608a', textColor:'#4a1535', clusterBkg:'#fde8f4', edgeLabelBg:'#fdf2f8' },
      plot:{ bg:'#fce7f3', text:'#4a1535', grid:'#f0b8d0', tick:'#a0608a', line:'#e879a0' } },

    { id:'terminal',       label:'Terminal',        swatch:'#000000', swatchBorder:'#00ff41',
      mermaid:{ mainBkg:'#0a0a0a', nodeBorder:'#00ff41', lineColor:'#007a1e', textColor:'#00ff41', clusterBkg:'#050505', edgeLabelBg:'#000000' },
      plot:{ bg:'#0a0a0a', text:'#00ff41', grid:'#1a1a1a', tick:'#007a1e', line:'#003010' } },

    { id:'coffee',         label:'Coffee',          swatch:'#1a1410', swatchBorder:'#c8924a',
      mermaid:{ mainBkg:'#241e18', nodeBorder:'#c8924a', lineColor:'#987850', textColor:'#f5e6d0', clusterBkg:'#1a1410', edgeLabelBg:'#241e18' },
      plot:{ bg:'#241e18', text:'#f5e6d0', grid:'#2e2620', tick:'#987850', line:'#3a3020' } },

    { id:'arctic',         label:'Arctic',          swatch:'#f0f6fc', swatchBorder:'#5e9fd8',
      mermaid:{ mainBkg:'#e4eef8', nodeBorder:'#5e9fd8', lineColor:'#4a7098', textColor:'#0d2340', clusterBkg:'#e4eef8', edgeLabelBg:'#f0f6fc' },
      plot:{ bg:'#e4eef8', text:'#0d2340', grid:'#c4d8ee', tick:'#4a7098', line:'#94bade' } },

    { id:'hc-light',       label:'HC Light',        swatch:'#ffffff', swatchBorder:'#000000',
      mermaid:{ mainBkg:'#ffffff', nodeBorder:'#000000', lineColor:'#000000', textColor:'#000000', clusterBkg:'#f0f0f0', edgeLabelBg:'#ffffff' },
      plot:{ bg:'#ffffff', text:'#000000', grid:'#767676', tick:'#000000', line:'#000000' } },

    { id:'hc-dark',        label:'HC Dark',         swatch:'#000000', swatchBorder:'#ffffff',
      mermaid:{ mainBkg:'#0d0d0d', nodeBorder:'#ffff00', lineColor:'#ffffff', textColor:'#ffffff', clusterBkg:'#0d0d0d', edgeLabelBg:'#0d0d0d' },
      plot:{ bg:'#0d0d0d', text:'#ffffff', grid:'#767676', tick:'#ffffff', line:'#767676' } },

    { id:'cyberpunk',      label:'Cyberpunk',       swatch:'#0d0015', swatchBorder:'#f0e040',
      mermaid:{ mainBkg:'#160025', nodeBorder:'#f0e040', lineColor:'#ff2d78', textColor:'#f0e8ff', clusterBkg:'#0d0015', edgeLabelBg:'#160025' },
      plot:{ bg:'#160025', text:'#f0e8ff', grid:'#1e0038', tick:'#8060a0', line:'#2a0044' } },

    { id:'neon',           label:'Neon',            swatch:'#060010', swatchBorder:'#ff00ff',
      mermaid:{ mainBkg:'#0c0020', nodeBorder:'#ff00ff', lineColor:'#00ffff', textColor:'#f0e8ff', clusterBkg:'#060010', edgeLabelBg:'#0c0020' },
      plot:{ bg:'#0c0020', text:'#f0e8ff', grid:'#14002e', tick:'#7040a0', line:'#1e0040' } },

    { id:'synthwave',      label:'Synthwave',       swatch:'#1a0533', swatchBorder:'#f92aad',
      mermaid:{ mainBkg:'#2a0845', nodeBorder:'#f92aad', lineColor:'#36f9f6', textColor:'#f4e4ff', clusterBkg:'#1a0533', edgeLabelBg:'#2a0845' },
      plot:{ bg:'#2a0845', text:'#f4e4ff', grid:'#360a58', tick:'#9060c0', line:'#44106a' } },

    { id:'retro',          label:'Retro',           swatch:'#1a1200', swatchBorder:'#e8a000',
      mermaid:{ mainBkg:'#2a1e00', nodeBorder:'#e8a000', lineColor:'#e84000', textColor:'#fff8e0', clusterBkg:'#1a1200', edgeLabelBg:'#2a1e00' },
      plot:{ bg:'#2a1e00', text:'#fff8e0', grid:'#362800', tick:'#a08020', line:'#3e2e00' } },

    { id:'amber',          label:'Amber',           swatch:'#fef3c7', swatchBorder:'#f59e0b',
      mermaid:{ mainBkg:'#fef3c7', nodeBorder:'#f59e0b', lineColor:'#d97706', textColor:'#451a03', clusterBkg:'#fde68a', edgeLabelBg:'#fefce8' },
      plot:{ bg:'#fef3c7', text:'#451a03', grid:'#fde68a', tick:'#b45309', line:'#fcd34d' } },

    { id:'mint',           label:'Mint',            swatch:'#d1fae5', swatchBorder:'#10b981',
      mermaid:{ mainBkg:'#d1fae5', nodeBorder:'#10b981', lineColor:'#059669', textColor:'#064e3b', clusterBkg:'#a7f3d0', edgeLabelBg:'#f0fdf9' },
      plot:{ bg:'#d1fae5', text:'#064e3b', grid:'#a7f3d0', tick:'#059669', line:'#6ee7b7' } },

    { id:'lavender',       label:'Lavender',        swatch:'#ede9fe', swatchBorder:'#8b5cf6',
      mermaid:{ mainBkg:'#ede9fe', nodeBorder:'#8b5cf6', lineColor:'#7c3aed', textColor:'#2e1065', clusterBkg:'#ddd6fe', edgeLabelBg:'#faf5ff' },
      plot:{ bg:'#ede9fe', text:'#2e1065', grid:'#ddd6fe', tick:'#7c3aed', line:'#c4b5fd' } },

    { id:'peach',          label:'Peach',           swatch:'#ffedd5', swatchBorder:'#f97316',
      mermaid:{ mainBkg:'#ffedd5', nodeBorder:'#f97316', lineColor:'#ea580c', textColor:'#431407', clusterBkg:'#fed7aa', edgeLabelBg:'#fff7ed' },
      plot:{ bg:'#ffedd5', text:'#431407', grid:'#fed7aa', tick:'#c2410c', line:'#fdba74' } },

    { id:'sky',            label:'Sky',             swatch:'#e0f2fe', swatchBorder:'#0284c7',
      mermaid:{ mainBkg:'#e0f2fe', nodeBorder:'#0284c7', lineColor:'#0369a1', textColor:'#082f49', clusterBkg:'#bae6fd', edgeLabelBg:'#f0f9ff' },
      plot:{ bg:'#e0f2fe', text:'#082f49', grid:'#bae6fd', tick:'#0369a1', line:'#7dd3fc' } },

    { id:'lemon',          label:'Lemon',           swatch:'#fef9c3', swatchBorder:'#ca8a04',
      mermaid:{ mainBkg:'#fef9c3', nodeBorder:'#ca8a04', lineColor:'#a16207', textColor:'#422006', clusterBkg:'#fef08a', edgeLabelBg:'#fefce8' },
      plot:{ bg:'#fef9c3', text:'#422006', grid:'#fef08a', tick:'#a16207', line:'#fde047' } },

    { id:'moonlight',      label:'Moonlight',       swatch:'#1f2335', swatchBorder:'#7e9cd8',
      mermaid:{ mainBkg:'#24283b', nodeBorder:'#7e9cd8', lineColor:'#957fb8', textColor:'#dcd7ba', clusterBkg:'#1f2335', edgeLabelBg:'#24283b' },
      plot:{ bg:'#24283b', text:'#dcd7ba', grid:'#2a2f45', tick:'#727169', line:'#363646' } },

    { id:'kanagawa',       label:'Kanagawa',        swatch:'#1f1f28', swatchBorder:'#7e9cd8',
      mermaid:{ mainBkg:'#2a2a37', nodeBorder:'#7e9cd8', lineColor:'#957fb8', textColor:'#dcd7ba', clusterBkg:'#1f1f28', edgeLabelBg:'#2a2a37' },
      plot:{ bg:'#2a2a37', text:'#dcd7ba', grid:'#363646', tick:'#727169', line:'#363646' } },

    { id:'everforest',     label:'Everforest',      swatch:'#2d353b', swatchBorder:'#a7c080',
      mermaid:{ mainBkg:'#343f44', nodeBorder:'#a7c080', lineColor:'#83c092', textColor:'#d3c6aa', clusterBkg:'#2d353b', edgeLabelBg:'#343f44' },
      plot:{ bg:'#343f44', text:'#d3c6aa', grid:'#3d484d', tick:'#9da9a0', line:'#475258' } },

    { id:'rose-pine',      label:'Rosé Pine',       swatch:'#191724', swatchBorder:'#ebbcba',
      mermaid:{ mainBkg:'#1f1d2e', nodeBorder:'#ebbcba', lineColor:'#c4a7e7', textColor:'#e0def4', clusterBkg:'#191724', edgeLabelBg:'#1f1d2e' },
      plot:{ bg:'#1f1d2e', text:'#e0def4', grid:'#26233a', tick:'#6e6a86', line:'#403d52' } },

    { id:'ayu-dark',       label:'Ayu Dark',        swatch:'#0d1017', swatchBorder:'#ffb454',
      mermaid:{ mainBkg:'#131721', nodeBorder:'#ffb454', lineColor:'#73d0ff', textColor:'#bfbdb6', clusterBkg:'#0d1017', edgeLabelBg:'#131721' },
      plot:{ bg:'#131721', text:'#bfbdb6', grid:'#1a2130', tick:'#626672', line:'#1e2535' } },

    { id:'ayu-light',      label:'Ayu Light',       swatch:'#fafafa', swatchBorder:'#f2ae49',
      mermaid:{ mainBkg:'#f3f4f5', nodeBorder:'#f2ae49', lineColor:'#399ee6', textColor:'#575f66', clusterBkg:'#e8e8e8', edgeLabelBg:'#fafafa' },
      plot:{ bg:'#f3f4f5', text:'#575f66', grid:'#e8e8e8', tick:'#8a9199', line:'#d0d0d0' } },

    { id:'one-dark',       label:'One Dark',        swatch:'#282c34', swatchBorder:'#61afef',
      mermaid:{ mainBkg:'#21252b', nodeBorder:'#61afef', lineColor:'#c678dd', textColor:'#abb2bf', clusterBkg:'#282c34', edgeLabelBg:'#21252b' },
      plot:{ bg:'#21252b', text:'#abb2bf', grid:'#2c313a', tick:'#5c6370', line:'#3e4451' } },

    { id:'one-light',      label:'One Light',       swatch:'#fafafa', swatchBorder:'#4078f2',
      mermaid:{ mainBkg:'#f2f2f2', nodeBorder:'#4078f2', lineColor:'#a626a4', textColor:'#383a42', clusterBkg:'#e5e5e6', edgeLabelBg:'#fafafa' },
      plot:{ bg:'#f2f2f2', text:'#383a42', grid:'#e5e5e6', tick:'#696c77', line:'#c8c8c8' } },

    { id:'material-dark',  label:'Material Dark',   swatch:'#212121', swatchBorder:'#82aaff',
      mermaid:{ mainBkg:'#2d2d2d', nodeBorder:'#82aaff', lineColor:'#c3e88d', textColor:'#eeffff', clusterBkg:'#212121', edgeLabelBg:'#2d2d2d' },
      plot:{ bg:'#2d2d2d', text:'#eeffff', grid:'#383838', tick:'#546e7a', line:'#3d3d3d' } },

    { id:'material-light', label:'Material Light',  swatch:'#fafafa', swatchBorder:'#6200ee',
      mermaid:{ mainBkg:'#ffffff', nodeBorder:'#6200ee', lineColor:'#03dac6', textColor:'#212121', clusterBkg:'#f5f5f5', edgeLabelBg:'#fafafa' },
      plot:{ bg:'#ffffff', text:'#212121', grid:'#e0e0e0', tick:'#757575', line:'#9e9e9e' } },

    { id:'palenight',      label:'Palenight',       swatch:'#292d3e', swatchBorder:'#82aaff',
      mermaid:{ mainBkg:'#1b1e2b', nodeBorder:'#82aaff', lineColor:'#c792ea', textColor:'#a6accd', clusterBkg:'#292d3e', edgeLabelBg:'#1b1e2b' },
      plot:{ bg:'#1b1e2b', text:'#a6accd', grid:'#232635', tick:'#676e95', line:'#303348' } },

    { id:'panda',          label:'Panda',           swatch:'#1a1b26', swatchBorder:'#ff75b5',
      mermaid:{ mainBkg:'#1e2030', nodeBorder:'#ff75b5', lineColor:'#19f9d8', textColor:'#e6e6e6', clusterBkg:'#1a1b26', edgeLabelBg:'#1e2030' },
      plot:{ bg:'#1e2030', text:'#e6e6e6', grid:'#252840', tick:'#6c6f93', line:'#2e3150' } },

    { id:'horizon',        label:'Horizon',         swatch:'#1c1e26', swatchBorder:'#e95678',
      mermaid:{ mainBkg:'#232530', nodeBorder:'#e95678', lineColor:'#fab795', textColor:'#d5d8da', clusterBkg:'#1c1e26', edgeLabelBg:'#232530' },
      plot:{ bg:'#232530', text:'#d5d8da', grid:'#2e303e', tick:'#6c6f8f', line:'#4a4c5e' } },

    { id:'pitch-black',    label:'Pitch Black',     swatch:'#000000', swatchBorder:'#333333',
      mermaid:{ mainBkg:'#060606', nodeBorder:'#444444', lineColor:'#666666', textColor:'#cccccc', clusterBkg:'#000000', edgeLabelBg:'#060606' },
      plot:{ bg:'#060606', text:'#cccccc', grid:'#111111', tick:'#555555', line:'#1a1a1a' } },

    { id:'paper',          label:'Paper',           swatch:'#f7f4ef', swatchBorder:'#555555',
      mermaid:{ mainBkg:'#fffef8', nodeBorder:'#555555', lineColor:'#888888', textColor:'#1a1a1a', clusterBkg:'#f7f4ef', edgeLabelBg:'#fffef8' },
      plot:{ bg:'#fffef8', text:'#1a1a1a', grid:'#ede9e1', tick:'#777777', line:'#ddd8d0' } },

    { id:'newspaper',      label:'Newspaper',       swatch:'#f5f0e8', swatchBorder:'#1a1a1a',
      mermaid:{ mainBkg:'#faf7f2', nodeBorder:'#1a1a1a', lineColor:'#cc0000', textColor:'#111111', clusterBkg:'#f5f0e8', edgeLabelBg:'#faf7f2' },
      plot:{ bg:'#faf7f2', text:'#111111', grid:'#ece7df', tick:'#666666', line:'#d0c8bc' } },

    { id:'ink',            label:'Ink',             swatch:'#111418', swatchBorder:'#4488cc',
      mermaid:{ mainBkg:'#181c20', nodeBorder:'#4488cc', lineColor:'#88ccaa', textColor:'#e0e4e8', clusterBkg:'#111418', edgeLabelBg:'#181c20' },
      plot:{ bg:'#181c20', text:'#e0e4e8', grid:'#1e2228', tick:'#6080a0', line:'#1e2838' } },

    { id:'dusk',           label:'Dusk',            swatch:'#1e1028', swatchBorder:'#c084fc',
      mermaid:{ mainBkg:'#261638', nodeBorder:'#c084fc', lineColor:'#fb7185', textColor:'#f0e8ff', clusterBkg:'#1e1028', edgeLabelBg:'#261638' },
      plot:{ bg:'#261638', text:'#f0e8ff', grid:'#301e48', tick:'#8868a8', line:'#3c2460' } },

    { id:'pastel',         label:'Pastel',          swatch:'#fdf8ff', swatchBorder:'#a78bfa',
      mermaid:{ mainBkg:'#fef3fb', nodeBorder:'#a78bfa', lineColor:'#f9a8d4', textColor:'#3d2c5e', clusterBkg:'#fdf8ff', edgeLabelBg:'#fef3fb' },
      plot:{ bg:'#fef3fb', text:'#3d2c5e', grid:'#e8d8f8', tick:'#9880b8', line:'#d4b8f0' } },

    { id:'teal',           label:'Teal',            swatch:'#ccfbf1', swatchBorder:'#0d9488',
      mermaid:{ mainBkg:'#ccfbf1', nodeBorder:'#0d9488', lineColor:'#0891b2', textColor:'#042f2e', clusterBkg:'#99f6e4', edgeLabelBg:'#f0fdfa' },
      plot:{ bg:'#ccfbf1', text:'#042f2e', grid:'#99f6e4', tick:'#0f766e', line:'#5eead4' } },

    { id:'woodland',       label:'Woodland',        swatch:'#ece4d4', swatchBorder:'#7a8c5a',
      mermaid:{ mainBkg:'#ece4d4', nodeBorder:'#7a8c5a', lineColor:'#c8a96e', textColor:'#2a2018', clusterBkg:'#f5f0e8', edgeLabelBg:'#f5f0e8' },
      plot:{ bg:'#ece4d4', text:'#2a2018', grid:'#d8cdb8', tick:'#6e6040', line:'#bcb098' } },

    { id:'desert',         label:'Desert',          swatch:'#ecdbc6', swatchBorder:'#d4955a',
      mermaid:{ mainBkg:'#ecdbc6', nodeBorder:'#d4955a', lineColor:'#c8a050', textColor:'#2e1a08', clusterBkg:'#f5ede0', edgeLabelBg:'#f5ede0' },
      plot:{ bg:'#ecdbc6', text:'#2e1a08', grid:'#dcc8a8', tick:'#8a6030', line:'#c4a880' } },

    { id:'volcano',        label:'Volcano',         swatch:'#1a0800', swatchBorder:'#ff4422',
      mermaid:{ mainBkg:'#220a00', nodeBorder:'#ff4422', lineColor:'#ffaa00', textColor:'#fff4e8', clusterBkg:'#1a0800', edgeLabelBg:'#220a00' },
      plot:{ bg:'#220a00', text:'#fff4e8', grid:'#2e1000', tick:'#c06030', line:'#3a1800' } },

    { id:'deep-sea',       label:'Deep Sea',        swatch:'#020e18', swatchBorder:'#00bcd4',
      mermaid:{ mainBkg:'#051824', nodeBorder:'#00bcd4', lineColor:'#00e676', textColor:'#b2ebf2', clusterBkg:'#020e18', edgeLabelBg:'#051824' },
      plot:{ bg:'#051824', text:'#b2ebf2', grid:'#092030', tick:'#006064', line:'#0a2a3a' } },

    { id:'grape',          label:'Grape',           swatch:'#16001e', swatchBorder:'#9c27b0',
      mermaid:{ mainBkg:'#1e0030', nodeBorder:'#9c27b0', lineColor:'#e040fb', textColor:'#f3e5f5', clusterBkg:'#16001e', edgeLabelBg:'#1e0030' },
      plot:{ bg:'#1e0030', text:'#f3e5f5', grid:'#280040', tick:'#7b1fa2', line:'#380058' } },

    { id:'ash',            label:'Ash',             swatch:'#263238', swatchBorder:'#78909c',
      mermaid:{ mainBkg:'#2e3c43', nodeBorder:'#78909c', lineColor:'#4db6ac', textColor:'#eceff1', clusterBkg:'#263238', edgeLabelBg:'#2e3c43' },
      plot:{ bg:'#2e3c43', text:'#eceff1', grid:'#37474f', tick:'#78909c', line:'#455a64' } },

    { id:'crimson',        label:'Crimson',         swatch:'#12000a', swatchBorder:'#dc143c',
      mermaid:{ mainBkg:'#1e000e', nodeBorder:'#dc143c', lineColor:'#ff6b6b', textColor:'#fff0f3', clusterBkg:'#12000a', edgeLabelBg:'#1e000e' },
      plot:{ bg:'#1e000e', text:'#fff0f3', grid:'#280014', tick:'#aa3050', line:'#3a0020' } },

    { id:'ice',            label:'Ice',             swatch:'#e0f0ff', swatchBorder:'#7dd3fc',
      mermaid:{ mainBkg:'#e0f0ff', nodeBorder:'#7dd3fc', lineColor:'#a5f3fc', textColor:'#0a2540', clusterBkg:'#b8d8f0', edgeLabelBg:'#f0f8ff' },
      plot:{ bg:'#e0f0ff', text:'#0a2540', grid:'#b8d8f0', tick:'#3a7aaa', line:'#80b8e0' } },

    { id:'coral',          label:'Coral',           swatch:'#ffe4e4', swatchBorder:'#ff6b6b',
      mermaid:{ mainBkg:'#ffe4e4', nodeBorder:'#ff6b6b', lineColor:'#ffd166', textColor:'#4a0808', clusterBkg:'#ffc0c0', edgeLabelBg:'#fff5f5' },
      plot:{ bg:'#ffe4e4', text:'#4a0808', grid:'#ffc0c0', tick:'#c05050', line:'#ff9090' } },
];

/**
 * Populates #theme-list with buttons generated from THEMES, marks the active
 * entry, and attaches hover-preview listeners. Hovering previews the theme
 * visually (CSS only, no Mermaid/Plotly re-render); clicking commits it.
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
 * Filters the theme list to entries whose label contains the query string
 * (case-insensitive). Shows a no-results message when nothing matches.
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

/**
 * Mermaid initialize config per UI theme. Uses themeVariables so colours
 * match the active palette exactly rather than relying on Mermaid's own
 * built-in dark/default tokens which ignore our CSS variables.
 * @param {string} theme - UI theme name
 * @returns {object} Mermaid initialize options object
 */
function mermaidConfigFor(theme) {
    const t = THEMES.find(x => x.id === theme) || THEMES[0];
    const m = t.mermaid;
    return {
        theme: 'base',
        themeVariables: {
            primaryColor: m.mainBkg, primaryTextColor: m.textColor,
            primaryBorderColor: m.nodeBorder, lineColor: m.lineColor,
            secondaryColor: m.clusterBkg, tertiaryColor: m.clusterBkg,
            background: m.mainBkg, mainBkg: m.mainBkg,
            nodeBorder: m.nodeBorder, clusterBkg: m.clusterBkg,
            titleColor: m.textColor, edgeLabelBackground: m.edgeLabelBg,
            fontFamily: 'inherit', fontSize: '13px',
        },
    };
}

/**
 * Returns Plotly layout colours tuned for readability in the given theme.
 * Solid opaque colours are required — Plotly ignores rgba for some properties.
 * @param {string} theme - UI theme name
 * @returns {{ bg: string, text: string, grid: string, tick: string, line: string }}
 */
function plotColorsFor(theme) {
    const t = THEMES.find(x => x.id === theme) || THEMES[0];
    return t.plot;
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
    // Close the dropdown after selection
    document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
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
        if (id === 'theme-dd') {
            const inp = document.getElementById('theme-search');
            if (inp) { inp.value = ''; filterThemes(''); inp.focus(); }
        }
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

// ============================================================
// Live Background System
// ============================================================

/**
 * Registry of available animated backgrounds.
 * Each entry: { id, label, preview (hex color for swatch), render(canvas, stop) }
 *   render(canvas, stopRef) — starts the animation loop.
 *     stopRef is a plain object; set stopRef.active=false to terminate the loop.
 *   preview — solid hex colour used to generate the tiny swatch thumbnail.
 */
/**
 * Reads --primary-color and --accent-color from the root element as [r,g,b] arrays.
 * Falls back to reasonable defaults if the value is not a plain hex string.
 * @returns {{ p:[number,number,number], a:[number,number,number] }}
 */
function _themeRGB() {
    const cs = getComputedStyle(document.documentElement);
    function parse(v, def) {
        v = v.trim();
        if (v.startsWith('#') && (v.length === 7 || v.length === 4)) {
            if (v.length === 4) v = '#' + v[1]+v[1]+v[2]+v[2]+v[3]+v[3];
            return [parseInt(v.slice(1,3),16), parseInt(v.slice(3,5),16), parseInt(v.slice(5,7),16)];
        }
        return def;
    }
    return {
        p: parse(cs.getPropertyValue('--primary-color'), [96,165,250]),
        a: parse(cs.getPropertyValue('--accent-color'),  [167,139,250]),
    };
}

/**
 * Compiles and links a WebGL program from vertex + fragment source.
 * Returns null if WebGL is unavailable.
 * @param {HTMLCanvasElement} canvas
 * @param {string} vert
 * @param {string} frag
 * @returns {{ gl: WebGLRenderingContext, prog: WebGLProgram }|null}
 */
function _glProgram(canvas, vert, frag) {
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    function compile(type, src) {
        const s = gl.createShader(type);
        gl.shaderSource(s, src); gl.compileShader(s);
        if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) { gl.deleteShader(s); return null; }
        return s;
    }
    const vs = compile(gl.VERTEX_SHADER, vert);
    const fs = compile(gl.FRAGMENT_SHADER, frag);
    if (!vs || !fs) return null;
    const prog = gl.createProgram();
    gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return null;
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
    gl.useProgram(prog);
    const pos = gl.getAttribLocation(prog, 'a_pos');
    gl.enableVertexAttribArray(pos);
    gl.vertexAttribPointer(pos, 2, gl.FLOAT, false, 0, 0);
    return { gl, prog };
}

const VERT_PASSTHROUGH = `attribute vec2 a_pos; void main(){ gl_Position=vec4(a_pos,0,1); }`;

const BACKGROUNDS = [
    { id: 'none', label: 'None', preview: null, render: null },

    {
        id: 'particles',
        label: 'Particles',
        preview: '#1a2a4a',
        /**
         * Floating dot particles with theme-coloured connections.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx = canvas.getContext('2d');
            const N = 100;
            let W, H, pts;
            function resize() { W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            function mkPt() {
                return { x:Math.random()*W, y:Math.random()*H,
                         vx:(Math.random()-0.5)*0.08, vy:(Math.random()-0.5)*0.08, r:Math.random()*2.5+1.5 };
            }
            resize(); pts=Array.from({length:N},mkPt);
            window.addEventListener('resize', resize);
            function frame() {
                if (!stop.active) { window.removeEventListener('resize',resize); return; }
                ctx.clearRect(0,0,W,H);
                const {p:[r,g,b]} = _themeRGB();
                for (let i=0; i<N; i++) {
                    const pt=pts[i];
                    pt.x+=pt.vx; pt.y+=pt.vy;
                    if (pt.x<0) pt.x=W; if (pt.x>W) pt.x=0;
                    if (pt.y<0) pt.y=H; if (pt.y>H) pt.y=0;
                    ctx.beginPath(); ctx.arc(pt.x,pt.y,pt.r,0,Math.PI*2);
                    ctx.fillStyle=`rgba(${r},${g},${b},0.85)`; ctx.fill();
                    for (let j=i+1; j<N; j++) {
                        const q=pts[j], dx=pt.x-q.x, dy=pt.y-q.y, d=Math.sqrt(dx*dx+dy*dy);
                        if (d<140) {
                            ctx.beginPath(); ctx.moveTo(pt.x,pt.y); ctx.lineTo(q.x,q.y);
                            ctx.strokeStyle=`rgba(${r},${g},${b},${((1-d/140)*0.35).toFixed(2)})`;
                            ctx.lineWidth=0.8; ctx.stroke();
                        }
                    }
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'waves',
        label: 'Waves',
        preview: '#0a1628',
        /**
         * Multiple sinusoidal wave layers using both theme colours, clearly visible.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx = canvas.getContext('2d');
            let W, H, t=0;
            function resize() { W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            resize(); window.addEventListener('resize', resize);
            const layers = [
                { amp:0.04, freq:0.010, speed:0.003, y:0.50, useAccent:false, alpha:0.40 },
                { amp:0.03, freq:0.016, speed:0.004, y:0.62, useAccent:true,  alpha:0.32 },
                { amp:0.035,freq:0.008, speed:0.002, y:0.72, useAccent:false, alpha:0.36 },
                { amp:0.025,freq:0.020, speed:0.005, y:0.82, useAccent:true,  alpha:0.28 },
            ];
            function frame() {
                if (!stop.active) { window.removeEventListener('resize',resize); return; }
                ctx.clearRect(0,0,W,H); t+=1;
                const {p:[r1,g1,b1], a:[r2,g2,b2]} = _themeRGB();
                for (const l of layers) {
                    const [r,g,b] = l.useAccent ? [r2,g2,b2] : [r1,g1,b1];
                    ctx.beginPath(); ctx.moveTo(0,H);
                    for (let x=0; x<=W; x+=3) {
                        const y = l.y*H + Math.sin(x*l.freq + t*l.speed)*l.amp*H
                                        + Math.sin(x*l.freq*1.6 + t*l.speed*0.7)*l.amp*H*0.4;
                        ctx.lineTo(x,y);
                    }
                    ctx.lineTo(W,H); ctx.closePath();
                    ctx.fillStyle=`rgba(${r},${g},${b},${l.alpha})`; ctx.fill();
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'matrix',
        label: 'Matrix Rain',
        preview: '#001400',
        /**
         * Matrix rain with variable-speed columns, glowing head character,
         * fading trail, and occasional full-bright flash — all theme-coloured.
         * Each column has its own speed, length cap, and reset probability.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx = canvas.getContext('2d');
            const FS   = 16;
            const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>{}[]|/\\;:?!=+-';
            let W, H, ROWS, cols, streams;

            /* Each stream mirrors a cmatrix column:
               head  — current row the leading glyph occupies
               len   — trail length in rows
               ticks — frames-per-step (speed tier: 1 = fastest, 3 = slowest)
               timer — countdown to next step
               active — whether the stream is currently falling              */
            function mkStream() {
                return {
                    head:   -Math.floor(Math.random() * ROWS),
                    len:    Math.floor(8 + Math.random() * 20),
                    ticks:  4 + Math.floor(Math.random() * 4),
                    timer:  0,
                    active: true,
                };
            }

            function resize() {
                W    = canvas.width  = window.innerWidth;
                H    = canvas.height = window.innerHeight;
                ROWS = Math.ceil(H / FS) + 2;
                cols = Math.floor(W / FS);
                /* Fill canvas with background so existing pixels are correct */
                ctx.clearRect(0, 0, W, H);
                streams = Array.from({ length: cols }, mkStream);
            }
            resize();
            window.addEventListener('resize', resize);

            let frame_count = 0;
            function frame() {
                if (!stop.active) { window.removeEventListener('resize', resize); return; }
                frame_count++;
                const { p:[r,g,b] } = _themeRGB();
                ctx.font = `bold ${FS}px monospace`;

                for (let i = 0; i < cols; i++) {
                    const s = streams[i];
                    if (!s.active) continue;

                    /* Only advance this column on its own tick cadence */
                    s.timer++;
                    if (s.timer < s.ticks) continue;
                    s.timer = 0;

                    const x = i * FS;

                    /* Erase the tail cell — clear that exact cell to transparent */
                    const tailRow = s.head - s.len;
                    if (tailRow >= 0 && tailRow < ROWS) {
                        ctx.clearRect(x, tailRow * FS, FS, FS);
                    }

                    /* Advance head one row */
                    s.head++;

                    /* Draw the new head character — bright white */
                    if (s.head >= 0 && s.head < ROWS) {
                        ctx.fillStyle = `rgba(210,255,225,0.95)`;
                        ctx.fillText(
                            CHARS[Math.floor(Math.random() * CHARS.length)],
                            x, s.head * FS + FS
                        );
                    }

                    /* Re-colour the previous head cell to dim theme colour
                       (simulates cmatrix switching the old head to a trail glyph) */
                    const prevRow = s.head - 1;
                    if (prevRow >= 0 && prevRow < ROWS) {
                        ctx.clearRect(x, prevRow * FS, FS, FS);
                        ctx.fillStyle = `rgba(${r},${g},${b},0.92)`;
                        ctx.fillText(
                            CHARS[Math.floor(Math.random() * CHARS.length)],
                            x, prevRow * FS + FS
                        );
                    }

                    /* Dim mid-trail characters — walk the visible trail and
                       reduce alpha slightly each tick to create brightness gradient */
                    for (let j = 2; j < s.len; j++) {
                        const tr = s.head - j;
                        if (tr < 0 || tr >= ROWS) continue;
                        /* Fade: brightest near head, darkest at tail */
                        const fade = 1 - j / s.len;
                        ctx.globalCompositeOperation = 'destination-out';
                        ctx.fillStyle = 'rgba(0,0,0,0.06)';
                        ctx.fillRect(x, tr * FS, FS, FS);
                        ctx.globalCompositeOperation = 'source-over';
                        /* Occasionally mutate a trail glyph */
                        if (Math.random() < 0.04) {
                            ctx.fillStyle = `rgba(${Math.round(r*fade)},${Math.round(g*fade)},${Math.round(b*fade)},${(fade*0.85).toFixed(2)})`;
                            ctx.fillText(
                                CHARS[Math.floor(Math.random() * CHARS.length)],
                                x, tr * FS + FS
                            );
                        }
                    }

                    /* Stream finished — reset after random pause */
                    if (s.head - s.len > ROWS) {
                        s.head   = -Math.floor(Math.random() * ROWS * 0.5);
                        s.len    = Math.floor(8 + Math.random() * 20);
                        s.ticks  = 4 + Math.floor(Math.random() * 4);
                    }
                }

                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'aurora',
        label: 'Aurora',
        preview: '#030818',
        /**
         * WebGL shader aurora — smooth large-scale noise bands in theme colours.
         * Falls back to Canvas2D if WebGL unavailable.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const frag = `
precision mediump float;
uniform vec2  u_res; uniform float u_t;
uniform vec3  u_c1;  uniform vec3  u_c2;
float hash(vec2 p){ return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453); }
float noise(vec2 p){
    vec2 i=floor(p), f=fract(p), u=f*f*(3.0-2.0*f);
    return mix(mix(hash(i),hash(i+vec2(1,0)),u.x),mix(hash(i+vec2(0,1)),hash(i+vec2(1,1)),u.x),u.y);
}
float fbm(vec2 p){
    float v=0.0,a=0.5; for(int i=0;i<5;i++){v+=a*noise(p);p=p*2.1+vec2(1.3,1.7);a*=0.5;} return v;
}
void main(){
    vec2 uv = gl_FragCoord.xy / u_res;
    uv.y = 1.0 - uv.y;
    float t = u_t * 0.07;
    float n = fbm(uv * vec2(2.5,1.2) + vec2(t*0.4, t*0.2));
    float n2= fbm(uv * vec2(1.8,2.0) + vec2(-t*0.3, t*0.5) + 3.7);
    float band1 = smoothstep(0.0,1.0, 1.0 - abs(uv.y - 0.38 - n*0.28)*4.0);
    float band2 = smoothstep(0.0,1.0, 1.0 - abs(uv.y - 0.62 - n2*0.22)*5.0);
    vec3 col = u_c1*band1*0.9 + u_c2*band2*0.85;
    float alpha = clamp(band1*0.75 + band2*0.70, 0.0, 0.88);
    gl_FragColor = vec4(col, alpha);
}`;
            const gl2 = _glProgram(canvas, VERT_PASSTHROUGH, frag);
            if (!gl2) {
                // Canvas2D fallback
                const ctx2=canvas.getContext('2d'); let W,H,t=0;
                function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
                resize(); window.addEventListener('resize',resize);
                function frame(){
                    if(!stop.active){window.removeEventListener('resize',resize);return;}
                    ctx2.clearRect(0,0,W,H); t+=0.012;
                    const {p:[r1,g1,b1],a:[r2,g2,b2]}=_themeRGB();
                    [[r1,g1,b1,0.35,0.7],[r2,g2,b2,0.45,0.8],[r1,g1,b1,0.28,0.5],[r2,g2,b2,0.38,0.6]].forEach(([r,g,b,ph,sp],i)=>{
                        const yc=(0.3+i*0.12+Math.sin(t*sp+ph)*0.15)*H, h=H*0.25;
                        const gd=ctx2.createLinearGradient(0,yc-h,0,yc+h);
                        gd.addColorStop(0,`rgba(${r},${g},${b},0)`);
                        gd.addColorStop(0.5,`rgba(${r},${g},${b},0.6)`);
                        gd.addColorStop(1,`rgba(${r},${g},${b},0)`);
                        ctx2.fillStyle=gd; ctx2.fillRect(0,yc-h,W,h*2);
                    });
                    requestAnimationFrame(frame);
                }
                return requestAnimationFrame(frame);
            }
            const {gl, prog} = gl2;
            const uRes=gl.getUniformLocation(prog,'u_res');
            const uT  =gl.getUniformLocation(prog,'u_t');
            const uC1 =gl.getUniformLocation(prog,'u_c1');
            const uC2 =gl.getUniformLocation(prog,'u_c2');
            let t=0;
            function resize(){ canvas.width=window.innerWidth; canvas.height=window.innerHeight; gl.viewport(0,0,canvas.width,canvas.height); }
            resize(); window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                t+=1;
                gl.useProgram(prog);
                const {p:[r1,g1,b1],a:[r2,g2,b2]}=_themeRGB();
                gl.uniform2f(uRes,canvas.width,canvas.height);
                gl.uniform1f(uT,t);
                gl.uniform3f(uC1,r1/255,g1/255,b1/255);
                gl.uniform3f(uC2,r2/255,g2/255,b2/255);
                gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'starfield',
        label: 'Starfield',
        preview: '#00000a',
        /**
         * Warp-speed stars coloured by theme primary, clear trail fade.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx=canvas.getContext('2d');
            let W,H; const N=280; let stars;
            function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            function mkStar(){
                const angle=Math.random()*Math.PI*2, dist=Math.random()*3;
                return {x:W/2+Math.cos(angle)*dist, y:H/2+Math.sin(angle)*dist,
                        px:W/2, py:H/2, speed:0.05+Math.random()*0.12, size:Math.random()*2+0.5};
            }
            resize(); stars=Array.from({length:N},mkStar);
            window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                const {p:[r,g,b]}=_themeRGB();
                ctx.globalCompositeOperation = 'destination-out';
                ctx.fillStyle = 'rgba(0,0,0,0.14)';
                ctx.fillRect(0,0,W,H);
                ctx.globalCompositeOperation = 'source-over';
                for(const s of stars){
                    s.px=s.x; s.py=s.y;
                    const dx=s.x-W/2, dy=s.y-H/2, len=Math.sqrt(dx*dx+dy*dy);
                    s.x+=dx/len*s.speed*(1+len/180); s.y+=dy/len*s.speed*(1+len/180);
                    const bright=Math.min(1,len/250);
                    ctx.beginPath(); ctx.moveTo(s.px,s.py); ctx.lineTo(s.x,s.y);
                    ctx.strokeStyle=`rgba(255,255,255,${(bright*0.85).toFixed(2)})`;
                    ctx.lineWidth=s.size*bright; ctx.stroke();
                    if(s.x<0||s.x>W||s.y<0||s.y>H){const ns=mkStar(); Object.assign(s,ns);}
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'metaballs',
        label: 'Metaballs',
        preview: '#020010',
        /**
         * WebGL SDF metaballs — smooth organic blobs in theme colours.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const frag = `
precision mediump float;
uniform vec2 u_res; uniform float u_t; uniform vec3 u_c1; uniform vec3 u_c2;
#define N 7
void main(){
    vec2 uv=(gl_FragCoord.xy/u_res)*2.0-1.0;
    uv.x*=u_res.x/u_res.y;
    float t=u_t*0.04;
    float field=0.0;
    for(int i=0;i<N;i++){
        float fi=float(i);
        float spd=0.5+fi*0.13;
        vec2 c=vec2(
            0.7*sin(t*spd+fi*2.39996),
            0.7*cos(t*spd*0.7+fi*1.61803)
        );
        float r=0.18+0.06*sin(t*1.1+fi);
        field+=r*r/dot(uv-c,uv-c);
    }
    float v=smoothstep(0.9,1.0,field);
    float edge=smoothstep(0.7,0.9,field)*(1.0-v);
    vec3 col=mix(u_c1,u_c2,clamp(field*0.3,0.0,1.0));
    float alpha=v*0.80+edge*0.40;
    gl_FragColor=vec4(col,alpha);
}`;
            const gp=_glProgram(canvas,VERT_PASSTHROUGH,frag);
            if(!gp) return;
            const {gl,prog}=gp;
            const uRes=gl.getUniformLocation(prog,'u_res');
            const uT  =gl.getUniformLocation(prog,'u_t');
            const uC1 =gl.getUniformLocation(prog,'u_c1');
            const uC2 =gl.getUniformLocation(prog,'u_c2');
            let t=0;
            function resize(){canvas.width=window.innerWidth;canvas.height=window.innerHeight;gl.viewport(0,0,canvas.width,canvas.height);}
            resize(); window.addEventListener('resize',resize);
            gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA,gl.ONE_MINUS_SRC_ALPHA);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                t+=0.15;
                gl.useProgram(prog);
                const {p:[r1,g1,b1],a:[r2,g2,b2]}=_themeRGB();
                gl.uniform2f(uRes,canvas.width,canvas.height);
                gl.uniform1f(uT,t);
                gl.uniform3f(uC1,r1/255,g1/255,b1/255);
                gl.uniform3f(uC2,r2/255,g2/255,b2/255);
                gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'flowfield',
        label: 'Flow Field',
        preview: '#000a0a',
        /**
         * Curl-noise flow field — thousands of particles streaming along vector field.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx=canvas.getContext('2d');
            let W,H,t=0; const N=1200;
            let pts;
            function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            function noise2(x,y,t){
                const s=Math.sin(x*0.012+t*0.4)*Math.cos(y*0.010+t*0.3)
                       +Math.sin(x*0.008-t*0.2)*Math.sin(y*0.014+t*0.5)
                       +Math.sin((x+y)*0.006+t*0.35);
                return s;
            }
            function mkPt(){ return {x:Math.random()*W,y:Math.random()*H,life:Math.random()*200+100}; }
            resize(); pts=Array.from({length:N},mkPt);
            window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                t+=0.0008;
                const {p:[r,g,b],a:[r2,g2,b2]}=_themeRGB();
                /* Erase slowly enough that trails are visible but fast enough they don't dirty */
                ctx.globalCompositeOperation = 'destination-out';
                ctx.fillStyle = 'rgba(0,0,0,0.07)';
                ctx.fillRect(0,0,W,H);
                ctx.globalCompositeOperation = 'source-over';
                ctx.lineWidth=0.9;
                for(const p of pts){
                    const angle=noise2(p.x,p.y,t)*Math.PI*2;
                    const px=p.x, py=p.y;
                    p.x+=Math.cos(angle)*0.22; p.y+=Math.sin(angle)*0.22;
                    p.life--;
                    const mix=0.5+0.5*Math.sin(t*80+p.x/W*Math.PI);
                    const cr=Math.round(r+(r2-r)*mix), cg=Math.round(g+(g2-g)*mix), cb=Math.round(b+(b2-b)*mix);
                    const alpha=Math.min(1,p.life/80)*0.55;
                    ctx.beginPath(); ctx.moveTo(px,py); ctx.lineTo(p.x,p.y);
                    ctx.strokeStyle=`rgba(${cr},${cg},${cb},${alpha.toFixed(2)})`; ctx.stroke();
                    if(p.life<=0||p.x<0||p.x>W||p.y<0||p.y>H){const n=mkPt(); p.x=n.x; p.y=n.y; p.life=n.life;}
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'fireflies',
        label: 'Fireflies',
        preview: '#020e06',
        /**
         * Glowing organic drifters — large visible halos in theme accent colour.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx=canvas.getContext('2d');
            let W,H,t=0; const N=70; let ff;
            function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            function mkFf(){ return {x:Math.random()*W,y:Math.random()*H,vx:0,vy:0,
                phase:Math.random()*Math.PI*2,pspeed:0.01+Math.random()*0.018,seed:Math.random()*1000}; }
            resize(); ff=Array.from({length:N},mkFf);
            window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                t+=0.0015;
                const {a:[r,g,b]}=_themeRGB();
                ctx.clearRect(0,0,W,H);
                for(const f of ff){
                    f.phase+=f.pspeed;
                    const angle=Math.sin(t*0.5+f.seed)*Math.PI*2+Math.cos(t*0.3+f.seed*0.7)*Math.PI;
                    f.vx+=Math.cos(angle)*0.006; f.vy+=Math.sin(angle)*0.006;
                    f.vx*=0.95; f.vy*=0.95;
                    f.x+=f.vx; f.y+=f.vy;
                    if(f.x<0)f.x=W; if(f.x>W)f.x=0; if(f.y<0)f.y=H; if(f.y>H)f.y=0;
                    const glow=Math.sin(f.phase)*0.5+0.5;
                    const radius=4+glow*6;
                    const grad=ctx.createRadialGradient(f.x,f.y,0,f.x,f.y,radius*5);
                    grad.addColorStop(0,`rgba(${r},${g},${b},${(glow*0.95).toFixed(2)})`);
                    grad.addColorStop(0.4,`rgba(${r},${g},${b},${(glow*0.5).toFixed(2)})`);
                    grad.addColorStop(1,`rgba(${r},${g},${b},0)`);
                    ctx.beginPath(); ctx.arc(f.x,f.y,radius*5,0,Math.PI*2);
                    ctx.fillStyle=grad; ctx.fill();
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'circuit',
        label: 'Circuit',
        preview: '#020808',
        /**
         * PCB-style circuit traces with bright theme-coloured signal pulses.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx=canvas.getContext('2d');
            let W,H,segs,pulses,t=0; const STEP=44;
            function resize(){
                W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight;
                segs=[]; pulses=[];
                const DIRS=[[1,0],[-1,0],[0,1],[0,-1]];
                for(let i=0;i<80;i++){
                    const x=Math.round(Math.random()*W/STEP)*STEP;
                    const y=Math.round(Math.random()*H/STEP)*STEP;
                    const dir=DIRS[Math.floor(Math.random()*4)];
                    const len=3+Math.floor(Math.random()*7);
                    segs.push({x1:x,y1:y,x2:x+dir[0]*STEP*len,y2:y+dir[1]*STEP*len});
                    if(Math.random()>0.4) pulses.push({seg:segs[segs.length-1],t:Math.random()});
                }
            }
            resize(); window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                ctx.clearRect(0,0,W,H); t+=0.08;
                const {p:[r,g,b]}=_themeRGB();
                ctx.strokeStyle=`rgba(${r},${g},${b},0.25)`; ctx.lineWidth=1;
                for(const s of segs){
                    ctx.beginPath(); ctx.moveTo(s.x1,s.y1); ctx.lineTo(s.x2,s.y2); ctx.stroke();
                    ctx.beginPath(); ctx.arc(s.x1,s.y1,2.5,0,Math.PI*2);
                    ctx.fillStyle=`rgba(${r},${g},${b},0.55)`; ctx.fill();
                }
                for(const p of pulses){
                    p.t=(p.t+0.0008)%1;
                    const px=p.seg.x1+(p.seg.x2-p.seg.x1)*p.t;
                    const py=p.seg.y1+(p.seg.y2-p.seg.y1)*p.t;
                    const grad=ctx.createRadialGradient(px,py,0,px,py,10);
                    grad.addColorStop(0,`rgba(${r},${g},${b},1)`);
                    grad.addColorStop(1,`rgba(${r},${g},${b},0)`);
                    ctx.beginPath(); ctx.arc(px,py,10,0,Math.PI*2);
                    ctx.fillStyle=grad; ctx.fill();
                }
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

    {
        id: 'voronoi',
        label: 'Voronoi',
        preview: '#080014',
        /**
         * WebGL Voronoi cell diagram — slowly drifting seed points produce
         * smooth cell boundaries coloured by theme primary/accent.
         * Each cell edge glows in accent colour; cell interiors fade to transparent.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const frag = `
precision mediump float;
uniform vec2  u_res;
uniform float u_t;
uniform vec3  u_c1;
uniform vec3  u_c2;
#define N 14
vec2 seed(int i, float t) {
    float fi = float(i);
    float spd = 0.03 + fi * 0.007;
    return vec2(
        0.5 + 0.42 * sin(t * spd        + fi * 2.3999),
        0.5 + 0.42 * cos(t * spd * 0.71 + fi * 1.6180)
    );
}
void main() {
    vec2 uv = gl_FragCoord.xy / u_res;
    float d1 = 9.0, d2 = 9.0;
    int   ci = 0;
    for (int i = 0; i < N; i++) {
        float d = distance(uv, seed(i, u_t));
        if (d < d1) { d2 = d1; d1 = d; ci = i; }
        else if (d < d2) { d2 = d; }
    }
    float edge   = 1.0 - smoothstep(0.0, 0.012, d2 - d1);
    float interior = smoothstep(0.0, 0.18, d2 - d1) * (1.0 - smoothstep(0.18, 0.55, d1));
    float hue    = fract(float(ci) * 0.618);
    vec3  cellC  = mix(u_c1, u_c2, hue);
    vec3  col    = mix(cellC * interior, u_c2, edge);
    float alpha  = edge * 0.80 + interior * 0.28;
    gl_FragColor = vec4(col, clamp(alpha, 0.0, 1.0));
}`;
            const gp = _glProgram(canvas, VERT_PASSTHROUGH, frag);
            if (!gp) return;
            const { gl, prog } = gp;
            const uRes = gl.getUniformLocation(prog, 'u_res');
            const uT   = gl.getUniformLocation(prog, 'u_t');
            const uC1  = gl.getUniformLocation(prog, 'u_c1');
            const uC2  = gl.getUniformLocation(prog, 'u_c2');
            let t = 0;
            function resize() {
                canvas.width  = window.innerWidth;
                canvas.height = window.innerHeight;
                gl.viewport(0, 0, canvas.width, canvas.height);
            }
            resize();
            window.addEventListener('resize', resize);
            gl.enable(gl.BLEND);
            gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
            function frame() {
                if (!stop.active) { window.removeEventListener('resize', resize); return; }
                t += 0.1;
                gl.useProgram(prog);
                const { p:[r1,g1,b1], a:[r2,g2,b2] } = _themeRGB();
                gl.uniform2f(uRes, canvas.width, canvas.height);
                gl.uniform1f(uT, t);
                gl.uniform3f(uC1, r1/255, g1/255, b1/255);
                gl.uniform3f(uC2, r2/255, g2/255, b2/255);
                gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
                requestAnimationFrame(frame);
            }
            requestAnimationFrame(frame);
        }
    },

];

/** Currently running background stop handle and canvas */
let _bgStop = null;
let _bgCanvas = null;
let _bgOverlay = null;

/**
 * Injects #bg-canvas and #bg-overlay into body if not already present.
 * Idempotent.
 */
function _ensureBgElements() {
    if (!_bgCanvas) {
        _bgCanvas = document.getElementById('bg-canvas');
        if (!_bgCanvas) {
            _bgCanvas = document.createElement('canvas');
            _bgCanvas.id = 'bg-canvas';
            document.body.prepend(_bgCanvas);
        }
    }
    if (!_bgOverlay) {
        _bgOverlay = document.getElementById('bg-overlay');
        if (!_bgOverlay) {
            _bgOverlay = document.createElement('div');
            _bgOverlay.id = 'bg-overlay';
            document.body.prepend(_bgOverlay);
        }
    }
}

/**
 * Stops any running background animation and restores normal body/html backgrounds.
 */
function _stopBg() {
    if (_bgStop) { _bgStop.active = false; _bgStop = null; }
    if (_bgCanvas) {
        const ctx = _bgCanvas.getContext('2d');
        if (ctx) ctx.clearRect(0, 0, _bgCanvas.width, _bgCanvas.height);
    }
    document.body.classList.remove('has-bg-canvas');
}

/**
 * Sets the active live background, persists to localStorage, updates active state.
 * Pins the <html> element background to the canvas base colour so no light bg
 * from the viewport (behind body) bleeds through.
 * @param {string} id - Background id from BACKGROUNDS registry.
 */
function setBg(id) {
    _stopBg();
    localStorage.setItem('ldmd-bg', id);
    document.querySelectorAll('.nav-bg-item').forEach(b =>
        b.classList.toggle('active', b.dataset.bg === id));

    const bg = BACKGROUNDS.find(b => b.id === id);
    if (!bg || !bg.render) return;

    _ensureBgElements();
    document.body.classList.add('has-bg-canvas');
    _bgStop = { active: true };
    bg.render(_bgCanvas, _bgStop);
}

/**
 * Draws a static gradient swatch onto a small preview canvas using the
 * background's preview hex colour and the current theme primary colour.
 * @param {HTMLCanvasElement} canvas
 * @param {string} hex  - base colour for the swatch
 */
function _drawBgSwatch(canvas, hex) {
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const {p:[r,g,b]} = _themeRGB();
    const grad = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
    grad.addColorStop(0, hex);
    grad.addColorStop(1, `rgba(${r},${g},${b},0.6)`);
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
}

/**
 * Populates #bg-list with buttons from BACKGROUNDS registry and attaches
 * click handlers. Preview swatches are static gradients — running full
 * renderers on tiny canvases conflicts with WebGL context limits.
 */
function initBgList() {
    const list = document.getElementById('bg-list');
    if (!list) return;

    list.innerHTML = BACKGROUNDS.map(b => {
        const previewHtml = b.preview
            ? `<span class="bg-preview"><canvas data-bg-preview="${b.id}" width="56" height="36" style="display:block;width:100%;height:100%"></canvas></span>`
            : `<span class="bg-preview" style="background:var(--divider);display:flex;align-items:center;justify-content:center"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="5" x2="19" y2="19"/><line x1="19" y1="5" x2="5" y2="19"/></svg></span>`;
        return `<button class="nav-popup-item nav-bg-item" data-bg="${b.id}">${previewHtml}${b.label}</button>`;
    }).join('');

    list.querySelectorAll('[data-bg-preview]').forEach(pc => {
        const bg = BACKGROUNDS.find(b => b.id === pc.dataset.bgPreview);
        if (bg && bg.preview) _drawBgSwatch(pc, bg.preview);
    });

    const saved = localStorage.getItem('ldmd-bg') || 'none';
    list.querySelectorAll('.nav-bg-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.bg === saved);
        btn.addEventListener('click', () => {
            setBg(btn.dataset.bg);
            document.querySelectorAll('.nav-popup-menu.open').forEach(m => m.classList.remove('open'));
            document.querySelectorAll('.nav-popup-btn.active').forEach(b => b.classList.remove('active'));
        });
    });
}

window.setBg = setBg;

// Apply persisted theme and fonts before first paint
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

// Mark active theme/font/bg once the DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initThemeList();
    initBgList();

    const savedFont = localStorage.getItem('ldmd-font') || 'departure-mono';
    document.querySelectorAll('.nav-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.font === savedFont));

    const savedReadingFont = localStorage.getItem('ldmd-reading-font') || 'inter';
    document.querySelectorAll('.nav-reading-font-item').forEach(b =>
        b.classList.toggle('active', b.dataset.readingFont === savedReadingFont));

    const savedBg = localStorage.getItem('ldmd-bg');
    if (savedBg && savedBg !== 'none') setBg(savedBg);
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
