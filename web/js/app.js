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
    initThemeList();

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
