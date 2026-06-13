// backgrounds.js — Animated background system.
// Depends on: themes.js (for _themeRGB via THEMES — not used directly here).
// Loaded after themes.js, before app.js.
// Exposes: BACKGROUNDS, setBg (also on window.setBg).

/* eslint-disable no-unused-vars */

/**
 * Reads --primary-color and --accent-color CSS vars from :root as [r,g,b] arrays.
 * Falls back gracefully if the value is not a plain 3/6-char hex string.
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
 * Compiles and links a WebGL program with a fullscreen quad buffer.
 * Returns null if WebGL is unavailable or shader compilation fails.
 * @param {HTMLCanvasElement} canvas
 * @param {string} vert - Vertex shader GLSL source
 * @param {string} frag - Fragment shader GLSL source
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

/**
 * Registry of available animated backgrounds.
 * Each entry: { id, label, preview (hex swatch color or null), render(canvas, stop) }
 *   render(canvas, stopRef) — starts the rAF loop.
 *     Set stopRef.active=false to terminate the loop.
 */
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
         * Multiple sinusoidal wave layers using both theme colours.
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
         * cmatrix-style rain: discrete rows, per-column speed tiers, white glowing
         * head that fades to theme-coloured trail behind it.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx = canvas.getContext('2d');
            const FS   = 16;
            const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>{}[]|/\\;:?!=+-';
            let W, H, ROWS, cols, streams;

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
                ctx.clearRect(0, 0, W, H);
                streams = Array.from({ length: cols }, mkStream);
            }
            resize();
            window.addEventListener('resize', resize);

            function frame() {
                if (!stop.active) { window.removeEventListener('resize', resize); return; }
                const { p:[r,g,b] } = _themeRGB();
                ctx.font = `bold ${FS}px monospace`;

                for (let i = 0; i < cols; i++) {
                    const s = streams[i];
                    if (!s.active) continue;
                    s.timer++;
                    if (s.timer < s.ticks) continue;
                    s.timer = 0;

                    const x = i * FS;
                    const tailRow = s.head - s.len;
                    if (tailRow >= 0 && tailRow < ROWS) ctx.clearRect(x, tailRow * FS, FS, FS);

                    s.head++;

                    if (s.head >= 0 && s.head < ROWS) {
                        ctx.fillStyle = `rgba(210,255,225,0.95)`;
                        ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, s.head * FS + FS);
                    }

                    const prevRow = s.head - 1;
                    if (prevRow >= 0 && prevRow < ROWS) {
                        ctx.clearRect(x, prevRow * FS, FS, FS);
                        ctx.fillStyle = `rgba(${r},${g},${b},0.92)`;
                        ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, prevRow * FS + FS);
                    }

                    for (let j = 2; j < s.len; j++) {
                        const tr = s.head - j;
                        if (tr < 0 || tr >= ROWS) continue;
                        ctx.globalCompositeOperation = 'destination-out';
                        ctx.fillStyle = 'rgba(0,0,0,0.06)';
                        ctx.fillRect(x, tr * FS, FS, FS);
                        ctx.globalCompositeOperation = 'source-over';
                        if (Math.random() < 0.04) {
                            const fade = 1 - j / s.len;
                            ctx.fillStyle = `rgba(${Math.round(r*fade)},${Math.round(g*fade)},${Math.round(b*fade)},${(fade*0.85).toFixed(2)})`;
                            ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, tr * FS + FS);
                        }
                    }

                    if (s.head - s.len > ROWS) {
                        s.head  = -Math.floor(Math.random() * ROWS * 0.5);
                        s.len   = Math.floor(8 + Math.random() * 20);
                        s.ticks = 4 + Math.floor(Math.random() * 4);
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
         * Falls back to Canvas2D if WebGL is unavailable.
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
         * Warp-speed stars with destination-out trail fade.
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
        vec2 c=vec2(0.7*sin(t*spd+fi*2.39996),0.7*cos(t*spd*0.7+fi*1.61803));
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
         * Curl-noise flow field — particles streaming along an animated vector field.
         * @param {HTMLCanvasElement} canvas
         * @param {{active:boolean}} stop
         */
        render(canvas, stop) {
            const ctx=canvas.getContext('2d');
            let W,H,t=0; const N=1200;
            let pts;
            function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
            function noise2(x,y,t){
                return Math.sin(x*0.012+t*0.4)*Math.cos(y*0.010+t*0.3)
                      +Math.sin(x*0.008-t*0.2)*Math.sin(y*0.014+t*0.5)
                      +Math.sin((x+y)*0.006+t*0.35);
            }
            function mkPt(){ return {x:Math.random()*W,y:Math.random()*H,life:Math.random()*200+100}; }
            resize(); pts=Array.from({length:N},mkPt);
            window.addEventListener('resize',resize);
            function frame(){
                if(!stop.active){window.removeEventListener('resize',resize);return;}
                t+=0.0008;
                const {p:[r,g,b],a:[r2,g2,b2]}=_themeRGB();
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
         * Glowing organic drifters with radial-gradient halos in theme accent colour.
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
         * WebGL Voronoi — slowly drifting seed points, glowing edges in accent colour.
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
    return vec2(0.5 + 0.42 * sin(t * spd + fi * 2.3999), 0.5 + 0.42 * cos(t * spd * 0.71 + fi * 1.6180));
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
    float edge    = 1.0 - smoothstep(0.0, 0.012, d2 - d1);
    float interior = smoothstep(0.0, 0.18, d2 - d1) * (1.0 - smoothstep(0.18, 0.55, d1));
    float hue     = fract(float(ci) * 0.618);
    vec3  cellC   = mix(u_c1, u_c2, hue);
    vec3  col     = mix(cellC * interior, u_c2, edge);
    float alpha   = edge * 0.80 + interior * 0.28;
    gl_FragColor  = vec4(col, clamp(alpha, 0.0, 1.0));
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

let _bgStop   = null;
let _bgCanvas = null;
let _bgOverlay = null;

/**
 * Injects #bg-canvas and #bg-overlay into body if not already present. Idempotent.
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
 * Stops any running background animation and clears the canvas.
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
 * Activates the background with the given id, persists selection, updates nav state.
 * @param {string} id - Background id from BACKGROUNDS registry
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
 * Draws a static gradient swatch onto a small preview canvas.
 * @param {HTMLCanvasElement} canvas
 * @param {string} hex - Base colour for the swatch
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
 * Populates #bg-list with buttons from BACKGROUNDS and attaches click handlers.
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
