#!/usr/bin/env python3
import ssl, os, json, datetime, logging
from http.server import BaseHTTPRequestHandler, HTTPServer

STORE = os.environ.get("TV_FLOW_STORE", os.path.join("logs", "tv_flow"))
os.makedirs(STORE, exist_ok=True)

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
            kind = "audio" if "kind=audio" in self.path else "video"
            os.makedirs(f"{STORE}/{kind}/{now.strftime('%Y%m%d')}", exist_ok=True)
            path = f"{STORE}/{kind}/{now.strftime('%Y%m%d')}/{now.strftime('%H%M%S')}_{fname}"
            with open(path, "wb") as f: f.write(body)
            logging.info(f"{self.client_address[0]} {kind} {len(body)} {fname}")
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
        except Exception as e:
            logging.error(f"recv fail: {e}")
    def do_GET(self):
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
        logging.warning(f"SSL certs not found at {certfile}/{keyfile}")
    return context

if __name__ == "__main__":
    port = int(os.environ.get("TV_FLOW_PORT", "7443"))
    srv = HTTPServer(("0.0.0.0", port), C4)
    context = create_ssl_context()
    srv.socket = context.wrap_socket(srv.socket, server_side=True)
    print(f"C4 Receiver running on :{port}")
    srv.serve_forever()
