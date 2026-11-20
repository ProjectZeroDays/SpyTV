"""Wire auto-update endpoints into c2_server.py."""
p = "c2_server.py"
s = open(p).read()

# 1. Add GET endpoint for /api/update/check
old = '        elif path == "/api/tv/info":\n            self.serve_tv_info()\n'
new = '        elif path == "/api/tv/info":\n            self.serve_tv_info()\n        elif path == "/api/update/check":\n            self.serve_update_check()\n'
assert old in s, "GET pattern not found"
s = s.replace(old, new)

# 2. Add serve_update_check method after serve_tv_info method
# Find the end of serve_tv_info method - look for the next method def or class
import re
# Insert before serve_settings method (which is a class method)
anchor = "    # ===== Settings endpoints ===============================================\n"
method = '''    def serve_update_check(self):
        """GET /api/update/check — check for available updates."""
        try:
            from core.auto_update import status as _au_status
            if _au_status is None:
                self.send_json(500, {"error": "auto_update module unavailable"})
                return
            self.send_json(200, _au_status())
        except Exception as e:
            self.send_json(500, {"error": str(e)})

'''
assert anchor in s, "anchor not found"
s = s.replace(anchor, method + anchor, 1)

# 3. Add startup auto-update check in main()
old_main = '    # Auto-update the CVE feed on every C2 start'
new_main = '    # Kick off background auto-update check (non-blocking)\n    try:\n        from core.auto_update import check_async as _au_check_async\n        if _au_check_async:\n            _au_check_async()\n    except Exception:\n        pass\n\n    # Auto-update the CVE feed on every C2 start'
assert old_main in s, "main pattern not found"
s = s.replace(old_main, new_main, 1)

open(p, "w").write(s)
print("All edits applied successfully")
"