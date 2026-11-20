s = open('c2_dashboard.html', encoding='utf-8').read()
old = '</header>\n\n<!-- Navigation -->'
new = '</header>\n\n<!-- Update Banner (hidden until an update is detected) -->\n<div id="update-banner" style="display:none; background:linear-gradient(90deg,#1E3A5F,#1E40AF); color:#F3F4F6; padding:10px 20px; text-align:center; font-size:13px; border-bottom:1px solid #3B82F6;">\n  <span id="update-banner-text">A new version of SpyTV is available.</span>\n  <a id="update-banner-link" href="#" target="_blank" style="color:#93C5FD; margin-left:12px; text-decoration:underline;">Download</a>\n  <button onclick="document.getElementById(\'update-banner\').style.display=\'none\'" style="background:none;border:none;color:#9CA3AF;margin-left:16px;cursor:pointer;">X</button>\n</div>\n\n<!-- Navigation -->'
assert old in s, "pattern not found"
s = s.replace(old, new, 1)
open('c2_dashboard.html', 'w', encoding='utf-8').write(s)
print('banner added successfully')
