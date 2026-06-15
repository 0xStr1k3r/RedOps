"""VulnLab web01 — intentionally vulnerable demo target (stdlib only).

Serves, deliberately:
  - no Content-Security-Policy / HSTS / X-Frame-Options headers
  - verbose Server banner with version
  - /robots.txt pointing at /admin
  - /sitemap.xml listing app routes
  - /admin login page (anything typed fails; no real accounts)
  - X-Powered-By + generator meta fingerprints

Lab use only. Never expose this container to untrusted networks.
"""
import http.server
import socketserver

SERVER_BANNER = "VulnLab/1.4.2"
ADMIN_TITLE = "Admin Console - Login"

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n"
SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/admin</loc></url>
  <url><loc>/api/status</loc></url>
</urlset>
"""
INDEX = """<html><head><title>VulnLab Intranet</title>
<meta name="generator" content="VulnPress 2.1">
</head><body><h1>VulnLab Intranet</h1>
<p>Employee portal. <a href="/admin">Admin login</a></p>
</body></html>
"""
ADMIN = """<html><head><title>Admin Console - Login</title></head>
<body><h1>Admin Console</h1>
<form method="post" action="/admin">
<input name="user" placeholder="username">
<input name="password" type="password" placeholder="password">
<input type="submit" value="Sign in"></form></body></html>
"""
STATUS = '{"status":"ok","version":"1.4.2"}'


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "VulnLab"
    sys_version = "1.4.2"

    def _send(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "VulnPHP/8.0")
        # NOTE: no CSP / HSTS / X-Frame-Options on purpose (lab target).
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if self.path == "/sitemap.xml":
            return self._send(200, SITEMAP, "application/xml")
        if self.path == "/admin":
            return self._send(200, ADMIN)
        if self.path == "/api/status":
            return self._send(200, STATUS, "application/json")
        return self._send(200, INDEX)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(min(length, 4096))
        self._send(401, "<html><body>Invalid credentials.</body></html>")

    def log_message(self, *args):  # keep logs quiet
        pass


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", 8080), Handler) as httpd:
        httpd.serve_forever()
