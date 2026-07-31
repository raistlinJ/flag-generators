import argparse
import base64
import hashlib
import json
import os
import sqlite3
import zipfile
from pathlib import Path
from typing import Any


GENERATOR_FAMILY = "http_variant_runtime"

TLS_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfftchsJqLON56
kQkWShbaND1cS4EXI95Fy1c/k7MH6rX8Y016KjqBIWWL7cfRoDXqf87vQ3JVYQeq
j3EAwlBwRmooMcZ/KvPhq+0iL3HSizDAMLaB0K0sPIjg1WKYn+BXK6NEtaLy2wzy
uZ0Wnvr6gHCYCwO7T66DwrCFUXCXqccQJFNzquJH1zpbvWYc9WS4Zf93NxUn+NSX
sHjLIum5+8DEm+E0RoyDIUZZ2eNMW7FKYn0EeW9uMBp1eQHZMPWnTtTYSG8gBdRs
FB0Qhruz3E0njiu4/vrxNH0Q1GFOwqZuNLXIsztuZ5Gz3OJzZ7tHuUOxs5GZRH4P
V8gG1FDxAgMBAAECggEAAfAk8bQAsGmbDk4taBxzfNhq3jXX6knBb2j4PQBYxKNB
TbvrFtLfv1PSP8DOfLgWWEyQKCPCUPem+TdpNBfYXxaOScxJ39/WuFwE0OAha+w3
cKoViVFpgvQI8Ff2x4QKUiQtwEW3gUgAgdbNRLde9VIqxBXeraJlzHRePXQlqB8c
lGU5NuiIbkVCUgOPQHgarnnNOkmGHNIg8w76iuY2JKYw3/E7w/J0n3gXTYMY4Bm+
frsBK4vdGcea/rbgW9oBobMjUWypM43f23exeEGsEKyd+tJ0jwc4SsdmRx4eibAa
iaoWmXSkAfOHEtJWyMckceyrjKbd+3AOd5LtJyr84QKBgQDSqaW87EfRvWSR6+Og
JWyJNJ6d/Axd6AxAUhV9uBVytdM2gXXB8fMfZNBpLmXSulk1ivPH/ko3HyaBQstH
2ve7e8BowrR3bf9EtglrenmxM+FUwgnzvaDQmmaBchTz29R2XxHtA9Gqxia/IH9N
a/bNmuZQ3XcV5Em4vMqSGmp1IQKBgQDB0ilWcPcypwmVVfpUeU4ujePpkPITkRjL
UPCm9PDT1lDc47ngKsf9Bme1LKoL91Hf5iRvDIkyP6J5USboofWlBI1kTVvikf7S
Mq/d0uVq4bNhpG4+S8PcE31neQkWOEOy1Ez9/2JdIgzidM0JQuiwhYxVyJ3e71i1
mIEmVDOR0QKBgBkqZP81prq6ikoYSN/3uIiHfa9Xzc5mCxif9atIE1/ZsrqfKocZ
tTZ535/BCC7tTfzkdYzdptYA5aOpbAlQcim2ddzN7asau9TkfimVvvXZQcDTUUcJ
zy08VKSAEVq0VyQw5T5QJ3rkIvrQEgUYsaoMKBle63v1Ao2MGBLuDuuhAoGABrvr
jcJNBGiDT7n2AZtZWQq7AXF0x7NB3kaIpfRarbGDi7kpyx0RZ7wiPEw5+EJ2iMXx
PB5+Yc2OMpLcPDbsVvhqhTKe36dc6Ca0r4tVRzpiRiE1Z1qwimPu9nphE3GPAJaZ
ujV2UHAPbIrMWOcHOKLbNlvLCGTeeyi6S/+e7xECgYBzlt1rN3IcEALjGnrF4ZGS
crIluHIx0AvHFR6elOy6Ibk7N9S92J7/GATLG3oxSTa2vQ8Y7P6SH9ln5UggJTwr
gg0e2LX2rwFMEYjPeyBDq3Kga9n7f635zJo+lE3JwY85S8q3UbeKw3tya6Fa0U52
mTb/QEDVpgn9GixJ5EOItw==
-----END PRIVATE KEY-----
"""

TLS_CERT = """-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIURstthG06u3Yr8ZQNxt0n+9bEojcwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZY29yZXRnLWh0dHAtdmFyaWFudC5sb2NhbDAeFw0yNjA1
MjEwMDAwMTJaFw0zNjA1MTgwMDAwMTJaMCQxIjAgBgNVBAMMGWNvcmV0Zy1odHRw
LXZhcmlhbnQubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf
ftchsJqLON56kQkWShbaND1cS4EXI95Fy1c/k7MH6rX8Y016KjqBIWWL7cfRoDXq
f87vQ3JVYQeqj3EAwlBwRmooMcZ/KvPhq+0iL3HSizDAMLaB0K0sPIjg1WKYn+BX
K6NEtaLy2wzyuZ0Wnvr6gHCYCwO7T66DwrCFUXCXqccQJFNzquJH1zpbvWYc9WS4
Zf93NxUn+NSXsHjLIum5+8DEm+E0RoyDIUZZ2eNMW7FKYn0EeW9uMBp1eQHZMPWn
TtTYSG8gBdRsFB0Qhruz3E0njiu4/vrxNH0Q1GFOwqZuNLXIsztuZ5Gz3OJzZ7tH
uUOxs5GZRH4PV8gG1FDxAgMBAAGjUzBRMB0GA1UdDgQWBBRHkpIl+umUFF5ZBbgH
hL4LCIu4tzAfBgNVHSMEGDAWgBRHkpIl+umUFF5ZBbgHhL4LCIu4tzAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQARzlEmhFb6abzRnQ2/HQ11uJT1
v3hE+iDfyHDAuPeySw9VQsZIl21Krbv8xiS9DXf4sV/AQIfawTKEtBWoHKJj1cdp
UQbtWnzQcPcGp/NTtKk1QXqhbPqFcZQTKl1XSSWLBq0JX8HXi/KifQat6Dc6ye0n
COV0vCx0R/tPpCHkqZT85bSfgEd6wDf+ccHdX6JMfbwowWjfrbPIS64XHWZ6yYTf
/7W2oodWP1RCi1N4i/ZYYo+xVAoqxu1+Fh58fWtM3xS8iNAF8cgJrwtLFD+I6ZaE
vlhmdst7OsF2S/yORt0NNdzvzl6OMUbi5CyeODljWWP5OxG+kbX0xtGcVsbg
-----END CERTIFICATE-----
"""


VARIANTS: dict[str, dict[str, Any]] = {
    "http_public_file_drop": {
        "scheme": "http",
        "auth": "none",
        "title": "Facilities Asset Portal",
        "tagline": "Shared maintenance notices and site asset packets.",
        "theme": "facilities",
        "endpoint": "/downloads/risk-register.txt",
        "flag_path": "public/downloads/risk-register.txt",
        "extra_facts": {"Misconfiguration(service)": "public_file_drop"},
        "files": {
            "public/downloads/maintenance-window.txt": "Maintenance window {digest}\nScope: access closets and UPS checks.\n",
            "public/downloads/risk-register.txt": "Facilities risk register\nowner=site-ops\nflag={flag}\n",
            "public/docs/vendor-contacts.csv": "vendor,contact\nLiftCo,service@example.invalid\nCleanOps,dispatch@example.invalid\n",
        },
    },
    "https_public_status_page": {
        "scheme": "https",
        "auth": "none",
        "title": "Regional Status Board",
        "tagline": "TLS status board for field office health and scheduled downtime.",
        "theme": "status",
        "endpoint": "/status/maintenance",
        "flag_path": "public/status/maintenance-note.txt",
        "extra_facts": {"Endpoint(path)": "/status/maintenance"},
        "files": {
            "public/status/maintenance-note.txt": "Status board note {digest}\nflag={flag}\n",
            "public/status/incidents.json": "{\"incidents\": [{\"id\": \"{digest}\", \"status\": \"monitoring\"}]}\n",
        },
    },
    "http_login_staff_portal": {
        "scheme": "http",
        "auth": "form",
        "title": "Staff Services Portal",
        "tagline": "Employee requests, onboarding notes, and departmental bulletins.",
        "theme": "staff",
        "endpoint": "/dashboard",
        "flag_path": "private/staff/onboarding-note.txt",
        "extra_facts": {"WebAuthBypass(app)": "staff_portal"},
        "files": {
            "private/staff/onboarding-note.txt": "Staff onboarding exception {digest}\nflag={flag}\n",
            "public/forms/timeoff-policy.txt": "Time off requests require manager approval and HR review.\n",
        },
    },
    "https_login_admin_console": {
        "scheme": "https",
        "auth": "form",
        "title": "Admin Operations Console",
        "tagline": "TLS-protected console for internal service checks.",
        "theme": "admin",
        "endpoint": "/dashboard",
        "flag_path": "private/admin/change-ticket.txt",
        "extra_facts": {"WebAuthBypass(app)": "admin_console"},
        "files": {
            "private/admin/change-ticket.txt": "Admin change ticket {digest}\nflag={flag}\n",
            "private/admin/service-map.csv": "service,owner\nauth,platform\nbilling,finance\n",
        },
    },
    "http_source_secret_repo": {
        "scheme": "http",
        "auth": "none",
        "title": "Internal Code Browser",
        "tagline": "Read-only source browser for a small operations utility.",
        "theme": "source",
        "endpoint": "/source/app.py",
        "flag_path": "source/app.py",
        "secret_source": True,
        "extra_facts": {"SourceCode(repo)": "ops_utility", "ExposedSecret(service)": "source_browser"},
        "files": {
            "public/README.txt": "Source mirror for the ops utility. Do not publish outside engineering.\n",
        },
    },
    "https_source_secret_ci": {
        "scheme": "https",
        "auth": "none",
        "title": "CI Artifact Viewer",
        "tagline": "TLS artifact mirror for build outputs and job metadata.",
        "theme": "ci",
        "endpoint": "/source/build_config.py",
        "flag_path": "source/build_config.py",
        "secret_source": True,
        "extra_facts": {"SourceCode(repo)": "ci_artifacts", "ExposedSecret(service)": "ci_viewer"},
        "files": {
            "public/builds/latest.txt": "build={digest}\nstatus=green\nartifact=web.tar.gz\n",
        },
    },
    "http_directory_traversal_docs": {
        "scheme": "http",
        "auth": "none",
        "title": "Documentation Library",
        "tagline": "Knowledge base articles and published operating procedures.",
        "theme": "docs",
        "endpoint": "/download?file=../private/flag.txt",
        "flag_path": "private/flag.txt",
        "directory_traversal": True,
        "extra_facts": {"Vulnerability(host, type)": "directory_traversal"},
        "files": {
            "public/docs/network-baseline.txt": "Baseline document {digest}\nReview cadence: quarterly.\n",
            "private/flag.txt": "Private documentation exception\nflag={flag}\n",
        },
    },
    "https_directory_traversal_backups": {
        "scheme": "https",
        "auth": "none",
        "title": "Backup Documentation Portal",
        "tagline": "TLS backup notes and operator documentation.",
        "theme": "backup",
        "endpoint": "/download?file=../private/restore-token.txt",
        "flag_path": "private/restore-token.txt",
        "directory_traversal": True,
        "extra_facts": {"Vulnerability(host, type)": "directory_traversal"},
        "files": {
            "public/docs/restore-runbook.txt": "Restore runbook {digest}\nUse approved backup windows.\n",
            "private/restore-token.txt": "Restore token note\nflag={flag}\n",
        },
    },
    "http_sqli_customer_lookup": {
        "scheme": "http",
        "auth": "none",
        "title": "Customer Lookup Desk",
        "tagline": "Support lookup for customer contacts and service tiers.",
        "theme": "customers",
        "endpoint": "/search?customer=' OR '1'='1",
        "flag_path": "private/sql-note.txt",
        "sqli": True,
        "extra_facts": {"Vulnerability(host, type)": "sql_injection"},
        "files": {
            "private/sql-note.txt": "Customer lookup hidden row flag={flag}\n",
        },
    },
    "https_sqli_invoice_portal": {
        "scheme": "https",
        "auth": "none",
        "title": "Invoice Review Portal",
        "tagline": "TLS invoice search for reconciliation and payment status.",
        "theme": "invoices",
        "endpoint": "/search?invoice=' OR '1'='1",
        "flag_path": "private/invoice-sql-note.txt",
        "sqli": True,
        "extra_facts": {"Vulnerability(host, type)": "sql_injection"},
        "files": {
            "private/invoice-sql-note.txt": "Invoice hidden row flag={flag}\n",
        },
    },
    "http_upload_file_drop": {
        "scheme": "http",
        "auth": "none",
        "title": "Vendor Intake Dropbox",
        "tagline": "Simple vendor document intake and review queue.",
        "theme": "dropbox",
        "endpoint": "/upload",
        "flag_path": "uploads/intake-note.txt",
        "upload": True,
        "extra_facts": {"UploadPrimitive(app)": "vendor_dropbox"},
        "files": {
            "uploads/intake-note.txt": "Vendor intake note {digest}\nflag={flag}\n",
            "public/templates/vendor-cover-sheet.txt": "Vendor name:\nContact:\nRequested service:\n",
        },
    },
    "https_basic_auth_reports": {
        "scheme": "https",
        "auth": "basic",
        "title": "Executive Reports Vault",
        "tagline": "TLS reports archive protected with HTTP Basic authentication.",
        "theme": "reports",
        "endpoint": "/reports",
        "flag_path": "private/reports/board-brief.txt",
        "extra_facts": {"WebAuthBypass(app)": "basic_reports"},
        "files": {
            "private/reports/board-brief.txt": "Board brief {digest}\nflag={flag}\n",
            "private/reports/q2-summary.csv": "metric,value\nrevenue,planned\nrisk,medium\n",
        },
    },
    "http_cookie_role_escalation": {
        "scheme": "http",
        "auth": "cookie_role",
        "title": "Project Management Console",
        "tagline": "Project dashboard with role-gated administrative notes.",
        "theme": "projects",
        "endpoint": "/admin",
        "flag_path": "private/admin-role-note.txt",
        "extra_facts": {"WebAuthBypass(app)": "role_cookie"},
        "files": {
            "private/admin-role-note.txt": "Role-gated project note {digest}\nflag={flag}\n",
        },
    },
    "https_token_debug_api": {
        "scheme": "https",
        "auth": "token",
        "title": "Device Telemetry API",
        "tagline": "TLS JSON API for device telemetry and debug metadata.",
        "theme": "api",
        "endpoint": "/api/profile?token=",
        "flag_path": "private/api-debug-note.txt",
        "token": True,
        "extra_facts": {"Token(service)": "telemetry_api", "APIKey(service)": "debug_api"},
        "files": {
            "private/api-debug-note.txt": "Telemetry debug note {digest}\nflag={flag}\n",
        },
    },
    "http_backup_archive_listing": {
        "scheme": "http",
        "auth": "none",
        "title": "Backup Archive Index",
        "tagline": "Publicly listed backup bundles for site recovery testing.",
        "theme": "archives",
        "endpoint": "/backups/site-backup.zip",
        "flag_path": "backups/site-backup.zip",
        "backup_archive": True,
        "extra_facts": {"BackupArchive(file)": "site-backup.zip", "ExposedSecret(service)": "backup_index"},
        "files": {
            "public/backups/README.txt": "Site recovery bundle index {digest}\n",
        },
    },
}


APP_TEMPLATE = r'''
import base64
import json
import os
import sqlite3
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

CONFIG = __CONFIG_JSON__
SITE_DIR = Path(__file__).resolve().parent / "site"
PUBLIC_DIR = SITE_DIR / "public"
PRIVATE_DIR = SITE_DIR / "private"
UPLOADS_DIR = SITE_DIR / "uploads"
SOURCE_DIR = SITE_DIR / "source"
BACKUPS_DIR = SITE_DIR / "backups"


def html_escape(value):
    return str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def page(title, body, status=200, extra_head=""):
    brand = html_escape(CONFIG.get("title") or "Portal")
    tagline = html_escape(CONFIG.get("tagline") or "Internal web service")
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html_escape(title)} - {brand}</title>
  <link rel=\"stylesheet\" href=\"/static/app.css\" />
  {extra_head}
</head>
<body>
  <header class=\"topbar\"><div><strong>{brand}</strong><span>{tagline}</span></div><nav><a href=\"/\">Home</a><a href=\"/downloads\">Files</a><a href=\"/status\">Status</a></nav></header>
  <main>{body}</main>
</body>
</html>""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "CoreTGWeb/1.0"

    def log_message(self, fmt, *args):
        return

    def send_body(self, content, status=200, content_type="text/html; charset=utf-8", headers=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for header_name, header_value in (headers or {}).items():
            self.send_header(header_name, header_value)
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location, headers=None):
        output_headers = {"Location": location}
        output_headers.update(headers or {})
        self.send_body(b"", status=302, content_type="text/plain", headers=output_headers)

    def cookie_map(self):
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                out[key.strip()] = value.strip()
        return out

    def is_form_authenticated(self):
        return self.cookie_map().get("session") == CONFIG.get("session_token")

    def require_basic(self):
        expected_raw = f"{CONFIG.get('login_user')}:{CONFIG.get('login_pass')}".encode("utf-8")
        expected = "Basic " + base64.b64encode(expected_raw).decode("ascii")
        if self.headers.get("Authorization") == expected:
            return True
        self.send_body(
            page("Authentication required", "<section class='panel'><h1>Authentication required</h1><p>Use the assigned report vault credentials.</p></section>"),
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="reports"'},
        )
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        auth_mode = CONFIG.get("auth") or "none"

        if path == "/static/app.css":
            return self.serve_file(PUBLIC_DIR / "css" / "app.css", "text/css; charset=utf-8")
        if path == "/login":
            return self.login_page()
        if path == "/logout":
            return self.redirect("/", {"Set-Cookie": "session=; Max-Age=0; Path=/"})
        if auth_mode == "form" and path in {"/dashboard", "/reports"} and not self.is_form_authenticated():
            return self.redirect("/login")
        if auth_mode == "basic" and path in {"/", "/reports", "/downloads"} and not self.require_basic():
            return

        if path == "/":
            return self.home_page()
        if path == "/dashboard":
            return self.dashboard_page()
        if path == "/downloads":
            return self.downloads_page()
        if path == "/download":
            return self.download_query(params)
        if path.startswith("/downloads/"):
            return self.serve_public_path(path.removeprefix("/downloads/"))
        if path == "/status" or path == "/status/maintenance":
            return self.status_page()
        if path == "/source/app.py" or path == "/source/build_config.py":
            filename = "build_config.py" if path.endswith("build_config.py") else "app.py"
            return self.serve_file(SOURCE_DIR / filename, "text/plain; charset=utf-8")
        if path == "/search":
            return self.search_page(params)
        if path == "/upload":
            return self.upload_page()
        if path == "/reports":
            return self.reports_page()
        if path == "/admin":
            return self.admin_page()
        if path == "/api/profile":
            return self.api_profile(params)
        if path == "/backups":
            return self.backups_page()
        if path.startswith("/backups/"):
            return self.serve_file(BACKUPS_DIR / path.removeprefix("/backups/"), "application/zip")
        return self.not_found()

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if parsed.path == "/login":
            fields = parse_qs(body)
            username = (fields.get("username") or [""])[0]
            password = (fields.get("password") or [""])[0]
            if username == CONFIG.get("login_user") and password == CONFIG.get("login_pass"):
                return self.redirect("/dashboard", {"Set-Cookie": f"session={CONFIG.get('session_token')}; Path=/; SameSite=Lax"})
            return self.send_body(page("Login failed", "<section class='panel'><h1>Login failed</h1><p>Check the assigned credentials and try again.</p><a class='button' href='/login'>Back</a></section>"), status=403)
        if parsed.path == "/upload":
            fields = parse_qs(body)
            note = (fields.get("note") or [""])[0]
            UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            safe_name = "submission.txt"
            (UPLOADS_DIR / safe_name).write_text(note[:4000], encoding="utf-8")
            return self.send_body(page("Upload queued", "<section class='panel'><h1>Upload queued</h1><p>Your vendor package was added to the intake queue.</p><a class='button' href='/upload'>Return</a></section>"))
        return self.not_found()

    def not_found(self):
        self.send_body(page("Not found", "<section class='panel'><h1>Not found</h1><p>The requested internal resource was not found.</p></section>"), status=404)

    def serve_file(self, path, content_type):
        path = Path(path)
        try:
            if not path.exists() or not path.is_file():
                return self.not_found()
            self.send_body(path.read_bytes(), content_type=content_type)
        except Exception:
            self.send_body(page("Read error", "<section class='panel'><h1>Read error</h1><p>The file could not be read.</p></section>"), status=500)

    def serve_public_path(self, requested):
        safe_name = Path(unquote(requested)).name
        self.serve_file(PUBLIC_DIR / "downloads" / safe_name, "text/plain; charset=utf-8")

    def home_page(self):
        cards = "".join([
            "<article><h3>Operations</h3><p>Review current service notes, owner assignments, and escalations.</p></article>",
            "<article><h3>Files</h3><p>Browse shared packets and published documentation for this node.</p></article>",
            "<article><h3>Status</h3><p>Check health summaries and maintenance windows.</p></article>",
        ])
        body = f"<section class='hero'><p class='eyebrow'>{html_escape(CONFIG.get('theme'))}</p><h1>{html_escape(CONFIG.get('title'))}</h1><p>{html_escape(CONFIG.get('tagline'))}</p></section><section class='grid'>{cards}</section><section class='panel'><h2>Quick links</h2>{self.quick_links()}</section>"
        if CONFIG.get("auth") == "cookie_role":
            body += "<section class='panel'><h2>Role state</h2><p>This browser starts with a low-privilege role cookie. Administrative notes require the admin role.</p><a class='button' href='/admin'>Open admin area</a></section>"
        return self.send_body(page("Home", body))

    def quick_links(self):
        links = ["<a class='button' href='/downloads'>Files</a>", "<a class='button' href='/status'>Status</a>"]
        if CONFIG.get("auth") == "form":
            links.append("<a class='button' href='/login'>Login</a>")
        if CONFIG.get("directory_traversal"):
            links.append("<a class='button' href='/download?file=network-baseline.txt'>Document download</a>")
        if CONFIG.get("sqli"):
            links.append("<a class='button' href='/search'>Search</a>")
        if CONFIG.get("upload"):
            links.append("<a class='button' href='/upload'>Upload</a>")
        if CONFIG.get("backup_archive"):
            links.append("<a class='button' href='/backups'>Backups</a>")
        if CONFIG.get("token"):
            links.append("<a class='button' href='/api/profile'>API profile</a>")
        return " ".join(links)

    def login_page(self):
        body = """<section class='login panel'><h1>Sign in</h1><form method='post' action='/login'><label>Username<input name='username' autocomplete='username'></label><label>Password<input name='password' type='password' autocomplete='current-password'></label><button type='submit'>Sign in</button></form></section>"""
        return self.send_body(page("Login", body))

    def dashboard_page(self):
        flag_rel = CONFIG.get("flag_path") or ""
        body = f"<section class='panel'><h1>Dashboard</h1><p>Welcome, {html_escape(CONFIG.get('login_user'))}. The current private review note is stored at <code>{html_escape(flag_rel)}</code>.</p><pre>{html_escape((SITE_DIR / flag_rel).read_text('utf-8', 'replace'))}</pre></section>"
        return self.send_body(page("Dashboard", body))

    def downloads_page(self):
        rows = []
        for file_path in sorted(PUBLIC_DIR.rglob("*")):
            if file_path.is_file() and file_path.name != "app.css":
                rel = file_path.relative_to(PUBLIC_DIR).as_posix()
                rows.append(f"<tr><td>{html_escape(rel)}</td><td><a href='/downloads/{html_escape(file_path.name)}'>download</a></td></tr>")
        body = "<section class='panel'><h1>Published files</h1><table><tr><th>File</th><th>Action</th></tr>" + "".join(rows) + "</table></section>"
        return self.send_body(page("Files", body))

    def download_query(self, params):
        requested = (params.get("file") or ["network-baseline.txt"])[0]
        if CONFIG.get("directory_traversal"):
            target = (PUBLIC_DIR / "docs" / requested).resolve()
            try:
                target.relative_to(SITE_DIR.resolve())
            except Exception:
                return self.send_body(page("Blocked", "<section class='panel'><h1>Blocked</h1><p>Path escaped the document root.</p></section>"), status=403)
        else:
            target = (PUBLIC_DIR / "docs" / Path(requested).name).resolve()
        return self.serve_file(target, "text/plain; charset=utf-8")

    def status_page(self):
        note = ""
        status_note = SITE_DIR / "public" / "status" / "maintenance-note.txt"
        if status_note.exists():
            note = f"<pre>{html_escape(status_note.read_text('utf-8', 'replace'))}</pre>"
        body = f"<section class='panel'><h1>Service status</h1><p>All monitored services are currently in review mode.</p>{note}</section>"
        return self.send_body(page("Status", body))

    def search_page(self, params):
        search_term = (params.get("customer") or params.get("invoice") or [""])[0]
        rows = []
        if search_term:
            database = sqlite3.connect(str(SITE_DIR / "app.db"))
            try:
                table_name = CONFIG.get("sql_table") or "records"
                statement = f"SELECT name, detail, note FROM {table_name} WHERE name = '{search_term}'"
                for record in database.execute(statement):
                    rows.append("<tr>" + "".join(f"<td>{html_escape(value)}</td>" for value in record) + "</tr>")
            except Exception as exc:
                rows.append(f"<tr><td colspan='3'>Query error: {html_escape(exc)}</td></tr>")
            finally:
                database.close()
        form = "<form class='search' method='get'><input name='customer' placeholder='customer or invoice id'><button>Search</button></form>"
        body = "<section class='panel'><h1>Lookup</h1>" + form + "<table><tr><th>Name</th><th>Detail</th><th>Note</th></tr>" + "".join(rows) + "</table></section>"
        return self.send_body(page("Lookup", body))

    def upload_page(self):
        flag_note = SITE_DIR / (CONFIG.get("flag_path") or "")
        preview = ""
        if flag_note.exists():
            preview = f"<pre>{html_escape(flag_note.read_text('utf-8', 'replace'))}</pre>"
        body = "<section class='panel'><h1>Vendor intake</h1><form method='post'><label>Package note<textarea name='note' rows='8'></textarea></label><button type='submit'>Queue upload</button></form></section><section class='panel'><h2>Queue note</h2>" + preview + "</section>"
        return self.send_body(page("Upload", body))

    def reports_page(self):
        report = SITE_DIR / (CONFIG.get("flag_path") or "")
        content = report.read_text("utf-8", "replace") if report.exists() else "No private report found."
        body = f"<section class='panel'><h1>Reports vault</h1><pre>{html_escape(content)}</pre></section>"
        return self.send_body(page("Reports", body))

    def admin_page(self):
        cookies = self.cookie_map()
        if cookies.get("role") != "admin":
            headers = {}
            if "role" not in cookies:
                headers["Set-Cookie"] = "role=user; Path=/; SameSite=Lax"
            body = "<section class='panel'><h1>Admin area</h1><p>Your current role is <code>user</code>. Administrative notes require <code>admin</code>.</p></section>"
            return self.send_body(page("Admin", body), headers=headers)
        note = SITE_DIR / (CONFIG.get("flag_path") or "")
        body = f"<section class='panel'><h1>Admin area</h1><pre>{html_escape(note.read_text('utf-8', 'replace'))}</pre></section>"
        return self.send_body(page("Admin", body))

    def api_profile(self, params):
        token = (params.get("token") or [CONFIG.get("user_token") or ""])[0]
        try:
            payload = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8"))
        except Exception:
            payload = {"role": "guest"}
        response = {"service": "telemetry", "role": payload.get("role"), "debug": CONFIG.get("api_key")}
        if payload.get("role") == "admin":
            response["flag"] = CONFIG.get("flag")
        self.send_body(json.dumps(response, indent=2).encode("utf-8"), content_type="application/json")

    def backups_page(self):
        rows = []
        for file_path in sorted(BACKUPS_DIR.glob("*")):
            if file_path.is_file():
                rows.append(f"<tr><td>{html_escape(file_path.name)}</td><td>{file_path.stat().st_size}</td><td><a href='/backups/{html_escape(file_path.name)}'>download</a></td></tr>")
        body = "<section class='panel'><h1>Backup archives</h1><table><tr><th>Archive</th><th>Bytes</th><th>Action</th></tr>" + "".join(rows) + "</table></section>"
        return self.send_body(page("Backups", body))


if __name__ == "__main__":
    port = int(os.environ.get("WEB_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if os.environ.get("WEB_TLS") == "1":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/app/certs/cert.pem", "/app/certs/key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
'''


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def _digest(*parts: str, length: int = 16) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:length]


def _format_template(value: str, mapping: dict[str, Any]) -> str:
    text = str(value)
    for key, replacement in mapping.items():
        text = text.replace("{" + str(key) + "}", str(replacement))
    return text


def _parse_credential(raw: Any, *, required: bool) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text:
        if required:
            raise ValueError('Credential(user, password) is required')
        return None
    if ":" not in text:
        raise ValueError('Credential(user, password) must use "user:password" format')
    username, password = text.split(":", 1)
    username = username.strip()
    password = password.strip()
    if not username or not password:
        raise ValueError('Credential(user, password) must include both user and password')
    return username, password


def _int_range(value: Any, default: int, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None and str(value).strip() != "" else default)
    except Exception as exc:
        raise ValueError(f"invalid {name}: {value}") from exc
    if number < minimum or number > maximum:
        raise ValueError(f"invalid {name}: {number}")
    return number


def _compute_flag(seed: str, node_name: str, variant_id: str, prefix: str) -> str:
    flag_prefix = (prefix or "FLAG").strip() or "FLAG"
    return f"{flag_prefix}{{{_digest(seed, node_name, variant_id, length=20)}}}"


def _write_css(site_dir: Path) -> None:
    css = """
:root{color-scheme:light;--ink:#17212b;--muted:#5c6b7a;--line:#d8e0e8;--panel:#ffffff;--bg:#f4f7fa;--accent:#226c8d;--accent2:#7b4e96}
*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5}.topbar{display:flex;justify-content:space-between;gap:24px;align-items:center;padding:16px 28px;background:#123044;color:white;box-shadow:0 2px 10px #0002}.topbar strong{display:block;font-size:18px}.topbar span{display:block;color:#c9d7e2;font-size:13px}.topbar a{color:white;text-decoration:none;margin-left:16px;font-size:14px}main{max-width:1120px;margin:0 auto;padding:30px 18px}.hero{background:linear-gradient(135deg,#eaf3f6,#f7f4fb);border:1px solid var(--line);border-radius:8px;padding:28px;margin-bottom:18px}.hero h1{font-size:34px;margin:4px 0 8px}.eyebrow{text-transform:uppercase;letter-spacing:.08em;color:var(--accent);font-size:12px;font-weight:700}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px}.grid article,.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px}.panel{margin-bottom:18px}.button,button{display:inline-block;border:0;border-radius:6px;background:var(--accent);color:white;text-decoration:none;padding:9px 12px;font-weight:650;margin:4px 6px 4px 0;cursor:pointer}button{font:inherit}table{border-collapse:collapse;width:100%;background:white}th,td{border-bottom:1px solid var(--line);padding:9px;text-align:left;vertical-align:top}th{font-size:13px;color:var(--muted);text-transform:uppercase}input,textarea{display:block;width:100%;padding:10px;border:1px solid var(--line);border-radius:6px;margin:5px 0 12px;background:white}label{font-weight:650;color:#2d3a45}pre{overflow:auto;background:#101820;color:#dce7ef;border-radius:7px;padding:14px}code{background:#eef3f7;border-radius:4px;padding:2px 5px}.login{max-width:460px;margin:30px auto}
""".strip() + "\n"
    _write_text(site_dir / "public" / "css" / "app.css", css)


def _create_database(site_dir: Path, variant: dict[str, Any], flag: str) -> None:
    database_path = site_dir / "app.db"
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database_path))
    try:
        table_name = "records"
        connection.execute("CREATE TABLE records (name TEXT, detail TEXT, note TEXT)")
        rows = [
            ("Acme Health", "standard support", "renewal in progress"),
            ("Northwind Traders", "premium support", "billing contact verified"),
            ("Contoso Retail", "regional", "shipment review open"),
            ("FLAG_ACCOUNT", "restricted", flag),
        ]
        connection.executemany("INSERT INTO records VALUES (?, ?, ?)", rows)
        connection.commit()
    finally:
        connection.close()
    variant["sql_table"] = table_name


def _create_backup_archive(site_dir: Path, flag: str, digest: str) -> None:
    backups_dir = site_dir / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    archive_path = backups_dir / "site-backup.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", f"Site backup {digest}\n")
        archive.writestr("config/settings.ini", "debug=false\nregion=west\n")
        archive.writestr("secrets/recovery-note.txt", f"recovery marker={flag}\n")


def _token_for(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _challenge_dockerfile() -> str:
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY app.py /app/app.py\n"
        "COPY site /app/site\n"
        "COPY certs /app/certs\n"
        "ENV WEB_PORT=8080\n"
        "EXPOSE 8080\n"
        "CMD [\"python\", \"/app/app.py\"]\n"
    )


def _challenge_compose(port: int, scheme: str, hostname: str) -> str:
    web_tls = "1" if scheme == "https" else "0"
    return (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    environment:\n"
        "      WEB_PORT: \"8080\"\n"
        f"      WEB_TLS: \"{web_tls}\"\n"
        "    ports:\n"
        f"      - \"{port}:8080\"\n"
        f"    hostname: {hostname}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HTTP/HTTPS node variant artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--variant", default=os.environ.get("WEB_VARIANT_ID", "http_public_file_drop"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    variant = dict(VARIANTS.get(variant_id) or {})
    if not variant:
        raise SystemExit(f"[validation error] unknown HTTP variant: {variant_id}")

    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        web_port = _int_range(cfg.get("web_port"), 8080, name="web_port", minimum=1, maximum=65535)
        auth_mode = str(variant.get("auth") or "none")
        parsed_credential = _parse_credential(cfg.get("Credential(user, password)"), required=auth_mode in {"form", "basic"})
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, variant_id, length=10)
    flag_value = _compute_flag(seed, node_name, variant_id, str(cfg.get("flag_prefix") or "FLAG"))
    if parsed_credential:
        login_user, login_pass = parsed_credential
    else:
        login_user = f"web_{digest[:6]}"
        login_pass = f"pw_{digest[6:10]}"

    site_dir = args.output / "site"
    certs_dir = args.output / "certs"
    site_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    _write_css(site_dir)

    mapping = {
        "digest": digest,
        "flag": flag_value,
        "user": login_user,
        "password": login_pass,
        "node": node_name,
    }
    for raw_path, raw_body in (variant.get("files") or {}).items():
        relative_path = _format_template(str(raw_path), mapping)
        body = _format_template(str(raw_body), mapping)
        _write_text(site_dir / relative_path, body)

    flag_path = _format_template(str(variant.get("flag_path") or "private/flag.txt"), mapping)
    if not (site_dir / flag_path).exists() and not variant.get("backup_archive"):
        _write_text(site_dir / flag_path, flag_value + "\n")

    if variant.get("secret_source"):
        source_name = "build_config.py" if "ci" in variant_id else "app.py"
        source_body = (
            f"# Internal source mirror {digest}\n"
            f"API_SECRET = 'key_{_digest(seed, variant_id, 'api', length=18)}'\n"
            f"RECOVERY_FLAG = '{flag_value}'\n"
            "def status():\n    return 'ok'\n"
        )
        _write_text(site_dir / "source" / source_name, source_body)
        flag_path = f"source/{source_name}"

    if variant.get("sqli"):
        _create_database(site_dir, variant, flag_value)

    if variant.get("backup_archive"):
        _create_backup_archive(site_dir, flag_value, digest)
        flag_path = "backups/site-backup.zip"

    user_token = _token_for({"sub": login_user, "role": "user", "seed": digest})
    admin_token = _token_for({"sub": login_user, "role": "admin", "seed": digest})
    api_key = f"api_{_digest(seed, node_name, variant_id, 'api', length=18)}"

    app_config = {
        **variant,
        "variant_id": variant_id,
        "flag": flag_value,
        "flag_path": flag_path,
        "login_user": login_user,
        "login_pass": login_pass,
        "session_token": _digest(seed, node_name, variant_id, "session", length=24),
        "user_token": user_token,
        "admin_token": admin_token,
        "api_key": api_key,
    }

    _write_text(args.output / "app.py", APP_TEMPLATE.replace("__CONFIG_JSON__", 'json.loads(r"""' + json.dumps(app_config, indent=2) + '""")'))
    _write_text(certs_dir / "key.pem", TLS_KEY, mode=0o600)
    _write_text(certs_dir / "cert.pem", TLS_CERT)
    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(args.output / "docker-compose.yml", _challenge_compose(web_port, str(variant.get("scheme") or "http"), variant_id.replace("_", "-")))

    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag_value,
        "FlagDelivery(mode)": "file" if not variant.get("secret_source") else "embedded",
        "FlagFile(path)": flag_path,
        "File(path)": "docker-compose.yml",
        "PortForward(host, port)": web_port,
        "Directory(host, path)": "site",
        "Endpoint(path)": str(variant.get("endpoint") or "/"),
        "Version(service)": f"{variant.get('scheme', 'http')}-stdlib",
    }
    if parsed_credential:
        outputs["Credential(user, password)"] = f"{login_user}:{login_pass}"
    if variant.get("token"):
        outputs["Token(service)"] = user_token
        outputs["APIKey(service)"] = api_key
    for fact_key, fact_value in (variant.get("extra_facts") or {}).items():
        outputs[str(fact_key)] = fact_value

    _write_text(
        args.output / "outputs.json",
        json.dumps({"generator_id": str(cfg.get("generator_id") or variant_id), "outputs": outputs}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()