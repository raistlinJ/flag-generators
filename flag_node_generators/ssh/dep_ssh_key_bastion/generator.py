import argparse
import hashlib
import html
import json
import os
import urllib.parse
from pathlib import Path
from typing import Any


VARIANTS: dict[str, dict[str, Any]] = {
    "dep_api_key_admin_endpoint": {
        "requires": "APIKey(service)",
        "mode": "api_key",
        "title": "API Key Admin Export",
        "endpoint": "/api/admin/export",
        "prompt": "Send the prior API key as X-API-Key or api_key to unlock the admin export.",
        "extra_outputs": {"Endpoint(path)": "/api/admin/export", "Version(service)": "dependency-api/1.0"},
    },
    "dep_ticket_attachment_portal": {
        "requires": "Ticket(id)",
        "mode": "ticket",
        "title": "Support Ticket Attachment Portal",
        "endpoint": "/support/attachment",
        "prompt": "Submit the ticket id from the previous challenge as ticket to retrieve the attachment.",
        "extra_outputs": {"Credential(user, password)": "ticket_{digest}:TicketPass-{short}!"},
    },
    "dep_file_parser_console": {
        "requires": "File(path)",
        "mode": "file_path",
        "title": "File Parser Secret Extractor",
        "endpoint": "/parser/result",
        "prompt": "Provide the prior file path as file or X-File-Path so the parser can extract the next secret.",
        "extra_outputs": {"APIKey(service)": "ak_file_{digest}", "Checksum(sha256)": "{checksum}"},
    },
    "dep_checksum_evidence_gate": {
        "requires": "Checksum(sha256)",
        "mode": "checksum",
        "title": "Checksum Evidence Gate",
        "endpoint": "/evidence/download",
        "prompt": "Present the previous sha256 as sha256 or X-Checksum-SHA256 to unlock the evidence download.",
        "extra_outputs": {"Endpoint(path)": "/evidence/download"},
    },
    "dep_endpoint_hidden_followup": {
        "requires": "Endpoint(path)",
        "mode": "endpoint",
        "title": "Hidden Endpoint Follow-Up",
        "endpoint_from_input": True,
        "fallback_endpoint": "/internal/hidden-followup",
        "prompt": "Use the endpoint path discovered in the previous challenge on this node.",
        "extra_outputs": {"Version(service)": "hidden-followup/{short}", "WebAuthBypass(app)": "endpoint-bypass-{short}"},
    },
    "dep_version_exploit_selector": {
        "requires": "Version(service)",
        "mode": "version",
        "title": "Version-Specific Exploit Selector",
        "endpoint": "/exploit/selector",
        "prompt": "Provide the previous service version as version or X-Service-Version to choose the exploit path.",
        "extra_outputs": {"Endpoint(path)": "/exploit/selector", "WebAuthBypass(app)": "version-bypass-{short}"},
    },
    "dep_port_forward_pivot": {
        "requires": "PortForward(host, port)",
        "mode": "port_forward",
        "title": "Internal Service Pivot",
        "endpoint": "/pivot/console",
        "prompt": "Use the prior port-forward mapping as pivot or X-Port-Forward to reach the internal console.",
        "extra_outputs": {"Endpoint(path)": "/pivot/console"},
    },
    "dep_webauth_bypass_console": {
        "requires": "WebAuthBypass(app)",
        "mode": "webauth_bypass",
        "title": "Bypass Token Admin Console",
        "endpoint": "/admin/bypass",
        "prompt": "Send the prior bypass marker as bypass or X-Auth-Bypass to expose the admin console.",
        "extra_outputs": {"APIKey(service)": "ak_bypass_{digest}"},
    },
    "dep_ssh_key_bastion": {
        "requires": "SSHPrivateKey(path)",
        "mode": "ssh_key",
        "title": "SSH Key Bastion Follow-Up",
        "endpoint": "/bastion/session",
        "prompt": "Provide the prior SSH private key path as key_path or X-SSH-Key-Path to open the bastion session note.",
        "extra_outputs": {"Credential(user)": "bastion_{short}"},
    },
}


APP_TEMPLATE = r'''import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG = __CONFIG_JSON__


def _html_page(title, body):
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<title>" + html.escape(title) + "</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:3rem auto;line-height:1.5}"
            "code{background:#f1f3f5;padding:.15rem .3rem;border-radius:4px}</style></head><body>"
            + body + "</body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _send(self, status, content, content_type="text/html; charset=utf-8"):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _query(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query)

    def _header(self, name):
        return str(self.headers.get(name) or "").strip()

    def _values_for_mode(self, query):
        mode = CONFIG.get("mode")
        lookup = {
            "api_key": ["api_key", "key"],
            "ticket": ["ticket", "ticket_id"],
            "file_path": ["file", "path"],
            "checksum": ["sha256", "checksum"],
            "version": ["version", "service_version"],
            "port_forward": ["pivot", "port_forward", "port"],
            "webauth_bypass": ["bypass", "token"],
            "ssh_key": ["key_path", "key"],
        }
        headers = {
            "api_key": ["X-API-Key"],
            "ticket": ["X-Ticket-ID"],
            "file_path": ["X-File-Path"],
            "checksum": ["X-Checksum-SHA256"],
            "version": ["X-Service-Version"],
            "port_forward": ["X-Port-Forward"],
            "webauth_bypass": ["X-Auth-Bypass"],
            "ssh_key": ["X-SSH-Key-Path"],
        }
        values = []
        for key in lookup.get(mode, []):
            values.extend(query.get(key, []))
        for key in headers.get(mode, []):
            values.append(self._header(key))
        return [str(value or "").strip() for value in values if str(value or "").strip()]

    def _authorized(self, path, query):
        expected = str(CONFIG.get("required_value") or "").strip()
        if CONFIG.get("mode") == "endpoint":
            return path == CONFIG.get("endpoint")
        return expected in self._values_for_mode(query)

    def do_GET(self):
        path, query = self._query()
        if path in {"/", "/health"}:
            body = ("<h1>" + html.escape(CONFIG.get("title") or "Dependency Consumer") + "</h1>"
                    "<p>" + html.escape(CONFIG.get("prompt") or "Use the prior artifact to continue.") + "</p>"
                    "<p>Challenge endpoint: <code>" + html.escape(CONFIG.get("endpoint") or "/") + "</code></p>"
                    "<p>Required artifact: <code>" + html.escape(CONFIG.get("required_fact") or "") + "</code></p>")
            self._send(200, _html_page(CONFIG.get("title") or "Dependency Consumer", body))
            return
        if path == CONFIG.get("endpoint"):
            if not self._authorized(path, query):
                body = "<h1>Artifact Required</h1><p>" + html.escape(CONFIG.get("prompt") or "Missing artifact.") + "</p>"
                self._send(403, _html_page("Artifact Required", body))
                return
            flag_path = Path("/app") / str(CONFIG.get("flag_path") or "site/private/flag.txt")
            try:
                flag_text = flag_path.read_text(encoding="utf-8").strip()
            except Exception:
                flag_text = str(CONFIG.get("flag") or "")
            body = "<h1>Unlocked</h1><p>Flag: <code>" + html.escape(flag_text) + "</code></p>"
            self._send(200, _html_page("Unlocked", body))
            return
        self._send(404, _html_page("Not Found", "<h1>Not Found</h1>"))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def _digest(*parts: str, length: int = 16) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:length]


def _flag(seed: str, node_name: str, variant_id: str, prefix: str) -> str:
    clean_prefix = (prefix or "FLAG").strip() or "FLAG"
    return f"{clean_prefix}{{{_digest(seed, node_name, variant_id, length=20)}}}"


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value).strip()


def _require_value(cfg: dict[str, Any], fact_name: str) -> str:
    value = _stringify(cfg.get(fact_name))
    if not value:
        raise SystemExit(f"[validation error] {fact_name} is required")
    return value


def _int_range(value: Any, default: int, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None and str(value).strip() != "" else default)
    except Exception as exc:
        raise SystemExit(f"[validation error] invalid {name}: {value}") from exc
    if number < minimum or number > maximum:
        raise SystemExit(f"[validation error] invalid {name}: {number}")
    return number


def _safe_endpoint(raw: Any, fallback: str) -> str:
    text = str(raw or "").strip() or fallback
    try:
        parsed = urllib.parse.urlparse(text)
        if parsed.path:
            text = parsed.path
    except Exception:
        pass
    if not text.startswith("/"):
        text = "/" + text
    clean = []
    for char in text.split("?", 1)[0]:
        clean.append(char if char.isalnum() or char in "/._-" else "-")
    endpoint = "".join(clean).replace("//", "/").rstrip("/")
    return endpoint or fallback


def _challenge_dockerfile() -> str:
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY app.py /app/app.py\n"
        "COPY site /app/site\n"
        "EXPOSE 8080\n"
        "CMD [\"python\", \"/app/app.py\"]\n"
    )


def _challenge_compose(port: int, hostname: str) -> str:
    return (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    ports:\n"
        f"      - \"{port}:8080\"\n"
        f"    hostname: {hostname}\n"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_outputs(templates: dict[str, str], context: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in templates.items():
        out[str(key)] = str(value).format(**context)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate dependency-consumer node artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--variant", default=os.environ.get("DEPENDENCY_CONSUMER_VARIANT_ID", "dep_ssh_key_bastion"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    variant = VARIANTS.get(variant_id)
    if not variant:
        raise SystemExit(f"[validation error] unknown dependency consumer variant: {variant_id}")

    cfg = _read_json(args.input / "config.json")
    seed = str(cfg.get("seed") or "").strip()
    node_name = str(cfg.get("node_name") or "").strip()
    if not seed or not node_name:
        raise SystemExit("[validation error] seed and node_name are required")

    required_fact = str(variant.get("requires") or "").strip()
    required_value = _require_value(cfg, required_fact)
    digest = _digest(seed, node_name, variant_id, required_value, length=16)
    short = digest[:8]
    default_port = 18080 + (int(digest[:4], 16) % 1200)
    web_port = _int_range(cfg.get("web_port"), default_port, name="web_port", minimum=1, maximum=65535)
    flag_value = _flag(seed, node_name, variant_id, str(cfg.get("flag_prefix") or "FLAG"))
    endpoint = _safe_endpoint(required_value, str(variant.get("fallback_endpoint") or "/challenge")) if variant.get("endpoint_from_input") else _safe_endpoint(variant.get("endpoint"), "/challenge")
    flag_path = f"site/private/{variant_id}-{short}.txt"
    flag_file = args.output / flag_path

    note = (
        f"Dependency consumer: {variant.get('title')}\n"
        f"Required artifact: {required_fact}\n"
        f"Artifact digest: {_digest(required_value, length=12)}\n"
        f"Endpoint: {endpoint}\n"
        f"Flag: {flag_value}\n"
    )
    _write_text(flag_file, note)
    _write_text(args.output / "site" / "public" / "README.txt", f"{variant.get('title')}\n{variant.get('prompt')}\n")

    app_config = {
        "variant_id": variant_id,
        "title": str(variant.get("title") or variant_id),
        "mode": str(variant.get("mode") or "value"),
        "prompt": str(variant.get("prompt") or "Use the prior artifact to continue."),
        "required_fact": required_fact,
        "required_value": required_value,
        "endpoint": endpoint,
        "flag": flag_value,
        "flag_path": flag_path,
    }
    _write_text(args.output / "app.py", APP_TEMPLATE.replace("__CONFIG_JSON__", 'json.loads(r"""' + json.dumps(app_config, indent=2) + '""")'))
    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(args.output / "docker-compose.yml", _challenge_compose(web_port, variant_id.replace("_", "-")))

    checksum = _sha256_file(flag_file)
    context = {
        "digest": digest,
        "short": short,
        "checksum": checksum,
        "endpoint": endpoint,
        "flag": flag_value,
        "port": web_port,
        "node": node_name,
    }
    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag_value,
        "FlagDelivery(mode)": "file",
        "FlagFile(path)": flag_path,
        "File(path)": "docker-compose.yml",
        "Checksum(sha256)": checksum,
        "PortForward(host, port)": web_port,
        "Directory(host, path)": "site",
        "Endpoint(path)": endpoint,
        "Version(service)": f"dependency-consumer/{short}",
    }
    outputs.update(_format_outputs(dict(variant.get("extra_outputs") or {}), context))

    _write_text(
        args.output / "outputs.json",
        json.dumps({"schema_version": 1, "generator_id": str(cfg.get("generator_id") or variant_id), "outputs": outputs}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()