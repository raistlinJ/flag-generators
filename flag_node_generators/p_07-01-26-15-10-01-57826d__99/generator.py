import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


GENERATOR_ID = "nfs_webdav_evidence_share"


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


def _flag(seed: str, node_name: str, prefix: str) -> str:
    return f"{(prefix or 'FLAG').strip() or 'FLAG'}{{{_digest(seed, node_name, GENERATOR_ID)}}}"


def _credential(raw: Any) -> tuple[str, str]:
    text = str(raw or "").strip()
    if ":" not in text:
        raise ValueError('Credential(user, password) must use "user:password" format')
    user, password = text.split(":", 1)
    user = user.strip()
    password = password.strip()
    if not user or not password:
        raise ValueError('Credential(user, password) must include both user and password')
    return user, password


def _port(value: Any, default: int) -> int:
    try:
        port = int(value or default)
    except Exception as exc:
        raise ValueError(f"invalid port: {value}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"invalid port: {port}")
    return port


def _challenge_dockerfile() -> str:
    return (
        "FROM debian:12-slim\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update \\\n"
        "  && apt-get install -y --no-install-recommends apache2 apache2-utils \\\n"
        "  && a2enmod dav dav_fs auth_basic headers \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n"
        "COPY dav.conf /etc/apache2/sites-available/000-default.conf\n"
        "COPY entrypoint.sh /entrypoint.sh\n"
        "RUN chmod +x /entrypoint.sh\n"
        "ENTRYPOINT [\"/entrypoint.sh\"]\n"
    )


def _entrypoint() -> str:
    return """#!/bin/sh
set -eu
htpasswd -bc /etc/apache2/dav.passwd "$DAV_USER" "$DAV_PASS"
exec apachectl -D FOREGROUND
"""


def _dav_conf() -> str:
    return """ServerName localhost
DAVLockDB /tmp/DAVLock
<VirtualHost *:80>
  DocumentRoot /var/www/html
  Alias /evidence /evidence
  <Directory /evidence>
    DAV On
    Options Indexes
    AuthType Basic
    AuthName "Evidence Repository"
    AuthUserFile /etc/apache2/dav.passwd
    Require valid-user
  </Directory>
</VirtualHost>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a password-required WebDAV evidence node")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    args = parser.parse_args()
    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        user, password = _credential(cfg.get("Credential(user, password)"))
        webdav_port = _port(cfg.get("webdav_port"), 8080)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, "evidence", length=10)
    flag_value = _flag(seed, node_name, str(cfg.get("flag_prefix") or "FLAG"))
    evidence = args.output / "evidence"
    flag_file = f"cases/case-{digest}/evidence-note.txt"

    _write_text(evidence / "manifest.txt", f"case=case-{digest}\nowner={user}\npriority=medium\n")
    _write_text(evidence / "cases" / f"case-{digest}" / "chain-of-custody.txt", "2026-05-19 received by incident response\n2026-05-20 exported for review\n")
    _write_text(evidence / flag_file, f"Evidence note {digest}\nRecovered marker: {flag_value}\n")
    _write_text(evidence / "decoys" / "camera-index.csv", "camera,timestamp,status\nlobby,2026-05-19T09:33:02Z,archived\n")

    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(args.output / "dav.conf", _dav_conf())
    _write_text(args.output / "entrypoint.sh", _entrypoint(), mode=0o755)
    _write_text(
        args.output / "docker-compose.yml",
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    ports:\n"
        f"      - \"{webdav_port}:80\"\n"
        "    environment:\n"
        f"      DAV_USER: {json.dumps(user)}\n"
        f"      DAV_PASS: {json.dumps(password)}\n"
        "    volumes:\n"
        "      - ./evidence:/evidence\n"
        "    hostname: evidence-webdav\n",
    )
    _write_text(
        args.output / "outputs.json",
        json.dumps(
            {
                "generator_id": str(cfg.get("generator_id") or GENERATOR_ID),
                "outputs": {
                    "Flag(flag_id)": flag_value,
                    "FlagDelivery(mode)": "file",
                    "FlagFile(path)": flag_file,
                    "Credential(user, password)": f"{user}:{password}",
                    "File(path)": "docker-compose.yml",
                    "PortForward(host, port)": webdav_port,
                    "Directory(host, path)": "evidence",
                },
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()