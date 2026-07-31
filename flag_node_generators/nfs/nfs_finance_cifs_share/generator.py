import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


GENERATOR_ID = "nfs_finance_cifs_share"


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
        "  && apt-get install -y --no-install-recommends samba tini \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n"
        "COPY smb.conf /etc/samba/smb.conf\n"
        "COPY entrypoint.sh /entrypoint.sh\n"
        "RUN chmod +x /entrypoint.sh\n"
        "ENTRYPOINT [\"/usr/bin/tini\", \"--\", \"/entrypoint.sh\"]\n"
    )


def _entrypoint() -> str:
    return """#!/bin/sh
set -eu
useradd -M -s /usr/sbin/nologin "$SHARE_USER" 2>/dev/null || true
printf '%s\n%s\n' "$SHARE_PASS" "$SHARE_PASS" | smbpasswd -s -a "$SHARE_USER" >/dev/null
smbpasswd -e "$SHARE_USER" >/dev/null
exec smbd -F --no-process-group -s /etc/samba/smb.conf
"""


def _smb_conf(share_name: str, user: str) -> str:
    return f"""[global]
   server role = standalone server
   map to guest = never
   disable spoolss = yes
   load printers = no
   printing = bsd
   smb ports = 445

[{share_name}]
   path = /share
   read only = yes
   browseable = yes
    valid users = {user}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a password-required CIFS finance share node")
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
        smb_port = _port(cfg.get("smb_port"), 1445)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, "finance", length=10)
    flag_value = _flag(seed, node_name, str(cfg.get("flag_prefix") or "FLAG"))
    share = args.output / "share"
    flag_file = f"quarterly/reconciliations/recon-{digest}.csv"

    _write_text(share / "README.txt", "Finance department shared drive. Access requires assigned SMB credentials.\n")
    _write_text(share / "quarterly" / "q2_vendor_summary.csv", "vendor,invoice,total\nNorthwind,1042,18340.55\nContoso,1088,9412.10\n")
    _write_text(share / "quarterly" / "payroll_notes.txt", f"temporary reviewer={user}\narchive batch={digest}\n")
    _write_text(share / flag_file, f"account,period,status,marker\n7300,2026-Q2,reconciled,{flag_value}\n")
    _write_text(share / "decoys" / f"journal-{digest}.csv", "id,comment\n1001,parking accrual adjusted\n1002,duplicate vendor row removed\n")

    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(args.output / "smb.conf", _smb_conf("finance", user))
    _write_text(args.output / "entrypoint.sh", _entrypoint(), mode=0o755)
    _write_text(
        args.output / "docker-compose.yml",
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    ports:\n"
        f"      - \"{smb_port}:445\"\n"
        "    environment:\n"
        f"      SHARE_USER: {json.dumps(user)}\n"
        f"      SHARE_PASS: {json.dumps(password)}\n"
        "    volumes:\n"
        "      - ./share:/share:ro\n"
        "    hostname: finance-share\n",
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
                    "PortForward(host, port)": smb_port,
                    "Directory(host, path)": "finance",
                },
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()