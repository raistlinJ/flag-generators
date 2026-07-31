import argparse
import hashlib
import json
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Any


GENERATOR_ID = "nfs_backup_archive_passphrase"


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


def _xor_hex(plaintext: str, password: str) -> str:
    data = plaintext.encode("utf-8")
    key = hashlib.sha256(password.encode("utf-8", "replace")).digest()
    out = bytes(byte ^ key[idx % len(key)] for idx, byte in enumerate(data))
    return out.hex()


def _unlock_script() -> str:
    return """#!/usr/bin/env python3
import hashlib
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: unlock_vault.py <vault.enc> <passphrase>')

raw = bytes.fromhex(open(sys.argv[1], 'r', encoding='utf-8').read().strip())
key = hashlib.sha256(sys.argv[2].encode('utf-8', 'replace')).digest()
plain = bytes(byte ^ key[idx % len(key)] for idx, byte in enumerate(raw))
print(plain.decode('utf-8', 'replace'))
"""


def _ganesha_conf() -> str:
    return (
        "NFS_Core_Param {\n  Protocols = 4;\n  Enable_NLM = false;\n  Enable_RQUOTA = false;\n}\n\n"
        "DBus {\n  Enabled = false;\n}\n\n"
        "EXPORT {\n"
        "  Export_Id = 1;\n"
        "  Path = /exports;\n"
        "  Pseudo = /backups;\n"
        "  Access_Type = RO;\n"
        "  Squash = no_root_squash;\n"
        "  SecType = sys;\n"
        "  Protocols = 4;\n"
        "  Transports = TCP;\n"
        "  FSAL {\n    Name = VFS;\n  }\n"
        "}\n"
    )


def _challenge_dockerfile() -> str:
    return (
        "FROM ubuntu:22.04\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update \\\n"
        "  && apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind netbase iproute2 \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a passphrase-gated NFS backup node")
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
        nfs_port = _port(cfg.get("nfs_port"), 2049)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    flag_value = _flag(seed, node_name, str(cfg.get("flag_prefix") or "FLAG"))
    digest = _digest(seed, node_name, "backup", length=10)
    exports = args.output / "exports"
    vault_rel = f"recovery/vault-{digest}.enc"
    archive_rel = f"snapshots/fileserver-{digest}.tar.gz"

    recovery_note = f"Recovered backup control note\noperator={user}\nflag={flag_value}\n"
    _write_text(exports / vault_rel, _xor_hex(recovery_note, password) + "\n")
    _write_text(exports / "tools" / "unlock_vault.py", _unlock_script(), mode=0o755)
    _write_text(exports / "README_RECOVERY.txt", "Vault files are encrypted with the assigned recovery credential password.\n")
    _write_text(exports / "manifests" / f"backup-index-{digest}.txt", f"snapshot={archive_rel}\nvault={vault_rel}\nowner={user}\n")

    archive_path = exports / archive_rel
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, body in {
            "etc/exports.previous": "/srv/backups 10.0.0.0/8(ro,sync)\n",
            "var/log/backup-agent.log": f"job {digest} completed with warnings\n",
            "README.txt": "Routine filesystem snapshot. Sensitive recovery notes are stored separately.\n",
        }.items():
            payload = body.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))

    _write_text(args.output / "ganesha.conf", _ganesha_conf())
    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(
        args.output / "docker-compose.yml",
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    command: ['sh','-lc','rpcbind -w -f & ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity']\n"
        "    privileged: true\n"
        "    ports:\n"
        f"      - \"{nfs_port}:2049\"\n"
        "    volumes:\n"
        "      - ./exports:/exports:ro\n"
        "      - ./ganesha.conf:/etc/ganesha/ganesha.conf:ro\n"
        "    hostname: nfs-backups\n",
    )
    _write_text(
        args.output / "outputs.json",
        json.dumps(
            {
                "generator_id": str(cfg.get("generator_id") or GENERATOR_ID),
                "outputs": {
                    "Flag(flag_id)": flag_value,
                    "FlagDelivery(mode)": "embedded",
                    "FlagFile(path)": vault_rel,
                    "Credential(user, password)": f"{user}:{password}",
                    "File(path)": "docker-compose.yml",
                    "PortForward(host, port)": nfs_port,
                    "Directory(host, path)": "/backups",
                },
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()