import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


GENERATOR_ID = "nfs_readonly_audit_share"


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


def _port(value: Any, default: int) -> int:
    try:
        port = int(value or default)
    except Exception as exc:
        raise ValueError(f"invalid port: {value}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"invalid port: {port}")
    return port


def _common_config(cfg: dict[str, Any]) -> tuple[str, str, str, int]:
    seed = str(cfg.get("seed") or "").strip()
    node_name = str(cfg.get("node_name") or "").strip()
    if not seed:
        raise ValueError("Missing required input: seed")
    if not node_name:
        raise ValueError("Missing required input: node_name")
    return seed, node_name, str(cfg.get("flag_prefix") or "FLAG"), _port(cfg.get("nfs_port"), 2049)


def _ganesha_conf(pseudo: str, access_type: str = "RO") -> str:
    return (
        "NFS_Core_Param {\n"
        "  Protocols = 4;\n"
        "  Enable_NLM = false;\n"
        "  Enable_RQUOTA = false;\n"
        "}\n\n"
        "DBus {\n"
        "  Enabled = false;\n"
        "}\n\n"
        "EXPORT {\n"
        "  Export_Id = 1;\n"
        "  Path = /exports;\n"
        f"  Pseudo = {pseudo};\n"
        f"  Access_Type = {access_type};\n"
        "  Squash = no_root_squash;\n"
        "  SecType = sys;\n"
        "  Protocols = 4;\n"
        "  Transports = TCP;\n"
        "  FSAL {\n"
        "    Name = VFS;\n"
        "  }\n"
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
    parser = argparse.ArgumentParser(description="Generate a read-only NFS audit share node")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    args = parser.parse_args()
    cfg = _read_json(args.input / "config.json")
    try:
        seed, node_name, flag_prefix, nfs_port = _common_config(cfg)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, "audit", length=10)
    flag_value = _flag(seed, node_name, flag_prefix)
    exports = args.output / "exports"
    flag_file = f"audit/review-note-{digest}.md"

    _write_text(exports / "README.txt", "Quarterly network audit export. Treat this share as read-only evidence.\n")
    _write_text(exports / "logs" / f"access-{digest}.log", "2026-05-18T08:21:10Z backup-vpn accepted auditor session\n2026-05-18T08:47:33Z acl check completed\n")
    _write_text(exports / "configs" / "access-switch-backup.cfg", f"hostname access-{digest}\nservice timestamps log datetime msec\nlogging buffered 64000\n")
    _write_text(exports / flag_file, f"# Audit Finding {digest}\n\nEvidence marker: {flag_value}\n\nFollow-up: reconcile stale export permissions.\n")

    _write_text(args.output / "ganesha.conf", _ganesha_conf("/audit", "RO"))
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
        "    hostname: nfs-audit\n",
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
                    "File(path)": "docker-compose.yml",
                    "PortForward(host, port)": nfs_port,
                    "Directory(host, path)": "/audit",
                },
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()