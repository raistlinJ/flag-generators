import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


GENERATOR_ID = "nfs_legacy_nfs3_share"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def _ganesha_conf() -> str:
    return (
        "NFS_Core_Param {\n"
        "  Protocols = 3,4;\n"
        "  Enable_NLM = false;\n"
        "  Enable_RQUOTA = false;\n"
        "  Mount_Path_Pseudo = true;\n"
        "}\n\n"
        "DBus {\n  Enabled = false;\n}\n\n"
        "EXPORT {\n"
        "  Export_Id = 1;\n"
        "  Path = /exports;\n"
        "  Pseudo = /legacy;\n"
        "  Access_Type = RW;\n"
        "  Squash = no_root_squash;\n"
        "  SecType = sys;\n"
        "  Protocols = 3,4;\n"
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
    parser = argparse.ArgumentParser(description="Generate a legacy NFS engineering share node")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    args = parser.parse_args()
    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        nfs_port = _port(cfg.get("nfs_port"), 2049)
        mountd_port = _port(cfg.get("mountd_port"), 20048)
        rpcbind_port = _port(cfg.get("rpcbind_port"), 11111)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, "legacy", length=10)
    flag_value = _flag(seed, node_name, str(cfg.get("flag_prefix") or "FLAG"))
    exports = args.output / "exports"
    flag_file = f"engineering/maintenance/window-{digest}.txt"

    _write_text(exports / "README.txt", "Legacy engineering export. Expect old mount options and noisy archive content.\n")
    _write_text(exports / "engineering" / "rack-map.txt", f"rack-a uplink sw-{digest[:4]}\nrack-b storage array legacy-nfs\n")
    _write_text(exports / "engineering" / "build-log.txt", "make all completed with warnings\nold automation retained for audit parity\n")
    _write_text(exports / flag_file, f"Maintenance exception {digest}\nflag={flag_value}\n")
    _write_text(exports / "drawings" / "plant-floor-links.csv", "link,device,status\nA1,agg-01,active\nB7,legacy-nfs,unknown\n")

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
        f"      - \"{rpcbind_port}:111\"\n"
        f"      - \"{nfs_port}:2049\"\n"
        f"      - \"{mountd_port}:20048\"\n"
        "    volumes:\n"
        "      - ./exports:/exports\n"
        "      - ./ganesha.conf:/etc/ganesha/ganesha.conf:ro\n"
        "    hostname: legacy-nfs\n",
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
                    "MountdPort(port)": mountd_port,
                    "RpcbindPort(port)": rpcbind_port,
                    "Directory(host, path)": "/legacy",
                },
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()