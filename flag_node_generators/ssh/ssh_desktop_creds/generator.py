import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _derive_pair(seed: str, namespace: str) -> tuple[str, str]:
    digest = hashlib.sha256(f"{seed}|{namespace}".encode("utf-8", "replace")).hexdigest()
    user = f"user_{digest[:6]}"
    pw = f"pw_{digest[6:14]}"
    return user, pw


def _parse_credential_pair(raw: Any) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text or ":" not in text:
        return None
    user, pw = text.split(":", 1)
    user = user.strip()
    pw = pw.strip()
    if not user or not pw:
        return None
    return user, pw


def _compute_flag(seed: str, node_name: str, flag_prefix: str) -> str:
    base = f"{seed}|{node_name}|ssh-desktop".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:20]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SSH desktop credentials node artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    return parser.parse_args()


def _validate_inputs(cfg: Dict[str, Any]) -> None:
    """Validate all input values and raise ValueError on invalid input."""
    seed = str(cfg.get("seed") or "").strip()
    if not seed:
        raise ValueError("Missing required input: seed (non-empty string required)")

    node_name = str(cfg.get("node_name") or "").strip()
    if not node_name:
        raise ValueError("Missing required input: node_name (non-empty string required)")

    ssh_port_raw = cfg.get("ssh_port")
    if ssh_port_raw is not None:
        try:
            port = int(ssh_port_raw)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid ssh_port: {port} (must be 1-65535)")
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid ssh_port: {ssh_port_raw} (must be integer 1-65535)") from exc

    flag_prefix_raw = cfg.get("flag_prefix")
    if flag_prefix_raw is not None:
        prefix = str(flag_prefix_raw).strip()
        if prefix and not prefix.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Invalid flag_prefix: {prefix} (alphanumeric, underscore, hyphen only)")

    cred_raw = cfg.get("Credential(user, password)")
    if not cred_raw:
        raise ValueError('Missing required input: Credential(user, password) (format: "user:password")')
    parsed = _parse_credential_pair(cred_raw)
    if not parsed:
        raise ValueError(f'Invalid Credential(user, password): {cred_raw} (expected format "user:password")')


def main() -> None:
    args = _parse_args()
    inputs_dir = args.input
    outputs_dir = args.output

    cfg = _read_json(inputs_dir / "config.json")

    try:
        _validate_inputs(cfg)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    seed = str(cfg.get("seed"))
    node_name = str(cfg.get("node_name"))
    ssh_port = int(cfg.get("ssh_port") or 2222)
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG")

    login_user, login_pass = _parse_credential_pair(cfg.get("Credential(user, password)"))
    desktop_user, desktop_pass = _derive_pair(seed, f"{node_name}|desktop")

    login_cred = f"{login_user}:{login_pass}"
    desktop_cred = f"{desktop_user}:{desktop_pass}"

    flag_value = _compute_flag(seed, node_name, flag_prefix)

    desktop_dir = outputs_dir / "desktop"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    _write_text(desktop_dir / "username_password.txt", desktop_cred + "\n")
    _write_text(desktop_dir / "flag.txt", flag_value + "\n")

    entrypoint_text = (
        "#!/bin/sh\n"
        "set -eu\n"
        "LOGIN_USER=\"${LOGIN_USER:-player}\"\n"
        "LOGIN_PASS=\"${LOGIN_PASS:-playerpass}\"\n"
        "\n"
        "if ! id \"$LOGIN_USER\" >/dev/null 2>&1; then\n"
        "  useradd -m -s /bin/bash \"$LOGIN_USER\"\n"
        "fi\n"
        "echo \"$LOGIN_USER:$LOGIN_PASS\" | chpasswd\n"
        "\n"
        "mkdir -p \"/home/$LOGIN_USER/Desktop\"\n"
        "if [ -d /challenge/desktop ]; then\n"
        "  cp -f /challenge/desktop/* \"/home/$LOGIN_USER/Desktop/\" 2>/dev/null || true\n"
        "fi\n"
        "chown -R \"$LOGIN_USER:$LOGIN_USER\" \"/home/$LOGIN_USER/Desktop\"\n"
        "chmod 700 \"/home/$LOGIN_USER\" || true\n"
        "chmod 755 \"/home/$LOGIN_USER/Desktop\" || true\n"
        "chmod 600 \"/home/$LOGIN_USER/Desktop/username_password.txt\" || true\n"
        "\n"
        "sed -ri 's/^#?PasswordAuthentication\\s+.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\n"
        "sed -ri 's/^#?PermitRootLogin\\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
        "grep -q '^UsePAM' /etc/ssh/sshd_config && sed -ri 's/^UsePAM\\s+.*/UsePAM no/' /etc/ssh/sshd_config || echo 'UsePAM no' >> /etc/ssh/sshd_config\n"
        "mkdir -p /var/run/sshd\n"
        "SSHD_PID=\"\"\n"
        "term_handler() {\n"
        "  if [ -n \"$SSHD_PID\" ] && kill -0 \"$SSHD_PID\" 2>/dev/null; then\n"
        "    kill -TERM \"$SSHD_PID\" 2>/dev/null || true\n"
        "    wait \"$SSHD_PID\" 2>/dev/null || true\n"
        "  fi\n"
        "  exit 143\n"
        "}\n"
        "trap term_handler TERM INT\n"
        "/usr/sbin/sshd -D -e &\n"
        "SSHD_PID=\"$!\"\n"
        "wait \"$SSHD_PID\"\n"
    )
    _write_text(outputs_dir / "entrypoint.sh", entrypoint_text)

    dockerfile_text = (
        "FROM ubuntu:22.04\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update \\\n"
        "  && apt-get install -y --no-install-recommends openssh-server ca-certificates passwd \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n"
        "COPY entrypoint.sh /entrypoint.sh\n"
        "RUN chmod +x /entrypoint.sh\n"
        "EXPOSE 22\n"
        "CMD [\"/entrypoint.sh\"]\n"
    )
    _write_text(outputs_dir / "Dockerfile", dockerfile_text)

    compose_text = (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    environment:\n"
        f"      LOGIN_USER: \"{login_user}\"\n"
        f"      LOGIN_PASS: \"{login_pass}\"\n"
        "    ports:\n"
        f"      - \"{ssh_port}:22\"\n"
        "    volumes:\n"
        "      - ./desktop:/challenge/desktop:ro\n"
        "    hostname: ssh-node\n"
    )
    _write_text(outputs_dir / "docker-compose.yml", compose_text)

    manifest = {
        "generator_id": str(cfg.get("generator_id") or "sample.ssh_desktop_creds"),
        "outputs": {
            "Flag(flag_id)": flag_value,
            "FlagDelivery(mode)": "file",
            "FlagFile(path)": "desktop/flag.txt",
            "Credential(user, password)": login_cred,
            "File(path)": "docker-compose.yml",
            "PortForward(host, port)": ssh_port,
            "Directory(host, path)": "desktop",
        },
    }
    _write_text(outputs_dir / "outputs.json", json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
