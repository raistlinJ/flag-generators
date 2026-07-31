import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDyqkDTwlsJFjj1akTu4KNE97mmZuyCYEr5bHLCxR/iPwAAAJibV7VZm1e1
WQAAAAtzc2gtZWQyNTUxOQAAACDyqkDTwlsJFjj1akTu4KNE97mmZuyCYEr5bHLCxR/iPw
AAAEDDPoyhh5SHpXQKGekQnHIW2JQatM7gutBkFZN9z85Cf/KqQNPCWwkWOPVqRO7go0T3
uaZm7IJgSvlscsLFH+I/AAAAEmNvcmV0Zy1zc2gtdmFyaWFudAECAw==
-----END OPENSSH PRIVATE KEY-----
"""
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPKqQNPCWwkWOPVqRO7go0T3uaZm7IJgSvlscsLFH+I/ coretg-ssh-variant"


VARIANTS: dict[str, dict[str, Any]] = {
    "ssh_password_audit_workstation": {
        "auth": "password",
        "user_prefix": "auditor",
        "hostname": "audit-workstation",
        "flag_path": "audit/review/flag.txt",
        "files": {
            "audit/README.txt": "Internal audit workstation. Review exported notes and command logs.\n",
            "audit/logs/terminal.log": "2026-05-20 08:12 opened stale ACL report\n2026-05-20 08:43 copied review note {digest}\n",
            "audit/review/flag.txt": "Audit finding {digest}\nflag={flag}\n",
            "audit/review/scope.md": "# Scope\n- access switches\n- user workstations\n- backup shares\n",
        },
    },
    "ssh_password_helpdesk_home": {
        "auth": "password",
        "user_prefix": "helpdesk",
        "hostname": "helpdesk-home",
        "flag_path": "support/tickets/ticket-{digest}.txt",
        "files": {
            "support/README.txt": "Helpdesk home directory export with old support notes.\n",
            "support/tickets/ticket-{digest}.txt": "Ticket {digest}: temporary escalation approved\nflag={flag}\n",
            "support/runbooks/password-reset.md": "Reset workflow requires manager approval and ticket attachment.\n",
            "Downloads/chat-export.txt": "Analyst asked for the ticket trail before escalation.\n",
        },
    },
    "ssh_password_timeout_shell": {
        "auth": "password",
        "user_prefix": "tempops",
        "hostname": "timeout-shell",
        "flag_path": "session/window-{digest}.txt",
        "timeout": 120,
        "files": {
            "session/README.txt": "Temporary access account. Shell sessions expire quickly.\n",
            "session/window-{digest}.txt": "Short-lived session marker\ntimeout={timeout}\nflag={flag}\n",
            "session/history.txt": "cd session\ncat window-{digest}.txt\nlogout\n",
        },
    },
    "ssh_password_finance_terminal": {
        "auth": "password",
        "user_prefix": "finance",
        "hostname": "finance-terminal",
        "flag_path": "finance/reconciliations/q2-{digest}.csv",
        "files": {
            "finance/README.txt": "Finance terminal home folder. Reconciliation files are local only.\n",
            "finance/reconciliations/q2-{digest}.csv": "account,period,status,marker\n7300,2026-Q2,reconciled,{flag}\n",
            "finance/exports/vendors.csv": "vendor,total\nNorthwind,18340.55\nContoso,9412.10\n",
        },
    },
    "ssh_key_ops_bastion": {
        "auth": "key",
        "user_prefix": "ops",
        "hostname": "ops-bastion",
        "flag_path": "ops/runbooks/bastion-note-{digest}.md",
        "files": {
            "ops/README.txt": "Bastion account accepts key authentication only.\n",
            "ops/runbooks/bastion-note-{digest}.md": "# Bastion Note\nRecovered marker: {flag}\n",
            "ops/runbooks/allowed-routes.txt": "mgmt-vlan\nbackup-vlan\nmonitoring-vlan\n",
        },
    },
    "ssh_key_backup_operator": {
        "auth": "key",
        "user_prefix": "backup",
        "hostname": "backup-operator",
        "flag_path": "backups/restore-note-{digest}.txt",
        "files": {
            "backups/README.txt": "Backup operator account. Key login required.\n",
            "backups/restore-note-{digest}.txt": "Restore batch {digest}\nflag={flag}\n",
            "backups/index.tsv": "snapshot\tstatus\nfileserver-a\tcomplete\nfinance-share\twarning\n",
        },
    },
    "ssh_key_git_deploy": {
        "auth": "key",
        "user_prefix": "deploy",
        "hostname": "git-deploy",
        "flag_path": "repo/DEPLOYMENT.md",
        "files": {
            "repo/DEPLOYMENT.md": "# Deployment Notes\nseed={digest}\nflag={flag}\n",
            "repo/.gitconfig": "[user]\n\temail = deploy@example.invalid\n\tname = Deploy Bot\n",
            "repo/releases/current.txt": "release=2026.05.{digest}\nstatus=staged\n",
        },
    },
    "ssh_key_research_lab": {
        "auth": "key",
        "user_prefix": "research",
        "hostname": "research-lab",
        "flag_path": "lab/notebooks/observation-{digest}.txt",
        "files": {
            "lab/README.txt": "Research lab account. Key-only access is enforced.\n",
            "lab/notebooks/observation-{digest}.txt": "Observation batch {digest}\ncontrol flag: {flag}\n",
            "lab/datasets/sample.csv": "sample,value\na,0.42\nb,0.77\n",
        },
    },
    "ssh_dual_incident_response": {
        "auth": "dual",
        "user_prefix": "ir",
        "hostname": "incident-response",
        "flag_path": "ir/evidence/summary-{digest}.txt",
        "timeout": 300,
        "files": {
            "ir/README.txt": "Incident response account supports password and key login.\n",
            "ir/evidence/summary-{digest}.txt": "Incident summary {digest}\ntimeout={timeout}\nflag={flag}\n",
            "ir/evidence/iocs.txt": "hash-a-{digest}\nuser-agent=legacy-sync\n",
        },
    },
    "ssh_sftp_dropbox_key": {
        "auth": "sftp",
        "user_prefix": "dropbox",
        "hostname": "sftp-dropbox",
        "flag_path": "dropbox/incoming/transfer-note-{digest}.txt",
        "files": {
            "dropbox/README.txt": "SFTP-only dropbox. Interactive shell is disabled.\n",
            "dropbox/incoming/transfer-note-{digest}.txt": "Transfer note {digest}\nflag={flag}\n",
            "dropbox/archive/listing.txt": "incoming/\nprocessed/\nquarantine/\n",
        },
    },
}


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


def _flag(seed: str, node_name: str, variant_id: str, prefix: str) -> str:
    return f"{(prefix or 'FLAG').strip() or 'FLAG'}{{{_digest(seed, node_name, variant_id, length=20)}}}"


def _parse_credential(raw: Any, *, required: bool) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text:
        if required:
            raise ValueError('Credential(user, password) is required')
        return None
    if ":" not in text:
        raise ValueError('Credential(user, password) must use "user:password" format')
    user, password = text.split(":", 1)
    user = user.strip()
    password = password.strip()
    if not user or not password:
        raise ValueError('Credential(user, password) must include both user and password')
    return user, password


def _int_range(value: Any, default: int, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None and str(value).strip() != "" else default)
    except Exception as exc:
        raise ValueError(f"invalid {name}: {value}") from exc
    if number < minimum or number > maximum:
        raise ValueError(f"invalid {name}: {number}")
    return number


def _entrypoint() -> str:
    return """#!/bin/sh
set -eu
LOGIN_USER="${LOGIN_USER:-player}"
LOGIN_PASS="${LOGIN_PASS:-}"
AUTH_MODE="${AUTH_MODE:-password}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"

if ! id "$LOGIN_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$LOGIN_USER"
fi

if [ -n "$LOGIN_PASS" ]; then
  echo "$LOGIN_USER:$LOGIN_PASS" | chpasswd
fi

mkdir -p "/home/$LOGIN_USER/.ssh"
if [ -f /challenge/keys/id_ed25519.pub ]; then
  cp -f /challenge/keys/id_ed25519.pub "/home/$LOGIN_USER/.ssh/authorized_keys"
fi
if [ -d /challenge/workspace ]; then
  cp -a /challenge/workspace/. "/home/$LOGIN_USER/" 2>/dev/null || true
fi
chown -R "$LOGIN_USER:$LOGIN_USER" "/home/$LOGIN_USER"
chmod 700 "/home/$LOGIN_USER/.ssh" || true
chmod 600 "/home/$LOGIN_USER/.ssh/authorized_keys" 2>/dev/null || true

PASS_AUTH=no
PUB_AUTH=no
if [ "$AUTH_MODE" = "password" ] || [ "$AUTH_MODE" = "dual" ]; then
  PASS_AUTH=yes
fi
if [ "$AUTH_MODE" = "key" ] || [ "$AUTH_MODE" = "dual" ] || [ "$AUTH_MODE" = "sftp" ]; then
  PUB_AUTH=yes
fi

sed -ri "s/^#?PasswordAuthentication .*/PasswordAuthentication $PASS_AUTH/" /etc/ssh/sshd_config
sed -ri "s/^#?PubkeyAuthentication .*/PubkeyAuthentication $PUB_AUTH/" /etc/ssh/sshd_config
sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
grep -q '^UsePAM' /etc/ssh/sshd_config && sed -ri 's/^UsePAM .*/UsePAM no/' /etc/ssh/sshd_config || echo 'UsePAM no' >> /etc/ssh/sshd_config
grep -q '^AuthorizedKeysFile' /etc/ssh/sshd_config && sed -ri 's#^AuthorizedKeysFile .*#AuthorizedKeysFile .ssh/authorized_keys#' /etc/ssh/sshd_config || echo 'AuthorizedKeysFile .ssh/authorized_keys' >> /etc/ssh/sshd_config

case "$TIMEOUT_SECONDS" in
  ''|0) ;;
  *)
    printf 'TMOUT=%s\nreadonly TMOUT\nexport TMOUT\n' "$TIMEOUT_SECONDS" > /etc/profile.d/coretg-timeout.sh
    echo "ClientAliveInterval $TIMEOUT_SECONDS" >> /etc/ssh/sshd_config
    echo 'ClientAliveCountMax 1' >> /etc/ssh/sshd_config
    ;;
esac

if [ "$AUTH_MODE" = "sftp" ]; then
  printf '\nMatch User %s\n  ForceCommand internal-sftp\n  X11Forwarding no\n  AllowTcpForwarding no\n' "$LOGIN_USER" >> /etc/ssh/sshd_config
fi

mkdir -p /var/run/sshd
SSHD_PID=""
term_handler() {
  if [ -n "$SSHD_PID" ] && kill -0 "$SSHD_PID" 2>/dev/null; then
    kill -TERM "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi
  exit 143
}
trap term_handler TERM INT
/usr/sbin/sshd -D -e &
SSHD_PID="$!"
wait "$SSHD_PID"
"""


def _challenge_dockerfile() -> str:
    return (
        "FROM ubuntu:22.04\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
            "RUN apt-get update \\\n  && apt-get install -y --no-install-recommends openssh-server ca-certificates passwd \\\n  && rm -rf /var/lib/apt/lists/*\n"
        "COPY entrypoint.sh /entrypoint.sh\n"
        "RUN chmod +x /entrypoint.sh\n"
        "EXPOSE 22\n"
        "CMD [\"/entrypoint.sh\"]\n"
    )


def _compose(port: int, user: str, password: str, auth: str, timeout: int, key_auth: bool, hostname: str) -> str:
    volumes = "      - ./workspace:/challenge/workspace:ro\n"
    if key_auth:
        volumes += "      - ./keys:/challenge/keys:ro\n"
    return (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    environment:\n"
        f"      LOGIN_USER: {json.dumps(user)}\n"
        f"      LOGIN_PASS: {json.dumps(password)}\n"
        f"      AUTH_MODE: {json.dumps(auth)}\n"
        f"      TIMEOUT_SECONDS: {json.dumps(str(timeout))}\n"
        "    ports:\n"
        f"      - \"{port}:22\"\n"
        "    volumes:\n"
        f"{volumes}"
        f"    hostname: {hostname}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SSH node variant artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--variant", default=os.environ.get("SSH_VARIANT_ID", "ssh_password_audit_workstation"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    variant = VARIANTS.get(variant_id)
    if not variant:
        raise SystemExit(f"[validation error] unknown SSH variant: {variant_id}")

    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        port = _int_range(cfg.get("ssh_port"), 2222, name="ssh_port", minimum=1, maximum=65535)
        timeout = _int_range(cfg.get("timeout_seconds"), int(variant.get("timeout") or 0), name="timeout_seconds", minimum=0, maximum=86400)
        auth = str(variant.get("auth") or "password")
        password_auth = auth in {"password", "dual"}
        key_auth = auth in {"key", "dual", "sftp"}
        parsed_credential = _parse_credential(cfg.get("Credential(user, password)"), required=password_auth)
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, variant_id, length=10)
    if parsed_credential:
        login_user, login_pass = parsed_credential
    else:
        login_user = f"{variant.get('user_prefix')}_{digest[:6]}"
        login_pass = ""
    flag_value = _flag(seed, node_name, variant_id, str(cfg.get("flag_prefix") or "FLAG"))

    workspace = args.output / "workspace"
    for raw_rel, raw_body in (variant.get("files") or {}).items():
        rel = str(raw_rel).format(digest=digest, user=login_user, timeout=timeout)
        body = str(raw_body).format(digest=digest, user=login_user, timeout=timeout, flag=flag_value, node=node_name)
        _write_text(workspace / rel, body)

    flag_path = str(variant.get("flag_path") or "flag.txt").format(digest=digest, user=login_user, timeout=timeout)
    flag_file = workspace / flag_path
    if not flag_file.exists():
        _write_text(flag_file, flag_value + "\n")

    if key_auth:
        _write_text(args.output / "keys" / "id_ed25519", PRIVATE_KEY, mode=0o600)
        _write_text(args.output / "keys" / "id_ed25519.pub", PUBLIC_KEY + "\n", mode=0o644)

    _write_text(args.output / "entrypoint.sh", _entrypoint(), mode=0o755)
    _write_text(args.output / "Dockerfile", _challenge_dockerfile())
    _write_text(
        args.output / "docker-compose.yml",
        _compose(port, login_user, login_pass, auth, timeout, key_auth, str(variant.get("hostname") or "ssh-node")),
    )

    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag_value,
        "FlagDelivery(mode)": "file",
        "FlagFile(path)": flag_path,
        "File(path)": "docker-compose.yml",
        "PortForward(host, port)": port,
        "Directory(host, path)": str(flag_path.split("/", 1)[0] if "/" in flag_path else "."),
    }
    if parsed_credential:
        outputs["Credential(user, password)"] = f"{login_user}:{login_pass}"
    else:
        outputs["Credential(user)"] = login_user
    if key_auth:
        outputs["SSHPrivateKey(path)"] = "keys/id_ed25519"
    if timeout:
        outputs["TimeoutSeconds(seconds)"] = timeout

    _write_text(
        args.output / "outputs.json",
        json.dumps({"generator_id": str(cfg.get("generator_id") or variant_id), "outputs": outputs}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()