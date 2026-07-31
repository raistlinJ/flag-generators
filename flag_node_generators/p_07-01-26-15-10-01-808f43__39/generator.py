import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any


GENERATOR_FAMILY = "service_variant_runtime"


VARIANTS: dict[str, dict[str, Any]] = {
    "ftp_anonymous_finance_drop": {
        "pack": "ftp",
        "service": "ftp",
        "protocol": "ftp",
        "default_port": 2121,
        "title": "Finance FTP Drop",
        "auth": "anonymous",
        "endpoint": "/finance/q2-close.txt",
        "flag_path": "finance/q2-close.txt",
        "extra_facts": {"Misconfiguration(service)": "anonymous_ftp", "ExposedSecret(service)": "ftp_public_drop"},
        "files": {
            "README.txt": "Anonymous FTP mirror for finance handoff files.\n",
            "finance/q2-close.txt": "Q2 close packet {digest}\nflag={flag}\n",
            "finance/vendor-aging.csv": "vendor,days_open,owner\nNorthwind,45,ap\nContoso,12,ops\n",
        },
    },
    "ftp_user_backup_home": {
        "pack": "ftp",
        "service": "ftp",
        "protocol": "ftp",
        "default_port": 2121,
        "title": "Authenticated Backup FTP",
        "auth": "password",
        "user_prefix": "backupftp",
        "endpoint": "/backups/restore-note.txt",
        "flag_path": "backups/restore-note.txt",
        "archive_path": "backups/restore-bundle.zip",
        "extra_facts": {"BackupArchive(file)": "backups/restore-bundle.zip"},
        "files": {
            "README.txt": "Nightly backup landing area. Authenticated access is required.\n",
            "backups/restore-note.txt": "Restore batch {digest}\nflag={flag}\n",
            "backups/index.tsv": "snapshot\tstatus\ncore-router\tcomplete\nfinance-share\twarning\n",
        },
    },
    "smb_guest_public_share": {
        "pack": "smb",
        "service": "smb",
        "protocol": "smb",
        "default_port": 1445,
        "title": "Guest SMB Share",
        "auth": "guest",
        "endpoint": "/Public/ops-note.txt",
        "flag_path": "Public/ops-note.txt",
        "extra_facts": {"Misconfiguration(service)": "smb_guest_share"},
        "files": {
            "Public/ops-note.txt": "Shared operations note {digest}\nflag={flag}\n",
            "Public/roster.csv": "team,contact\nfield,field@example.invalid\nplatform,platform@example.invalid\n",
            "README.txt": "Guest-readable department share.\n",
        },
    },
    "smb_hr_payroll_share": {
        "pack": "smb",
        "service": "smb",
        "protocol": "smb",
        "default_port": 1445,
        "title": "HR Payroll Share",
        "auth": "password",
        "user_prefix": "hrshare",
        "endpoint": "/HR/payroll-exception.txt",
        "flag_path": "HR/payroll-exception.txt",
        "extra_facts": {"ExposedSecret(service)": "smb_payroll_share"},
        "files": {
            "HR/payroll-exception.txt": "Payroll exception report {digest}\nflag={flag}\n",
            "HR/onboarding/checklist.md": "# New hire checklist\n- badge\n- payroll\n- device\n",
        },
    },
    "dns_zone_transfer_records": {
        "pack": "dns",
        "service": "dns",
        "protocol": "dns",
        "default_port": 1053,
        "title": "Leaky Internal DNS Zone",
        "auth": "none",
        "endpoint": "/AXFR/internal.example.test",
        "flag_path": "zones/internal.example.test.zone",
        "extra_facts": {"Misconfiguration(service)": "dns_zone_transfer", "Hostname(host)": "internal.example.test"},
        "files": {
            "zones/internal.example.test.zone": "$ORIGIN internal.example.test.\n@ 3600 IN SOA ns1 hostmaster 1 7200 3600 1209600 3600\nflag 60 IN TXT \"{flag}\"\nfiles 60 IN A 10.10.20.15\n",
            "zones/README.txt": "Zone transfer allowed from lab networks for diagnostics.\n",
        },
    },
    "dns_txt_secret_record": {
        "pack": "dns",
        "service": "dns",
        "protocol": "dns",
        "default_port": 1053,
        "title": "DNS TXT Secret Record",
        "auth": "none",
        "endpoint": "/TXT/vault.internal.example.test",
        "flag_path": "records/vault.internal.example.test.txt",
        "extra_facts": {"ExposedSecret(service)": "dns_txt_record", "Hostname(host)": "vault.internal.example.test"},
        "files": {
            "records/vault.internal.example.test.txt": "vault.internal.example.test TXT \"recovery={flag}\"\n",
            "records/helpdesk.internal.example.test.txt": "helpdesk.internal.example.test TXT \"owner=support\"\n",
        },
    },
    "postgres_customer_dump": {
        "pack": "database",
        "service": "postgres",
        "protocol": "database",
        "default_port": 15432,
        "title": "Postgres Customer Dump",
        "auth": "password",
        "user_prefix": "pgapp",
        "endpoint": "/database/customer_exports.sql",
        "flag_path": "database/customer_exports.sql",
        "extra_facts": {"ExposedSecret(service)": "postgres_dump", "Version(service)": "postgresql-15-simulated"},
        "files": {
            "database/customer_exports.sql": "-- exported by support desk {digest}\nINSERT INTO notes VALUES ('priority', '{flag}');\n",
            "database/schema.sql": "CREATE TABLE notes (name text, value text);\nCREATE TABLE customers (id int, name text);\n",
        },
    },
    "mysql_backup_table": {
        "pack": "database",
        "service": "mysql",
        "protocol": "database",
        "default_port": 13306,
        "title": "MySQL Backup Table",
        "auth": "password",
        "user_prefix": "mysqlapp",
        "endpoint": "/database/backup_table.sql",
        "flag_path": "database/backup_table.sql",
        "archive_path": "database/mysql-nightly.zip",
        "extra_facts": {"BackupArchive(file)": "database/mysql-nightly.zip", "Version(service)": "mysql-8-simulated"},
        "files": {
            "database/backup_table.sql": "CREATE TABLE backup_notes(id int, note text);\nINSERT INTO backup_notes VALUES (1, '{flag}');\n",
            "database/restore.log": "restore id {digest}: finished with warnings\n",
        },
    },
    "redis_exposed_keys": {
        "pack": "cache",
        "service": "redis",
        "protocol": "redis",
        "default_port": 16379,
        "title": "Exposed Redis Cache",
        "auth": "none",
        "endpoint": "/keys/session:admin",
        "flag_path": "keys/session_admin.txt",
        "token": True,
        "extra_facts": {"Misconfiguration(service)": "redis_no_auth", "Token(service)": "{token}"},
        "files": {
            "keys/session_admin.txt": "session:admin={flag}\nreset_token={token}\n",
            "keys/cache_listing.txt": "session:admin\nfeature:beta\nqueue:rollout\n",
        },
    },
    "memcached_session_cache": {
        "pack": "cache",
        "service": "memcached",
        "protocol": "memcached",
        "default_port": 11211,
        "title": "Memcached Session Cache",
        "auth": "none",
        "endpoint": "/cache/session_admin",
        "flag_path": "cache/session_admin.txt",
        "extra_facts": {"ExposedSecret(service)": "memcached_session"},
        "files": {
            "cache/session_admin.txt": "VALUE session_admin 0 64\n{flag}\nEND\n",
            "cache/stats.txt": "STAT curr_items 3\nSTAT bytes 2048\nEND\n",
        },
    },
    "smtp_open_relay_queue": {
        "pack": "mail",
        "service": "smtp",
        "protocol": "smtp",
        "default_port": 2525,
        "title": "SMTP Relay Queue",
        "auth": "none",
        "endpoint": "/queue/deferred-1729.eml",
        "flag_path": "queue/deferred-1729.eml",
        "extra_facts": {"Misconfiguration(service)": "smtp_open_relay"},
        "files": {
            "queue/deferred-1729.eml": "From: noc@example.invalid\nTo: ops@example.invalid\nSubject: relay exception {digest}\n\n{flag}\n",
            "queue/README.txt": "Deferred queue is world-readable in this lab fixture.\n",
        },
    },
    "imap_shared_mailbox": {
        "pack": "mail",
        "service": "imap",
        "protocol": "imap",
        "default_port": 2143,
        "title": "Shared IMAP Mailbox",
        "auth": "password",
        "user_prefix": "mailbox",
        "endpoint": "/INBOX/0004.eml",
        "flag_path": "INBOX/0004.eml",
        "files": {
            "INBOX/0004.eml": "From: facilities@example.invalid\nSubject: mailbox handoff\n\nShared mailbox note {digest}\nflag={flag}\n",
            "INBOX/0001.eml": "From: helpdesk@example.invalid\nSubject: onboarding\n\nWelcome to the shared mailbox.\n",
        },
    },
    "ldap_anonymous_directory": {
        "pack": "ldap",
        "service": "ldap",
        "protocol": "ldap",
        "default_port": 1389,
        "title": "Anonymous LDAP Directory",
        "auth": "anonymous",
        "endpoint": "/ou=People,dc=lab,dc=local",
        "flag_path": "directory/people.ldif",
        "extra_facts": {"Misconfiguration(service)": "ldap_anonymous_bind"},
        "files": {
            "directory/people.ldif": "dn: uid=svc-backup,ou=People,dc=lab,dc=local\ncn: Backup Service\ndescription: {flag}\n",
            "directory/groups.ldif": "dn: cn=operators,ou=Groups,dc=lab,dc=local\nmemberUid: svc-backup\n",
        },
    },
    "ldap_bind_service_account": {
        "pack": "ldap",
        "service": "ldap",
        "protocol": "ldap",
        "default_port": 1389,
        "title": "LDAP Service Account Bind",
        "auth": "password",
        "user_prefix": "svc_ldap",
        "endpoint": "/cn=service-notes,dc=lab,dc=local",
        "flag_path": "directory/service-notes.ldif",
        "extra_facts": {"ExposedSecret(service)": "ldap_service_account"},
        "files": {
            "directory/service-notes.ldif": "dn: cn=service-notes,dc=lab,dc=local\ncn: service-notes\ndescription: bind recovered {flag}\n",
            "directory/access.ldif": "dn: cn=readers,dc=lab,dc=local\nmember: uid={user},ou=People,dc=lab,dc=local\n",
        },
    },
    "git_http_bare_repo": {
        "pack": "git",
        "service": "git",
        "protocol": "git",
        "default_port": 19418,
        "title": "Bare Git Repository Mirror",
        "auth": "none",
        "endpoint": "/repo/config",
        "flag_path": "repo/config",
        "extra_facts": {"SourceCode(repo)": "ops_mirror", "ExposedSecret(service)": "git_config_secret"},
        "files": {
            "repo/config": "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = ssh://git@example.invalid/ops.git\n[secret]\n\tflag = {flag}\n",
            "repo/refs/heads/main": "{digest}\n",
            "repo/HEAD": "ref: refs/heads/main\n",
        },
    },
    "git_deploy_key_repo": {
        "pack": "git",
        "service": "git",
        "protocol": "git",
        "default_port": 19418,
        "title": "Deploy Key Repository",
        "auth": "password",
        "user_prefix": "gitdeploy",
        "endpoint": "/repo/deploy.env",
        "flag_path": "repo/deploy.env",
        "api_key": True,
        "extra_facts": {"SourceCode(repo)": "deploy_repo", "APIKey(service)": "{api_key}"},
        "files": {
            "repo/deploy.env": "DEPLOY_API_KEY={api_key}\nRECOVERY_FLAG={flag}\n",
            "repo/README.md": "# Deploy repo\nRestricted release automation mirror.\n",
        },
    },
    "mqtt_public_broker_topic": {
        "pack": "mqtt",
        "service": "mqtt",
        "protocol": "mqtt",
        "default_port": 1883,
        "title": "Public MQTT Topic",
        "auth": "none",
        "endpoint": "/topics/site/alerts",
        "flag_path": "topics/site_alerts.txt",
        "token": True,
        "extra_facts": {"Misconfiguration(service)": "mqtt_public_topic", "Token(service)": "{token}"},
        "files": {
            "topics/site_alerts.txt": "topic=site/alerts\nmessage=maintenance token {token}\nflag={flag}\n",
            "topics/README.txt": "Use SUB site/alerts in the lab service shell.\n",
        },
    },
    "mqtt_credentialed_ops_topic": {
        "pack": "mqtt",
        "service": "mqtt",
        "protocol": "mqtt",
        "default_port": 1883,
        "title": "Credentialed MQTT Ops Topic",
        "auth": "password",
        "user_prefix": "mqttops",
        "endpoint": "/topics/ops/private",
        "flag_path": "topics/ops_private.txt",
        "files": {
            "topics/ops_private.txt": "topic=ops/private\nmessage=dispatch window {digest}\nflag={flag}\n",
            "topics/site_public.txt": "topic=site/public\nmessage=ok\n",
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
    clean_prefix = (prefix or "FLAG").strip() or "FLAG"
    return f"{clean_prefix}{{{_digest(seed, node_name, variant_id, length=20)}}}"


def _format_template(value: Any, mapping: dict[str, Any]) -> str:
    text = str(value)
    for key, replacement in mapping.items():
        text = text.replace("{" + str(key) + "}", str(replacement))
    return text


def _parse_credential(raw: Any) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if ":" not in text:
        raise ValueError('Credential(user, password) must use "user:password" format')
    user, password = text.split(":", 1)
    user = user.strip()
    password = password.strip()
    if not user or not password:
        raise ValueError("Credential(user, password) must include both user and password")
    return user, password


def _int_range(value: Any, default: int, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None and str(value).strip() != "" else default)
    except Exception as exc:
        raise ValueError(f"invalid {name}: {value}") from exc
    if number < minimum or number > maximum:
        raise ValueError(f"invalid {name}: {number}")
    return number


def _service_script() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
import socketserver
from pathlib import Path


ROOT = Path(os.environ.get("SERVICE_ROOT", "/srv/service")).resolve()
CONFIG = json.loads((ROOT / "config.json").read_text("utf-8"))


def _safe_path(raw):
    rel = str(raw or "").strip().replace("\\", "/").lstrip("/")
    if not rel:
        return None
    candidate = (ROOT / rel).resolve()
    try:
        candidate.relative_to(ROOT)
    except Exception:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def _read_rel(raw):
    path = _safe_path(raw)
    if path is None:
        return "ERR not found\n"
    return path.read_text("utf-8", errors="replace")


def _listing():
    rows = []
    for path in sorted(ROOT.rglob("*")):
        if path.name == "config.json" or not path.is_file():
            continue
        rows.append(str(path.relative_to(ROOT)).replace("\\", "/"))
    return "\n".join(rows) + ("\n" if rows else "")


class Handler(socketserver.StreamRequestHandler):
    def setup(self):
        super().setup()
        self.authed = CONFIG.get("auth") in ("none", "anonymous", "guest")

    def write(self, text):
        self.wfile.write(str(text).encode("utf-8", "replace"))

    def _check_auth(self):
        if self.authed:
            return True
        self.write("ERR authentication required\n")
        return False

    def _auth(self, parts):
        if CONFIG.get("auth") in ("none", "anonymous", "guest"):
            self.authed = True
            self.write("OK anonymous access\n")
            return
        if len(parts) >= 3 and parts[1] == CONFIG.get("username") and parts[2] == CONFIG.get("password"):
            self.authed = True
            self.write("OK authenticated\n")
            return
        self.write("ERR invalid credentials\n")

    def _http_get(self, line):
        try:
            path = line.split()[1].split("?", 1)[0].lstrip("/") or "README.txt"
        except Exception:
            path = "README.txt"
        body = _read_rel(path)
        status = "200 OK" if not body.startswith("ERR ") else "404 Not Found"
        response = f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}"
        self.write(response)

    def _protocol_alias(self, raw, upper):
        protocol = CONFIG.get("protocol")
        parts = raw.split()
        if protocol == "ftp":
            if upper.startswith("USER "):
                self.write("331 password required\n")
                return True
            if upper.startswith("PASS "):
                if CONFIG.get("auth") == "password":
                    expected = CONFIG.get("password")
                    self.authed = raw.split(None, 1)[1].strip() == expected if len(parts) > 1 else False
                else:
                    self.authed = True
                self.write("230 login ok\n" if self.authed else "530 login incorrect\n")
                return True
            if upper == "LIST":
                if self._check_auth():
                    self.write(_listing())
                return True
            if upper.startswith("RETR "):
                if self._check_auth():
                    self.write(_read_rel(raw.split(None, 1)[1]))
                return True
        if protocol == "smb" and upper in ("SHARES", "DIR"):
            if self._check_auth():
                self.write(_listing())
            return True
        if protocol == "dns":
            if upper.startswith("AXFR") or upper.startswith("TXT"):
                self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "redis":
            if upper.startswith("KEYS"):
                self.write(_listing())
                return True
            if upper.startswith("GET "):
                self.write(_read_rel(raw.split(None, 1)[1].replace(":", "_") + ".txt"))
                return True
        if protocol == "memcached":
            if upper == "STATS":
                self.write(_read_rel("cache/stats.txt"))
                return True
            if upper.startswith("GET "):
                self.write(_read_rel("cache/" + raw.split(None, 1)[1] + ".txt"))
                return True
        if protocol == "smtp":
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.write("250-coretg relay\n250 HELP\n")
                return True
            if upper.startswith("VRFY") or upper == "QUEUE":
                self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "imap":
            if upper.startswith("LOGIN"):
                if len(parts) >= 3 and parts[1] == CONFIG.get("username") and parts[2] == CONFIG.get("password"):
                    self.authed = True
                    self.write("OK LOGIN completed\n")
                else:
                    self.write("NO LOGIN failed\n")
                return True
            if upper.startswith("FETCH"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "ldap":
            if upper.startswith("BIND"):
                self._auth(["AUTH"] + parts[1:])
                return True
            if upper.startswith("SEARCH"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "mqtt":
            if upper.startswith("SUB"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        return False

    def handle(self):
        self.write(CONFIG.get("banner", "service ready") + "\n")
        self.write("Commands: HELP, INFO, AUTH <user> <password>, LIST, GET <path>\n")
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            raw = line.decode("utf-8", "replace").strip()
            if not raw:
                continue
            upper = raw.upper()
            if raw.startswith("GET ") and " HTTP/" in raw:
                self._http_get(raw)
                return
            parts = raw.split()
            if upper in ("QUIT", "EXIT"):
                self.write("bye\n")
                return
            if upper == "HELP":
                self.write(CONFIG.get("help", "Use LIST and GET <path>.\n"))
                continue
            if upper == "INFO":
                self.write(json.dumps({k: CONFIG.get(k) for k in ("variant_id", "service", "protocol", "title", "endpoint")}, indent=2) + "\n")
                continue
            if upper.startswith("AUTH "):
                self._auth(parts)
                continue
            if self._protocol_alias(raw, upper):
                continue
            if upper == "LIST":
                if self._check_auth():
                    self.write(_listing())
                continue
            if upper.startswith("GET "):
                if self._check_auth():
                    self.write(_read_rel(raw.split(None, 1)[1]))
                continue
            self.write("ERR unknown command\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("SERVICE_PORT", str(CONFIG.get("port", 9000))))
    with Server(("0.0.0.0", port), Handler) as server:
        server.serve_forever()
'''


def _challenge_dockerfile(port: int) -> str:
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /srv\n"
        "COPY service.py /srv/service.py\n"
        "COPY service /srv/service\n"
        f"ENV SERVICE_PORT={port}\n"
        f"EXPOSE {port}\n"
        "CMD [\"python\", \"/srv/service.py\"]\n"
    )


def _compose(port: int, hostname: str) -> str:
    return (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    environment:\n"
        f"      SERVICE_PORT: {json.dumps(str(port))}\n"
        "    ports:\n"
        f"      - \"{port}:{port}\"\n"
        f"    hostname: {hostname}\n"
    )


def _write_archive(service_root: Path, archive_rel: str, mapping: dict[str, Any]) -> None:
    archive_path = service_root / archive_rel
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", _format_template("Recovery archive {digest}\n", mapping))
        archive.writestr("secrets/recovery-note.txt", _format_template("Recovered marker: {flag}\n", mapping))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate service node variant artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--variant", default=os.environ.get("SERVICE_VARIANT_ID", "ftp_anonymous_finance_drop"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    variant = VARIANTS.get(variant_id)
    if not variant:
        raise SystemExit(f"[validation error] unknown service variant: {variant_id}")

    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        port = _int_range(cfg.get("service_port"), int(variant.get("default_port") or 9000), name="service_port", minimum=1, maximum=65535)
        parsed_credential = _parse_credential(cfg.get("Credential(user, password)"))
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, variant_id, length=10)
    needs_credential = str(variant.get("auth") or "none") == "password"
    if parsed_credential:
        username, password = parsed_credential
    elif needs_credential:
        username = f"{variant.get('user_prefix') or variant.get('service')}_{digest[:6]}"
        password = f"Svc-{digest[6:]}!"
    else:
        username = str(variant.get("auth") or "anonymous")
        password = ""

    token = _digest(seed, variant_id, "token", length=24)
    api_key = "ak_" + _digest(seed, variant_id, "api", length=28)
    flag_value = _flag(seed, node_name, variant_id, str(cfg.get("flag_prefix") or "FLAG"))
    mapping = {
        "api_key": api_key,
        "digest": digest,
        "flag": flag_value,
        "node": node_name,
        "password": password,
        "port": port,
        "token": token,
        "user": username,
    }

    service_root = args.output / "service"
    for raw_rel, raw_body in (variant.get("files") or {}).items():
        rel = _format_template(raw_rel, mapping).lstrip("/")
        body = _format_template(raw_body, mapping)
        _write_text(service_root / rel, body)

    flag_path = _format_template(str(variant.get("flag_path") or "flag.txt"), mapping).lstrip("/")
    if not (service_root / flag_path).exists():
        _write_text(service_root / flag_path, flag_value + "\n")

    archive_rel = str(variant.get("archive_path") or "").strip().lstrip("/")
    if archive_rel:
        _write_archive(service_root, archive_rel, mapping)

    endpoint = _format_template(str(variant.get("endpoint") or "/" + flag_path), mapping)
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    service_name = str(variant.get("service") or variant.get("pack") or "service")
    protocol = str(variant.get("protocol") or service_name)
    banner = f"{service_name.upper()} lab service {digest} ({variant.get('title') or variant_id})"
    service_config = {
        "variant_id": variant_id,
        "service": service_name,
        "protocol": protocol,
        "title": str(variant.get("title") or variant_id),
        "auth": str(variant.get("auth") or "none"),
        "username": username,
        "password": password,
        "endpoint": endpoint,
        "flag_path": flag_path,
        "port": port,
        "banner": banner,
        "help": "Use LIST to enumerate files and GET <path> to read one. Service-specific aliases are also supported.\n",
    }
    _write_text(service_root / "config.json", json.dumps(service_config, indent=2) + "\n")
    _write_text(args.output / "service.py", _service_script(), mode=0o755)
    _write_text(args.output / "Dockerfile", _challenge_dockerfile(port))
    _write_text(args.output / "docker-compose.yml", _compose(port, f"{service_name}-{digest[:6]}"))

    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag_value,
        "FlagDelivery(mode)": "file",
        "FlagFile(path)": flag_path,
        "File(path)": "docker-compose.yml",
        "Directory(host, path)": "service",
        "PortForward(host, port)": port,
        "Endpoint(path)": endpoint,
        "Version(service)": f"{service_name}-simulated-{protocol}",
    }
    if needs_credential or parsed_credential:
        outputs["Credential(user, password)"] = f"{username}:{password}"
    for fact, raw_value in (variant.get("extra_facts") or {}).items():
        outputs[str(fact)] = _format_template(raw_value, mapping)

    _write_text(
        args.output / "outputs.json",
        json.dumps({"generator_id": str(cfg.get("generator_id") or variant_id), "outputs": outputs}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()