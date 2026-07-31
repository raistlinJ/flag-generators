import argparse
import gzip
import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any

DEFAULT_VARIANT = "archive_tgz_config_backup"
VARIANTS = {'archive_gzip_rotated_log': {'builder': 'archive_gzip_log',
                              'family': 'archive',
                              'filename': 'auth.log.3.gz',
                              'name': 'Archive: Gzip Rotated Log'},
 'archive_tar_siem_export': {'builder': 'archive_tar_siem',
                             'family': 'archive',
                             'filename': 'siem_export.tar',
                             'name': 'Archive: TAR SIEM Export'},
 'archive_tgz_config_backup': {'builder': 'archive_tgz_config',
                               'family': 'archive',
                               'filename': 'config_backup.tgz',
                               'name': 'Archive: TGZ Config Backup'},
 'archive_zip_case_notes': {'builder': 'archive_zip_case',
                            'family': 'archive',
                            'filename': 'case_notes_export.zip',
                            'name': 'Archive: ZIP Case Notes'},
 'archive_zip_support_bundle': {'builder': 'archive_zip_support',
                                'family': 'archive',
                                'filename': 'support_bundle.zip',
                                'name': 'Archive: ZIP Support Bundle'},
 'hash_manifest_checksum_gate': {'builder': 'hash_manifest_gate',
                                 'family': 'hash',
                                 'filename': 'asset_manifest.sha256',
                                 'name': 'Hash: Manifest Checksum Gate'},
 'hash_md5_legacy_token': {'builder': 'hash_md5_token',
                           'family': 'hash',
                           'filename': 'legacy_token.md5',
                           'name': 'Hash: MD5 Legacy Token'},
 'hash_pbkdf2_recovery_phrase': {'builder': 'hash_pbkdf2_phrase',
                                 'family': 'hash',
                                 'filename': 'recovery_phrase.pbkdf2',
                                 'name': 'Hash: PBKDF2 Recovery Phrase'},
 'hash_salted_pin_digest': {'builder': 'hash_salted_pin',
                            'family': 'hash',
                            'filename': 'operator_pin.hash',
                            'name': 'Hash: Salted PIN Digest'},
 'hash_sha3_audit_token': {'builder': 'hash_sha3_audit',
                           'family': 'hash',
                           'filename': 'audit_token.sha3',
                           'name': 'Hash: SHA3 Audit Token'},
 'text_chatops_transcript': {'builder': 'text_chatops_transcript',
                             'family': 'text',
                             'filename': 'chatops_transcript.txt',
                             'name': 'Text: ChatOps Transcript'},
 'text_license_renewal_memo': {'builder': 'text_license_memo',
                               'family': 'text',
                               'filename': 'license_renewal_memo.txt',
                               'name': 'Text: License Renewal Memo'},
 'text_maintenance_clipboard': {'builder': 'text_maintenance_clipboard',
                                'family': 'text',
                                'filename': 'maintenance_clipboard.txt',
                                'name': 'Text: Maintenance Window Clipboard'},
 'text_runbook_escalation_note': {'builder': 'text_runbook_escalation',
                                  'family': 'text',
                                  'filename': 'runbook_escalation.txt',
                                  'name': 'Text: Runbook Escalation Note'},
 'text_ssh_known_hosts_comment': {'builder': 'text_known_hosts',
                                  'family': 'text',
                                  'filename': 'known_hosts.note',
                                  'name': 'Text: SSH Known Hosts Comment'}}


def _load_config(config_path: str) -> dict[str, Any]:
    for candidate in (config_path, "/inputs/config.json"):
        if not candidate:
            continue
        try:
            loaded = json.loads(Path(candidate).read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            continue
    return {}


def _digest(*parts: str, length: int = 16) -> str:
    joined = "|".join(str(part) for part in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:length]


def _flag(seed: str, variant_id: str, prefix: str) -> str:
    clean_prefix = (prefix or "FLAG").strip() or "FLAG"
    return f"{clean_prefix}{{{_digest(seed, variant_id, 'flag', length=24)}}}"


def _safe_filename(raw: Any, default: str) -> str:
    text = str(raw or "").replace("\\", "/").split("/")[-1].strip() or default
    if text in {".", ".."}:
        text = default
    cleaned = "".join(character if character.isalnum() or character in "._-" else "_" for character in text)
    return cleaned or default


def _context(seed: str, variant_id: str, flag: str) -> dict[str, str]:
    digest = _digest(seed, variant_id, length=12)
    return {
        "digest": digest,
        "flag": flag,
        "password": "Pass-" + digest[6:] + "!",
        "pin": str(int(_digest(seed, variant_id, "pin", length=6), 16) % 900000 + 100000),
        "salt": _digest(seed, variant_id, "salt", length=12),
        "token": "tok_" + _digest(seed, variant_id, "token", length=22),
        "user": "svc_" + digest[:6],
    }


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _add_tar_text(archive: tarfile.TarFile, archive_name: str, content: str) -> None:
    payload = content.encode("utf-8")
    info = tarfile.TarInfo(archive_name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


def _archive(builder: str, artifact_path: Path, context: dict[str, str]) -> dict[str, Any]:
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    if builder == "archive_tgz_config":
        with tarfile.open(artifact_path, "w:gz") as archive:
            _add_tar_text(archive, "etc/app/service.conf", f"service=field-api\nowner={context['user']}\n")
            _add_tar_text(archive, "etc/app/recovery.flag", context["flag"] + "\n")
            _add_tar_text(archive, "README.txt", f"Config backup {context['digest']}\n")
        return {"Archive(format)": "tar.gz", "Compression(format)": "gzip"}
    if builder == "archive_zip_case":
        with zipfile.ZipFile(artifact_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("case/README.txt", f"Case export {context['digest']}\n")
            archive.writestr("case/evidence/recovery-note.txt", f"Case marker {context['flag']}\n")
            archive.writestr("case/chain-of-custody.txt", f"custodian={context['user']}\n")
        return {"Archive(format)": "zip", "Case(id)": "CASE-" + context["digest"][:6]}
    if builder == "archive_tar_siem":
        with tarfile.open(artifact_path, "w") as archive:
            _add_tar_text(archive, "alerts/correlation-17.json", json.dumps({"alert": context["digest"], "flag": context["flag"]}) + "\n")
            _add_tar_text(archive, "events/raw.log", f"accepted token {context['token']}\n")
        return {"Archive(format)": "tar", "Alert(id)": "CORR-17-" + context["digest"][:4]}
    if builder == "archive_zip_support":
        with zipfile.ZipFile(artifact_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("diagnostics/summary.txt", f"Support bundle {context['digest']}\n")
            archive.writestr("logs/escalation.log", f"ticket={context['digest']} marker={context['flag']}\n")
            archive.writestr("attachments/operator.txt", f"operator={context['user']}\n")
        return {"Archive(format)": "zip", "Ticket(id)": "SUP-" + context["digest"][:6]}
    with gzip.open(artifact_path, "wt", encoding="utf-8") as handle:
        handle.write(f"May 27 authd[{context['digest']}]: accepted publickey for {context['user']}\n")
        handle.write(f"May 27 authd[{context['digest']}]: incident marker {context['flag']}\n")
    return {"Archive(format)": "gzip", "Compression(format)": "gzip"}


def _hash(builder: str, context: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == "hash_md5_token":
        digest = hashlib.md5((context["token"] + context["flag"]).encode()).hexdigest()
        return f"token_id={context['token']}\nmd5={digest}\n", {"Token(service)": context["token"], "Hash(value)": digest}
    if builder == "hash_sha3_audit":
        digest = hashlib.sha3_256((context["token"] + ":" + context["flag"]).encode()).hexdigest()
        return f"audit_token={context['token']}\nsha3_256={digest}\nflag_hint={context['digest']}\n", {"Token(service)": context["token"], "Hash(value)": digest}
    if builder == "hash_pbkdf2_phrase":
        digest = hashlib.pbkdf2_hmac("sha256", ("recover-" + context["flag"]).encode(), context["salt"].encode(), 12000).hex()
        return f"algorithm=pbkdf2-sha256\niterations=12000\nsalt={context['salt']}\ndigest={digest}\n", {"Hash(value)": digest, "Salt(value)": context["salt"]}
    if builder == "hash_salted_pin":
        digest = hashlib.sha256((context["salt"] + context["pin"] + context["flag"]).encode()).hexdigest()
        return f"operator={context['user']}\nsalt={context['salt']}\npin_digest={digest}\n", {"Credential(user,password)": f"{context['user']}:{context['pin']}", "Hash(value)": digest, "Salt(value)": context["salt"]}
    recovery_digest = hashlib.sha256(context["flag"].encode()).hexdigest()
    lines = [f"{_digest(context['flag'], 'release', length=64)}  release.tar", f"{recovery_digest}  recover.txt", f"{_digest(context['digest'], 'notes', length=64)}  notes.md"]
    return "\n".join(lines) + "\n", {"Hash(value)": recovery_digest}


def _text(builder: str, context: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == "text_runbook_escalation":
        content = f"Runbook Escalation\nTicket: RB-{context['digest'][:6]}\nTemporary access: {context['user']} / {context['password']}\nMarker: {context['flag']}\n"
        return content, {"Credential(user,password)": f"{context['user']}:{context['password']}", "Ticket(id)": "RB-" + context["digest"][:6]}
    if builder == "text_chatops_transcript":
        content = f"#deploy-war-room\n09:41 {context['user']}: token {context['token']} approved\n09:43 release-bot: marker {context['flag']}\n"
        return content, {"Token(service)": context["token"], "Ticket(id)": "CHAT-" + context["digest"][:6]}
    if builder == "text_license_memo":
        content = f"License renewal memo\nReference: LIC-{context['digest'][:8]}\nPortal token: {context['token']}\nRenewal marker: {context['flag']}\n"
        return content, {"Token(service)": context["token"]}
    if builder == "text_known_hosts":
        hostname = f"jump-{context['digest'][:6]}.lab.internal"
        content = f"# recovery marker {context['flag']}\n{hostname} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{context['digest']}\n"
        return content, {"Hostname(host)": hostname}
    content = f"Maintenance clipboard\nWindow: MW-{context['digest'][:6]}\nOwner: {context['user']}\nTask: preserve marker {context['flag']} before handoff\n"
    return content, {"Ticket(id)": "MW-" + context["digest"][:6], "Window(id)": "MW-" + context["digest"][:6]}


def build_artifact(variant_id: str, config: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    variant = VARIANTS[variant_id]
    seed = str(config.get("seed") or os.environ.get("SEED") or "seed")
    flag_prefix = str(config.get("flag_prefix") or os.environ.get("FLAG_PREFIX") or "FLAG")
    flag = str(config.get("Flag(flag_id)") or "").strip() or _flag(seed, variant_id, flag_prefix)
    context = _context(seed, variant_id, flag)
    relative_path = "artifacts/" + _safe_filename(config.get("File(path)"), variant["filename"])
    artifact_path = output_dir / relative_path
    builder = variant["builder"]
    if builder.startswith("archive_"):
        extra_outputs = _archive(builder, artifact_path, context)
    elif builder.startswith("hash_"):
        content, extra_outputs = _hash(builder, context)
        _write(artifact_path, content)
    else:
        content, extra_outputs = _text(builder, context)
        _write(artifact_path, content)
    delivery = "file" if variant["family"] == "text" else "embedded"
    outputs: dict[str, Any] = {"Flag(flag_id)": flag, "FlagDelivery(mode)": delivery, "File(path)": relative_path, "Checksum(sha256)": _sha256(artifact_path)}
    if delivery == "file":
        outputs["FlagFile(path)"] = relative_path
    outputs.update(extra_outputs)
    return {"schema_version": 1, "generator_id": variant_id, "outputs": outputs}


def main() -> int:
    parser = argparse.ArgumentParser(description="ScenarioForge artifact generator variants")
    parser.add_argument("--variant", default=os.environ.get("ARTIFACT_VARIANT_ID") or DEFAULT_VARIANT)
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH") or "/inputs/config.json")
    parser.add_argument("--output", "--out-dir", dest="output_dir", default=os.environ.get("OUT_DIR") or "/outputs")
    arguments = parser.parse_args()
    variant_id = str(arguments.variant or "").strip()
    if variant_id not in VARIANTS:
        raise SystemExit(f"Unknown artifact variant: {variant_id}")
    output_dir = Path(arguments.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    result = build_artifact(variant_id, _load_config(arguments.config), output_dir)
    (output_dir / "outputs.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
