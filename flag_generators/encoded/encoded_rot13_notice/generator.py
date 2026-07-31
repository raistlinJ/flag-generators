import argparse
import base64
import csv
import hashlib
import io
import json
import os
import tarfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any


VARIANTS: dict[str, dict[str, Any]] = {
    "binary_xor_loader_blob": {"pack": "binary", "filename": "loader_diag.bin", "builder": "binary_xor", "delivery": "embedded"},
    "binary_license_checker": {"pack": "binary", "filename": "license_check.bin", "builder": "binary_license", "delivery": "embedded"},
    "binary_firmware_config_blob": {"pack": "binary", "filename": "sensor_firmware_v3.img", "builder": "binary_firmware", "delivery": "embedded"},
    "binary_magic_header_payload": {"pack": "binary", "filename": "capture_payload.dat", "builder": "binary_magic", "delivery": "embedded"},
    "text_support_ticket_dump": {"pack": "text", "filename": "support_ticket_4172.txt", "builder": "text_ticket", "delivery": "file"},
    "text_ops_readme_note": {"pack": "text", "filename": "README.ops.txt", "builder": "text_readme", "delivery": "file"},
    "text_env_backup_creds": {"pack": "text", "filename": ".env.backup", "builder": "text_env", "delivery": "file"},
    "text_chat_export_token": {"pack": "text", "filename": "chat_export.txt", "builder": "text_chat", "delivery": "file"},
    "encoded_base64_dispatch": {"pack": "encoded", "filename": "dispatch_note.b64", "builder": "encoded_base64", "delivery": "embedded"},
    "encoded_hex_payload": {"pack": "encoded", "filename": "incident_payload.hex", "builder": "encoded_hex", "delivery": "embedded"},
    "encoded_rot13_notice": {"pack": "encoded", "filename": "hr_notice.rot13", "builder": "encoded_rot13", "delivery": "embedded"},
    "encoded_url_callback": {"pack": "encoded", "filename": "callback_url.txt", "builder": "encoded_url", "delivery": "embedded"},
    "formatted_json_profile_secret": {"pack": "formatted", "filename": "service-profile.json", "builder": "formatted_json", "delivery": "file"},
    "formatted_yaml_deploy_config": {"pack": "formatted", "filename": "deploy-values.yaml", "builder": "formatted_yaml", "delivery": "file"},
    "formatted_ini_database_config": {"pack": "formatted", "filename": "database.ini", "builder": "formatted_ini", "delivery": "file"},
    "formatted_csv_user_export": {"pack": "formatted", "filename": "user-export.csv", "builder": "formatted_csv", "delivery": "file"},
    "archive_zip_nested_evidence": {"pack": "archives", "filename": "evidence_bundle.zip", "builder": "archive_zip", "delivery": "embedded"},
    "archive_tar_log_bundle": {"pack": "archives", "filename": "ops_logs.tar", "builder": "archive_tar", "delivery": "embedded"},
    "hash_shadow_credential": {"pack": "hashes", "filename": "shadow.fragment", "builder": "hash_shadow", "delivery": "embedded"},
    "hash_api_key_digest": {"pack": "hashes", "filename": "api_key_digest.txt", "builder": "hash_api", "delivery": "embedded"},
}


def _load_config(config_path: str, input_dir: str) -> dict[str, Any]:
    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    if input_dir:
        candidates.append(Path(input_dir) / "config.json")
    for path in candidates:
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            continue
    return {}


def _digest(text: str, length: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:length]


def _derive_flag(seed: str, generator_id: str, flag_prefix: str) -> str:
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{_digest(seed + '|' + generator_id, 24)}}}"


def _safe_name(raw: Any, default: str) -> str:
    text = str(raw or "").replace("\\", "/").split("/")[-1].strip()
    if not text or text in {".", ".."}:
        return default
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return cleaned or default


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _context(seed: str, generator_id: str, flag: str) -> dict[str, str]:
    digest = _digest(seed + generator_id, 12)
    user = f"svc_{digest[:6]}"
    password = f"Pass-{digest[6:]}!"
    token = f"tok_{_digest(generator_id + seed, 20)}"
    api_key = f"ak_{_digest(seed + ':api:' + generator_id, 24)}"
    return {"digest": digest, "user": user, "password": password, "token": token, "api_key": api_key, "flag": flag}


def _binary_blob(builder: str, ctx: dict[str, str]) -> tuple[bytes, dict[str, Any]]:
    flag = ctx["flag"]
    digest = ctx["digest"]
    if builder == "binary_xor":
        key = int(digest[:2], 16) or 41
        encoded = bytes(b ^ key for b in flag.encode("utf-8"))
        blob = b"\x7fELF\x02\x01\x01CORETG-XOR" + bytes([key]) + encoded + b"\x00loader telemetry\x00"
        return blob, {"Binary(architecture)": "x86_64", "Encoding(name)": "xor", "DecryptionKey(value)": str(key)}
    if builder == "binary_license":
        blob = b"MZ\x90\x00CORETG-LICENSE-CHECK\x00" + f"licensee=field-ops\nserial={ctx['token']}\nflag={flag}\n".encode("utf-8")
        return blob, {"Binary(format)": "pe-like", "Token(service)": ctx["token"]}
    if builder == "binary_firmware":
        blob = b"FWR1" + bytes.fromhex(_digest(flag, 32)) + f"\nmodel=relay-sensor\nchannel=ops\nrecovery={flag}\n".encode("utf-8")
        return blob, {"Binary(format)": "firmware-image", "Version(service)": "relay-sensor/3.4.7"}
    blob = b"CTGPAYLOAD" + len(flag).to_bytes(2, "big") + flag.encode("utf-8") + b"\x00\xff\x00capture trailer\n"
    return blob, {"Binary(format)": "magic-header-payload"}


def _build_text(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == "text_ticket":
        body = (
            "Ticket: INC-4172\nQueue: identity-support\n"
            f"Temporary account: {ctx['user']} / {ctx['password']}\n"
            f"Resolution note: place recovery marker {ctx['flag']} in the handoff folder.\n"
        )
        return body, {"Ticket(id)": "INC-4172", "Credential(user, password)": f"{ctx['user']}:{ctx['password']}"}
    if builder == "text_readme":
        body = f"Operations README\n=================\nCluster: blue-floor\nRecovery flag: {ctx['flag']}\nReference: {ctx['digest']}\n"
        return body, {"Knowledge(value)": "blue-floor"}
    if builder == "text_env":
        body = f"APP_ENV=staging\nSERVICE_USER={ctx['user']}\nSERVICE_PASSWORD={ctx['password']}\nAPI_KEY={ctx['api_key']}\nFLAG={ctx['flag']}\n"
        return body, {"Credential(user, password)": f"{ctx['user']}:{ctx['password']}", "APIKey(service)": ctx["api_key"]}
    body = f"#channel: release-war-room\n09:14 {ctx['user']}: token rotated to {ctx['token']}\n09:17 ops: final marker {ctx['flag']}\n"
    return body, {"Token(service)": ctx["token"]}


def _build_encoded(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    message = f"handoff={ctx['flag']}; ticket={ctx['digest']}; owner={ctx['user']}"
    if builder == "encoded_base64":
        encoded = base64.b64encode(message.encode("utf-8")).decode("ascii")
        return encoded + "\n", {"Encoding(name)": "base64", "Encoded(value)": encoded}
    if builder == "encoded_hex":
        encoded = message.encode("utf-8").hex()
        return encoded + "\n", {"Encoding(name)": "hex", "Encoded(value)": encoded}
    if builder == "encoded_rot13":
        encoded = _rot13(message)
        return encoded + "\n", {"Encoding(name)": "rot13", "Encoded(value)": encoded}
    callback = f"https://ops.example.invalid/callback?token={ctx['token']}&flag={ctx['flag']}"
    encoded = urllib.parse.quote(callback, safe="")
    return encoded + "\n", {"Encoding(name)": "urlencode", "Encoded(value)": encoded, "Endpoint(path)": "/callback"}


def _build_formatted(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == "formatted_json":
        data = {"service": "inventory-api", "owner": ctx["user"], "api_key": ctx["api_key"], "recovery_flag": ctx["flag"]}
        return json.dumps(data, indent=2) + "\n", {"Format(name)": "json", "APIKey(service)": ctx["api_key"]}
    if builder == "formatted_yaml":
        body = f"service:\n  name: billing-worker\n  user: {ctx['user']}\n  password: {ctx['password']}\n  recovery_flag: {ctx['flag']}\n"
        return body, {"Format(name)": "yaml", "Credential(user, password)": f"{ctx['user']}:{ctx['password']}"}
    if builder == "formatted_ini":
        body = f"[database]\nhost=db.internal\nusername={ctx['user']}\npassword={ctx['password']}\nflag={ctx['flag']}\n"
        return body, {"Format(name)": "ini", "Credential(user, password)": f"{ctx['user']}:{ctx['password']}"}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["username", "role", "token", "flag"])
    writer.writerow([ctx["user"], "auditor", ctx["token"], ctx["flag"]])
    return buffer.getvalue(), {"Format(name)": "csv", "Token(service)": ctx["token"]}


def _write_archive(builder: str, path: Path, ctx: dict[str, str]) -> dict[str, Any]:
    if builder == "archive_zip":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", "Evidence export from document review.\n")
            archive.writestr("nested/recovery/flag.txt", ctx["flag"] + "\n")
            archive.writestr("nested/recovery/operator.txt", ctx["user"] + "\n")
        return {"Archive(format)": "zip"}
    with tarfile.open(path, "w") as archive:
        entries = {
            "logs/app.log": f"INFO token={ctx['token']}\nWARN recovery flag {ctx['flag']}\n",
            "logs/owners.txt": f"owner={ctx['user']}\n",
        }
        for name, content in entries.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return {"Archive(format)": "tar", "Token(service)": ctx["token"]}


def _build_hash(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == "hash_shadow":
        salt = _digest(ctx["user"], 8)
        digest = hashlib.sha512((salt + ctx["flag"]).encode("utf-8")).hexdigest()
        shadow_hash = f"$6${salt}${digest}"
        return f"{ctx['user']}:{shadow_hash}:19076:0:99999:7:::\n", {"Credential(user)": ctx["user"], "Credential(user, hash)": f"{ctx['user']}:{shadow_hash}", "Hash(value)": shadow_hash}
    digest = hashlib.sha256((ctx["api_key"] + ctx["flag"]).encode("utf-8")).hexdigest()
    body = f"service=payments\napi_key_id={ctx['api_key']}\nsha256={digest}\n"
    return body, {"APIKey(service)": ctx["api_key"], "Hash(value)": digest}


def build_artifact(variant_id: str, cfg: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    spec = VARIANTS[variant_id]
    seed = str(cfg.get("seed") or os.environ.get("SEED") or "seed")
    flag_prefix = str(cfg.get("flag_prefix") or cfg.get("flag-prefix") or os.environ.get("FLAG_PREFIX") or "FLAG")
    flag = str(cfg.get("Flag(flag_id)") or "").strip() or _derive_flag(seed, variant_id, flag_prefix)
    ctx = _context(seed, variant_id, flag)
    filename = _safe_name(cfg.get("File(path)"), str(spec["filename"]))
    rel_path = f"artifacts/{filename}"
    artifact_path = out_dir / rel_path
    builder = str(spec["builder"])

    extra: dict[str, Any]
    if builder.startswith("binary_"):
        blob, extra = _binary_blob(builder, ctx)
        _write_bytes(artifact_path, blob)
    elif builder.startswith("text_"):
        content, extra = _build_text(builder, ctx)
        _write_text(artifact_path, content)
    elif builder.startswith("encoded_"):
        content, extra = _build_encoded(builder, ctx)
        _write_text(artifact_path, content)
    elif builder.startswith("formatted_"):
        content, extra = _build_formatted(builder, ctx)
        _write_text(artifact_path, content)
    elif builder.startswith("archive_"):
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        extra = _write_archive(builder, artifact_path, ctx)
    elif builder.startswith("hash_"):
        content, extra = _build_hash(builder, ctx)
        _write_text(artifact_path, content)
    else:
        raise SystemExit(f"Unknown builder for {variant_id}: {builder}")

    checksum = _sha256_file(artifact_path)
    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag,
        "FlagDelivery(mode)": str(spec.get("delivery") or "file"),
        "File(path)": rel_path,
        "Checksum(sha256)": checksum,
    }
    if outputs["FlagDelivery(mode)"] == "file":
        outputs["FlagFile(path)"] = rel_path
    outputs.update(extra)
    return {
        "schema_version": 1,
        "generator_id": variant_id,
        "outputs": outputs,
        "handoff": {"hints": [{"kind": "artifact", "text": f"Inspect {rel_path} for the generated handoff material."}]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CORE TopoGen artifact flag generator variants")
    parser.add_argument("--variant", default=os.environ.get("ARTIFACT_VARIANT_ID", ""))
    parser.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    parser.add_argument("--input", default=os.environ.get("INPUT_DIR", ""))
    parser.add_argument("--output", "--out-dir", dest="out_dir", default=os.environ.get("OUT_DIR", "out"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    if not variant_id:
        raise SystemExit("Missing --variant or ARTIFACT_VARIANT_ID")
    if variant_id not in VARIANTS:
        raise SystemExit(f"Unknown artifact variant: {variant_id}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = _load_config(args.config, args.input)
    cfg.setdefault("generator_id", variant_id)
    manifest = build_artifact(variant_id, cfg, out_dir)
    (out_dir / "outputs.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
