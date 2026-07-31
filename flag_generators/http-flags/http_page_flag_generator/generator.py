import hashlib
import json
import os
from pathlib import Path


def _read_config() -> dict:
    try:
        return json.loads(Path("/inputs/config.json").read_text("utf-8"))
    except Exception:
        return {}


def _derive_credentials(seed: str, username: str, password: str) -> tuple[str, str]:
    if username and password:
        return username, password
    h = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()
    user = f"user_{h[:8]}"
    pw = f"pass_{h[8:16]}"
    return user, pw


def _derive_flag(seed: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{generator_id}|flag".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def _generate_html_page(username: str, password: str, flag: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Flag Page</title>
    <style>
        body {{ font-family: monospace; padding: 20px; }}
        .credentials {{ background: #f0f0f0; padding: 10px; margin: 10px 0; }}
        .flag {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Flag Page</h1>
    <div class="credentials">
        <strong>Username:</strong> {username}<br>
        <strong>Password:</strong> {password}
    </div>
    <div class="flag">
        <strong>Flag:</strong> {flag}
    </div>
</body>
</html>"""


def main() -> None:
    cfg = _read_config()
    seed = str(cfg.get("seed") or "").strip()
    username = str(cfg.get("username") or "").strip()
    password = str(cfg.get("password") or "").strip()
    flag_prefix = str(cfg.get("flag_prefix") or "FLAG").strip() or "FLAG"
    generator_id = str(cfg.get("generator_id") or "http_page_flag_generator").strip()

    if not seed:
        raise SystemExit("Missing seed in /inputs/config.json")

    user, pw = _derive_credentials(seed, username, password)
    flag_value = _derive_flag(seed, generator_id, flag_prefix)
    html_content = _generate_html_page(user, pw, flag_value)

    out_dir = Path("/outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    html_file_path = artifacts_dir / "flag_page.html"
    html_file_path.write_text(html_content, encoding="utf-8")

    outputs = {
        "generator_id": generator_id,
        "outputs": {
            "Flag(flag_id)": flag_value,
            "File(path)": "artifacts/flag_page.html",
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
