import hashlib
import json
import os
from pathlib import Path


def _read_config() -> dict:
    try:
        return json.loads(Path("/inputs/config.json").read_text("utf-8"))
    except Exception:
        return {}


def _generate_md5_hash(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def main() -> None:
    cfg = _read_config()
    seed = str(cfg.get("seed") or "").strip()

    if not seed:
        raise SystemExit("Missing seed in /inputs/config.json")

    # Use a common 5-letter word for the password
    password = "hello"
    md5_hash = _generate_md5_hash(password)
    
    # Create artifact file with ONLY the hash (no password included)
    artifacts_dir = Path("/outputs/artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    hash_file_path = artifacts_dir / "md5_hash.txt"
    hash_file_path.write_text(f"MD5 Hash: {md5_hash}\n", encoding="utf-8")

    outputs = {
        "generator_id": "md5_password_hash",
        "outputs": {
            "Flag(flag_id)": md5_hash,
            "Credential(user,password)": password,
            "File(path)": "artifacts/md5_hash.txt",
        },
    }

    out_dir = Path("/outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
