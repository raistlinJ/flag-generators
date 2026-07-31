import argparse
import hashlib
import json
import os
import struct
from pathlib import Path


def _load_config(path: str) -> dict:
    if not path:
        return {}
    try:
        p = Path(path)
        if not p.exists():
            return {}
        data = json.loads(p.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _derive_user_pass(seed: str) -> tuple[str, str]:
    h = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()
    user = f"user_{h[:6]}"
    pw = f"pw_{h[6:14]}"
    return user, pw


def _derive_flag(seed: str, generator_id: str, flag_prefix: str) -> str:
    base = f"{seed}|{generator_id}".encode("utf-8", "replace")
    digest = hashlib.sha256(base).hexdigest()[:24]
    prefix = (flag_prefix or "FLAG").strip() or "FLAG"
    return f"{prefix}{{{digest}}}"


def _create_real_image(output_path: str) -> None:
    """Create a real, viewable PNG image using PIL."""
    from PIL import Image
    
    # Create a 100x100 gradient image
    img = Image.new('RGB', (100, 100), color='white')
    pixels = img.load()
    
    for y in range(100):
        for x in range(100):
            # Create a gradient from blue to red
            r = int(255 * x / 100)
            g = int(255 * (1 - x / 100))
            b = int(255 * y / 100)
            pixels[x, y] = (r, g, b)
    
    # Add a visible marker (a small red square)
    for y in range(45, 55):
        for x in range(45, 55):
            pixels[x, y] = (255, 0, 0)
    
    img.save(output_path, 'PNG')


def _embed_credentials(image_path: str, user: str, password: str, output_path: str) -> bool:
    """Embed credentials into image using LSB steganography."""
    try:
        from PIL import Image
        
        # Load image
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Convert credentials to bytes
        credentials = f"{user}|{password}".encode('utf-8')
        
        # Add length prefix (4 bytes)
        length_bytes = struct.pack('>I', len(credentials))
        data = length_bytes + credentials
        
        # Convert to binary string
        binary_data = ''.join(format(byte, '08b') for byte in data)
        
        # Pad to fit image
        max_bits = img.width * img.height * 3  # 3 channels per pixel
        if len(binary_data) > max_bits:
            raise ValueError("Data too large for image")
        
        # Embed in LSB
        pixels = list(img.getdata())
        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            if bit_index >= len(binary_data):
                new_pixels.append(pixel)
                continue
            
            r, g, b = pixel
            
            # Embed in R channel
            if bit_index < len(binary_data):
                r = (r & 0xFE) | int(binary_data[bit_index])
                bit_index += 1
            
            # Embed in G channel
            if bit_index < len(binary_data):
                g = (g & 0xFE) | int(binary_data[bit_index])
                bit_index += 1
            
            # Embed in B channel
            if bit_index < len(binary_data):
                b = (b & 0xFE) | int(binary_data[bit_index])
                bit_index += 1
            
            new_pixels.append((r, g, b))
        
        # Create new image
        new_img = Image.new('RGB', img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path, 'PNG')
        
        return True
        
    except ImportError:
        # Fallback: create a text file with credentials if PIL not available
        Path(output_path).write_text(f"{user}|{password}", encoding='utf-8')
        return True
    except Exception as e:
        print(f"Error embedding credentials: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Steganography Drop Generator")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", ""))
    ap.add_argument("--seed", default=os.environ.get("SEED", ""))
    ap.add_argument("--flag-prefix", default=os.environ.get("FLAG_PREFIX", "FLAG"))
    ap.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "out"))
    ap.add_argument("--image-path", default=os.environ.get("IMAGE_PATH", ""))
    args = ap.parse_args()

    cfg = _load_config(args.config)
    seed = str(args.seed or cfg.get("seed") or "seed")
    flag_prefix = str(args.flag_prefix or cfg.get("flag_prefix") or cfg.get("flag-prefix") or "FLAG")
    image_path = str(args.image_path or cfg.get("image_path") or "")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    user, pw = _derive_user_pass(seed)
    generator_id = str(cfg.get("generator_id") or "steganography_drop")
    flag_value = _derive_flag(seed, generator_id, flag_prefix)

    # Create steganography image
    image_output_path = artifacts_dir / "stego_image.png"
    
    if image_path and Path(image_path).exists():
        _embed_credentials(image_path, user, pw, str(image_output_path))
    else:
        # Create a real, viewable image if no input image provided
        _create_real_image(str(image_output_path))
        _embed_credentials(str(image_output_path), user, pw, str(image_output_path))

    outputs = {
        "generator_id": generator_id,
        "outputs": {
            "Flag(flag_id)": flag_value,
            "Credential(user,password)": f"{user}:{pw}",
            "File(path)": str(image_output_path.relative_to(out_dir)),
        },
    }

    (out_dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
