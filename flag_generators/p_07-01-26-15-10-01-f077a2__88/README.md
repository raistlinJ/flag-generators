# Steganography Drop Generator

This generator embeds a username/password into an image using steganography techniques.

## Usage

```bash
docker-compose run generator --seed "your_seed" --flag_prefix "FLAG"
```

## Outputs

- `Flag(flag_id)`: The generated flag
- `Credential(user,password)`: The embedded credentials
- `File(path)`: The steganography image file
