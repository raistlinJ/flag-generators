# HTTP Page Flag Generator

Generates an HTML page containing embedded credentials and a deterministic flag.

## Usage

```bash
python generator.py --seed <seed> --username <user> --password <pass>
```

## Outputs

- `Flag(flag_id)`: Deterministic flag value
- `File(path)`: HTML file with embedded credentials
