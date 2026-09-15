#!/usr/bin/env python3
"""Rebuild participant hints from reviewed artifact recipes and service walkthroughs."""
import argparse
import ast
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
ANSWER = 'Answer: {{OUTPUT.Flag(flag_id)}}'
FILE = '{{OUTPUT.File(path):basename}}'
NODE = '{{THIS_NODE_NAME}}'
PORT = '{{OUTPUT.PortForward(host, port)}}'


class HintDumper(yaml.SafeDumper):
    pass


def hint_string(dumper, value):
    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style='|' if '\n' in value else None)


HintDumper.add_representer(str, hint_string)


def variant_spec(path, manifest):
    variant = manifest.get('env', {}).get('ARTIFACT_VARIANT_ID', str(manifest['id']))
    for statement in ast.parse(path.with_name('generator.py').read_text()).body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(t, ast.Name) and t.id == 'VARIANTS' for t in targets):
                return ast.literal_eval(statement.value).get(variant, {})
    return {}


def python_command(body):
    return "python3 - \"$artifact\" <<'PY'\nimport sys\nfrom pathlib import Path\np = Path(sys.argv[1])\n" + body + '\nPY'


ARCHIVES = {
    'archive_tgz_config': ('gzip-compressed tar', 'etc/app/recovery.flag', 'tar -xzOf'),
    'archive_zip_case': ('ZIP', 'case/evidence/recovery-note.txt', 'unzip -p'),
    'archive_tar_siem': ('tar', 'alerts/correlation-17.json', 'tar -xOf'),
    'archive_zip_support': ('ZIP', 'logs/escalation.log', 'unzip -p'),
    'archive_zip': ('ZIP', 'nested/recovery/flag.txt', 'unzip -p'),
    'archive_tar': ('tar', 'logs/app.log', 'tar -xOf'),
}
DECODERS = {
    'encoded_base64': ('Base64', 'import base64\nprint(base64.b64decode(p.read_bytes()).decode())'),
    'encoded_hex': ('hexadecimal', 'print(bytes.fromhex(p.read_text()).decode())'),
    'encoded_rot13': ('ROT13', 'import codecs\nprint(codecs.decode(p.read_text(), "rot_13"))'),
    'encoded_url': ('percent-encoded URL', 'from urllib.parse import unquote\nprint(unquote(p.read_text()))'),
    'enc_base32': ('Base32', 'import base64\nprint(base64.b32decode(p.read_text().strip()).decode())'),
    'enc_ascii85': ('Ascii85', 'import base64\nprint(base64.a85decode(p.read_text().strip()).decode())'),
    'enc_gzip_b64': ('Base64 around gzip', 'import base64, gzip\nprint(gzip.decompress(base64.b64decode(p.read_bytes())).decode())'),
    'enc_jwt': ('unsigned JWT with Base64URL claims', 'import base64, json\nclaims = p.read_text().split(".")[1]\nprint(json.dumps(json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))), indent=2))'),
}
HASH_DETAILS = {
    'hash_md5_token': 'The MD5 input is the token_id followed immediately by the flag; the token alone is not the answer.',
    'hash_sha3_audit': 'The SHA3-256 input is audit_token, a colon, and the flag. The short flag_hint is not a reversible encoding.',
    'hash_pbkdf2_phrase': 'The digest uses PBKDF2-HMAC-SHA256, 12,000 iterations, the printed salt, and the phrase recover- followed by the flag.',
    'hash_salted_pin': 'The digest is SHA256(salt + PIN + flag). Brute-forcing a PIN alone will not recover the flag.',
    'hash_manifest_gate': 'The recover.txt line contains SHA256(flag). It is a checksum entry; this artifact does not include recover.txt itself.',
    'hash_api': 'The digest is SHA256(api_key_id + flag). The exposed API key is a separate artifact.',
    'hash_sha1': 'The sha1 field hashes the service-account password. The username is printed beside it.',
    'hash_sha256': 'The sha256 field hashes password:token. A password-only digest will not match.',
    'hash_sha512': 'The audit phrase is hashed with SHA512, but the flag is also written directly in the flag field.',
    'hash_hmac': 'The flag is in the signed message body. HMAC-SHA256 authenticates that body; no HMAC cracking is needed.',
}


def artifact_hints(path, manifest):
    spec = variant_spec(path, manifest)
    builder = spec.get('builder', str(manifest['id']))
    name = manifest['name'].removeprefix('Sample: ')
    command = 'cat "$artifact"'
    low = 'Operational files can disclose more than their intended purpose.'
    clue = f'Inspect the {name} artifact as text and look for recovery, flag, marker, or credential fields.'
    detail = ''
    if builder in ARCHIVES:
        fmt, member, reader = ARCHIVES[builder]
        low = 'The useful evidence is inside a backup or evidence bundle.'
        clue = f'This is a {fmt} archive; list its members and inspect nested evidence files.'
        detail = f'The flag-bearing member is {member}.'
        command = f'{reader} "$artifact" {member}'
    elif builder == 'archive_gzip_log':
        low = 'A rotated log still contains an incident clue.'
        clue = 'Decompress the gzip log and inspect its incident marker line.'
        command = 'gzip -dc "$artifact"'
    elif builder in DECODERS:
        encoding, body = DECODERS[builder]
        low = 'The message is encoded rather than encrypted.'
        clue = f'The encoding is {encoding}; decode it to inspect the message fields.'
        command = python_command(body)
        if builder == 'encoded_url':
            detail = 'Decode the URL locally and read its flag query parameter; the example hostname does not need to be contacted.'
    elif builder == 'enc_morse':
        low = 'The punctuation is a signal alphabet.'
        clue = 'Decode the Morse tokens; spaces separate symbols and / separates words. Non-Morse punctuation is retained.'
        # The exact alphabet is defined in the artifact runtime.
        tree = ast.parse(path.with_name('generator.py').read_text())
        table = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'MORSE' for t in n.targets))
        command = python_command(f'table = {table!r}\ninverse = {{value: key for key, value in table.items()}}\nprint("".join(" " if word == "/" else inverse.get(word, word) for word in p.read_text().split()))')
        detail = 'This encoding uppercases letters; use the exact answer below if flag matching is case-sensitive.'
    elif builder.startswith('binary'):
        low = 'Human-readable data may survive inside a binary artifact.'
        clue = 'Inspect the file signature and printable strings before attempting to execute anything.'
        command = 'strings -a "$artifact"'
        if builder == 'binary_xor':
            clue = 'The CORETG-XOR header is followed by a one-byte XOR key and an encoded flag.'
            command = python_command('data = p.read_bytes()\nstart = data.index(b"CORETG-XOR") + len(b"CORETG-XOR")\nkey = data[start]\nend = data.index(b"\\x00loader telemetry", start + 1)\nprint(bytes(byte ^ key for byte in data[start + 1:end]).decode())')
        elif builder == 'binary_magic':
            clue = 'After CTGPAYLOAD, a two-byte big-endian length describes the following text payload.'
            command = python_command('data = p.read_bytes()\nstart = len(b"CTGPAYLOAD")\nsize = int.from_bytes(data[start:start + 2], "big")\nprint(data[start + 2:start + 2 + size].decode())')
    elif builder in HASH_DETAILS or builder == 'hash_shadow':
        low = 'Separate the digest from the account or recovery information stored beside it.'
        clue = 'Identify the digest input and any salt before testing a candidate. A hash is not a reversible text encoding.'
        detail = HASH_DETAILS.get(builder, 'This shadow-like record uses a custom SHA512(salt + value) hex digest, not standard SHA512-crypt despite its $6$ prefix.')
        if builder == 'hash_shadow':
            detail += ' The value is ' + ('the flag.' if str(manifest['id']) == 'hash_shadow_credential' else 'the password.')
    elif builder == 'md5_password_hash':
        low = 'A short password can be recognizable from its legacy digest.'
        clue = 'Read the MD5 Hash field and test a common five-letter greeting.'
        detail = 'The password is hello. The submitted flag for this recipe is the MD5 digest itself, not the plaintext password.'
        command = "printf %s hello | md5sum"
    elif builder == 'Steganography_Drop':
        low = 'An ordinary-looking image may carry hidden account information.'
        clue = 'Read RGB least-significant bits in pixel order. The first 32 bits give the payload byte count in big-endian order.'
        command = python_command('from PIL import Image\nimage = Image.open(p).convert("RGB")\nbits = "".join(str(channel & 1) for pixel in image.getdata() for channel in pixel)\nsize = int(bits[:32], 2)\nprint(bytes(int(bits[i:i+8], 2) for i in range(32, 32 + 8 * size, 8)).decode())')
        detail = 'Requires Pillow. The hidden payload is user|password; the flag is supplied separately below. If the artifact is plain text, read it directly.'
    elif builder.startswith('https') or builder == 'http_page_flag_generator':
        low = 'Web content and its source can expose operational secrets.'
        clue = 'Read the injected HTML, JSON, or robots-style file, including comments. This artifact does not create its own HTTPS listener.'
    elif builder.startswith('formatted'):
        low = 'Structured exports can contain sensitive fields alongside ordinary records.'
        clue = 'Inspect the flag or recovery_flag field and adjacent account fields in the structured export.'
    elif not builder.startswith('text'):
        raise ValueError(f'Unreviewed artifact builder: {builder}')
    medium = [f'Artifact on {NODE}: {FILE}.', clue]
    high = [ANSWER]
    if detail:
        high.append(detail)
    high.append('On the target, or after copying the artifact locally, set artifact to its actual path; this example assumes the current directory.\n```bash\nartifact="./' + FILE + '"\n' + command + '\n```')
    return {'low': [low], 'medium': medium, 'high': high}


def node_hints(path, manifest):
    gid = str(manifest['id'])
    steps = manifest.get('access_instructions', {}).get('steps', [])
    text = '\n'.join(str(step.get('instructions') or '') for step in steps)
    produces = manifest.get('artifacts', {}).get('produces', [])
    canonical = {key.replace(' ', ''): key for key in produces}
    def output(key):
        return '{{OUTPUT.' + canonical[key.replace(' ', '')] + '}}'
    title = manifest.get('access_instructions', {}).get('title', manifest['name'])
    low = {
        'cache': 'Applications sometimes leave reusable secrets in cached records.',
        'database': 'Exported records may expose information beyond the database login.',
        'dns': 'Service records can reveal more than host addresses.',
        'ftp': 'Inspect the files exposed through the transfer service.',
        'git': 'Repository files can retain deployment secrets.',
        'ldap': 'Directory entries may disclose operational notes as well as account names.',
        'mail': 'Retained messages can contain handoff notes and access details.',
        'mqtt': 'Consider what messages a subscriber can receive.',
        'smb': 'Shared folders may expose internal records to an unintended reader.',
        'http': 'Explore the portal and the operational records it makes available.',
    }.get(path.parent.parent.name, 'Explore the exposed service and its operational records.')
    for marker, clue in [
        ('dep_', 'A finding from an earlier challenge is the input to this service.'),
        ('cookie', 'Consider whether the client controls the claimed role.'),
        ('traversal', 'Check how the document service confines requested file paths.'),
        ('sqli', 'Consider how search input affects which records are returned.'),
        ('source', 'Published source code can expose secrets as well as functionality.'),
        ('backup', 'Backup material can preserve sensitive information.'),
        ('ssh_', 'The account home directory may contain useful operational records.'),
        ('nfs_', 'Shared files can expose information beyond the public service interface.'),
    ]:
        if marker in gid:
            low = clue
            break
    medium = [f'Service: {title}. Target: {NODE}; TCP port: {PORT}.',
              f'Check the assigned port:\n```bash\nnmap -sT -sV -p {PORT} {NODE}\n```']
    if 'MountdPort(port)' in canonical:
        medium.append('The NFSv3 mount daemon also uses TCP port ' + output('MountdPort(port)') + '.')
    if 'Directory(host,path)' in canonical and path.parent.parent.name == 'nfs':
        medium.append('Share or export: ' + output('Directory(host,path)') + '.')
    high = [ANSWER]
    if 'Credential(user,password)' in canonical:
        high.append('Credential (user:password): ' + output('Credential(user,password)') + '. Replace <username> and <password> in the commands with these two components.')
    mapping = {'NODE': NODE, 'NODE_IP': NODE, 'PORT': PORT,
               'FLAG_FILE': output('FlagFile(path)'), 'USERNAME': '<username>', 'PASSWORD': '<password>',
               'TIMEOUT_SECONDS': 'the configured idle timeout'}
    for alias, key in [('PATH', 'Directory(host,path)'), ('KEY_FILE', 'SSHPrivateKey(path)'),
                       ('TOKEN', 'Token(service)'), ('MOUNTD_PORT', 'MountdPort(port)')]:
        if key.replace(' ', '') in canonical:
            mapping[alias] = output(key)
    if gid == 'nfs_sensitive_file':
        # This older sample exports a bare name and a host-relative flag path.
        mapping['PATH'] = '/' + output('Directory(host,path)')
        mapping['FLAG_FILE'] = '{{OUTPUT.FlagFile(path):basename}}'
    if 'nc {{NODE}}' in text:
        medium.append('This service accepts a line-oriented text protocol. Connect with nc, then enter the commands shown in the high hint in that same session.')
    if gid.startswith('dep_'):
        requirement = next(key for key in manifest['artifacts']['requires'] if key != 'Knowledge(ip)')
        medium.append('Required earlier finding: ' + requirement + '. Use its exact value from the preceding challenge.')
        headers = {'dep_api_key_admin_endpoint': 'X-API-Key', 'dep_checksum_evidence_gate': 'X-Checksum-SHA256',
                   'dep_file_parser_console': 'X-File-Path', 'dep_port_forward_pivot': 'X-Port-Forward',
                   'dep_ticket_attachment_portal': 'X-Ticket-ID', 'dep_version_exploit_selector': 'X-Service-Version',
                   'dep_webauth_bypass_console': 'X-Auth-Bypass', 'dep_ssh_key_bastion': 'X-SSH-Key-Path'}
        header = headers.get(gid)
        high.append('This gate uses HTTP. ' + ('Replace <prior-value> with the earlier ' + requirement + '. ' if header else '')
                    + '\n```bash\ncurl ' + (f"-H '{header}: <prior-value>' " if header else '')
                    + f"'http://{NODE}:{PORT}" + output('Endpoint(path)') + "'\n```")
    else:
        for step in steps:
            instructions = str(step.get('instructions') or '').strip()
            if not instructions or str(step.get('title', '')).lower().startswith('record'):
                continue
            instructions = re.sub(r'\{\{([A-Z_]+)\}\}', lambda m: mapping[m[1]], instructions)
            instructions = instructions.replace('<user>', '<username>')
            if gid in {'nfs_backup_archive_passphrase', 'nfs_legacy_nfs3_share', 'nfs_readonly_audit_share'}:
                instructions = instructions.replace(':/' + output('Directory(host,path)'), ':' + output('Directory(host,path)'))
            instructions = instructions.replace("-d 'username=<username>&password=<password>'", "--data-urlencode 'username=<username>' --data-urlencode 'password=<password>'")
            instructions = instructions.replace('Idle sessions expire after about the configured idle timeout seconds.', 'The shell has an idle timeout; read the file promptly.')
            # URL spaces must be encoded, even inside shell quotes.
            instructions = instructions.replace("=' OR '1'='1", "=%27%20OR%20%271%27=%271")
            # The credentials above are used manually at the protocol prompt.
            high.append(str(step.get('title') or title) + ':\n' + instructions)
        if gid == 'https_token_debug_api':
            high.append('Request the admin profile with an unsigned role claim:\n```bash\n'
                        + "token=$(python3 -c 'import base64; print(base64.urlsafe_b64encode(b\"{\\\"role\\\":\\\"admin\\\"}\").decode().rstrip(\"=\"))')\n"
                        + f'curl -k --get --data-urlencode "token=$token" "https://{NODE}:{PORT}/api/profile"\n```')
    return {'low': [low], 'medium': medium, 'high': high}


def build_hints(path, manifest):
    hints = artifact_hints(path, manifest) if manifest['kind'] == 'flag-generator' else node_hints(path, manifest)
    if manifest['kind'] == 'flag-generator':
        for key in manifest.get('artifacts', {}).get('produces', []):
            if key.replace(' ', '') in {'Credential(user,password)', 'APIKey(service)', 'Token(service)', 'DecryptionKey(value)'}:
                hints['high'].append(key + ': {{OUTPUT.' + key + '}}')
    return hints


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    paths = sorted(p for directory in ['flag_generators', 'flag_node_generators'] for p in (ROOT / directory).rglob('manifest.yaml'))
    changed = []
    for path in paths:
        raw = path.read_text()
        manifest = yaml.safe_load(raw)
        hints = build_hints(path, manifest)
        # Replace only hint fields; preserve runtime, inputs, notes and author formatting.
        replacement = yaml.dump({'hint_levels': hints}, Dumper=HintDumper, sort_keys=False, allow_unicode=True, width=120)
        updated = re.sub(r'^hint_levels:\n.*?(?=^[^\s#]|\Z)', lambda _: replacement, raw, flags=re.M | re.S)
        # Legacy consumers should receive a useful low hint without answer leaks.
        for key in ['hint_template', 'hint_templates']:
            if key in manifest:
                value = hints['low'][0] if key == 'hint_template' else hints['low']
                block = yaml.safe_dump({key: value}, sort_keys=False, allow_unicode=True, width=100)
                # YAML sequence entries at column zero belong to the field.
                updated = re.sub(r'^' + key + r':.*?(?=^(?!-)[A-Za-z_][A-Za-z_0-9]*:|\Z)', lambda _: block, updated, flags=re.M | re.S)
        if updated != raw:
            changed.append(path)
            if not args.check:
                path.write_text(updated)
    if args.check and changed:
        raise SystemExit(f'{len(changed)} generator manifests need hint regeneration')
    print(f'{"Checked" if args.check else "Updated"} hints for {len(paths)} generators ({len(changed)} changed).')


if __name__ == '__main__':
    main()
