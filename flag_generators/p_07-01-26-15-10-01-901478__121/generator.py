import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_VARIANT = "hash_hmac_message_signature"
VARIANTS = {'binary_bootloader_recovery': {'builder': 'binary_boot',
                                'description': 'Generate a bootloader-style image that stores a '
                                               'recovery flag in device metadata.',
                                'family': 'binary',
                                'filename': 'bootloader_recovery.img',
                                'inject_paths': ['/boot/recovery',
                                                 '/opt/firmware',
                                                 '/var/lib/device',
                                                 '/srv/images'],
                                'low_hint': 'The recovery image name is a useful starting point on '
                                            '{{NEXT_NODE_NAME}}.',
                                'name': 'Binary: Bootloader Recovery Image',
                                'produces_extra': ['Binary(format)', 'Checksum(sha256)']},
 'binary_core_dump_marker': {'builder': 'binary_core',
                             'description': 'Generate a pseudo core dump segment with a '
                                            'recoverable marker embedded among memory strings.',
                             'family': 'binary',
                             'filename': 'core_dump_segment.bin',
                             'inject_paths': ['/var/crash',
                                              '/opt/diagnostics',
                                              '/tmp/corefiles',
                                              '/srv/debug'],
                             'low_hint': 'Inspect the recovered binary artifact on '
                                         '{{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}.',
                             'name': 'Binary: Core Dump Marker',
                             'produces_extra': ['Binary(format)', 'Checksum(sha256)']},
 'binary_debug_symbols_note': {'builder': 'binary_symbols',
                               'description': 'Generate a symbol-table-like binary artifact with a '
                                              'recovery marker hidden in debug data.',
                               'family': 'binary',
                               'filename': 'symbols.symtab',
                               'inject_paths': ['/usr/lib/debug',
                                                '/opt/symbols',
                                                '/srv/build/debug',
                                                '/var/cache/symbols'],
                               'low_hint': 'Inspect the debug symbols artifact placed on '
                                           '{{NEXT_NODE_NAME}}.',
                               'name': 'Binary: Debug Symbols Note',
                               'produces_extra': ['Binary(format)', 'Checksum(sha256)']},
 'binary_heap_snapshot_token': {'builder': 'binary_heap',
                                'description': 'Generate a heap snapshot style binary with '
                                               'token-like strings and one embedded flag.',
                                'family': 'binary',
                                'filename': 'heap_snapshot.bin',
                                'inject_paths': ['/var/tmp/snapshots',
                                                 '/opt/app/debug',
                                                 '/srv/support/dumps',
                                                 '/tmp/heap'],
                                'low_hint': 'Search memory-like strings in the snapshot on '
                                            '{{NEXT_NODE_NAME}}.',
                                'name': 'Binary: Heap Snapshot Token',
                                'produces_extra': ['Binary(format)', 'Checksum(sha256)']},
 'binary_packet_capture_blob': {'builder': 'binary_pcap',
                                'description': 'Generate a compact capture-like binary payload '
                                               'with the flag hidden in packet metadata.',
                                'family': 'binary',
                                'filename': 'capture_frame_payload.bin',
                                'inject_paths': ['/var/log/network',
                                                 '/opt/captures',
                                                 '/srv/pcap',
                                                 '/tmp/netdumps'],
                                'low_hint': 'Look for the injected capture payload before moving '
                                            'to {{NEXT_NODE_NAME}}.',
                                'name': 'Binary: Packet Capture Blob',
                                'produces_extra': ['Binary(format)', 'Checksum(sha256)']},
 'encoding_ascii85_dispatch': {'builder': 'enc_ascii85',
                               'description': 'Generate an ASCII85 encoded dispatch string with a '
                                              'flag-bearing handoff message.',
                               'family': 'encoding',
                               'filename': 'dispatch.a85',
                               'inject_paths': ['/srv/share/messages',
                                                '/opt/dispatch',
                                                '/var/tmp/dropbox',
                                                '/home/www-data/public'],
                               'low_hint': 'The dispatch payload is encoded, not encrypted.',
                               'name': 'Encoding: ASCII85 Dispatch',
                               'produces_extra': ['Encoding(name)',
                                                  'Encoded(value)',
                                                  'Checksum(sha256)']},
 'encoding_base32_field_note': {'builder': 'enc_base32',
                                'description': 'Generate a Base32 encoded field note that carries '
                                               'the flag in a deterministic dispatch message.',
                                'family': 'encoding',
                                'filename': 'field_note.b32',
                                'inject_paths': ['/var/www/html/assets',
                                                 '/srv/media/uploads',
                                                 '/opt/gallery/images',
                                                 '/var/tmp/image_drop'],
                                'low_hint': 'Decode the field note before continuing to '
                                            '{{NEXT_NODE_NAME}}.',
                                'name': 'Encoding: Base32 Field Note',
                                'produces_extra': ['Encoding(name)',
                                                   'Encoded(value)',
                                                   'Checksum(sha256)']},
 'encoding_gzip_base64_ticket': {'builder': 'enc_gzip_b64',
                                 'description': 'Generate a gzip-compressed ticket note wrapped in '
                                                'Base64 for layered decoding practice.',
                                 'family': 'encoding',
                                 'filename': 'ticket_payload.gz.b64',
                                 'inject_paths': ['/srv/tickets',
                                                  '/opt/support/attachments',
                                                  '/var/log/helpdesk',
                                                  '/tmp/ticket_drop'],
                                 'low_hint': 'Start with Base64, then inspect the decompressed '
                                             'ticket.',
                                 'name': 'Encoding: Gzip Base64 Ticket',
                                 'produces_extra': ['Encoding(name)',
                                                    'Encoded(value)',
                                                    'Checksum(sha256)']},
 'encoding_jwt_style_claims': {'builder': 'enc_jwt',
                               'description': 'Generate an unsigned JWT-style token where the flag '
                                              'appears in encoded claims.',
                               'family': 'encoding',
                               'filename': 'session_claims.jwt',
                               'inject_paths': ['/srv/auth/tokens',
                                                '/opt/web/sessions',
                                                '/var/lib/app/cache',
                                                '/tmp/session_drop'],
                               'low_hint': 'Split the token into sections and decode the claims.',
                               'name': 'Encoding: JWT Style Claims',
                               'produces_extra': ['Encoding(name)',
                                                  'Encoded(value)',
                                                  'Checksum(sha256)']},
 'encoding_morse_ops_bulletin': {'builder': 'enc_morse',
                                 'description': 'Generate a Morse-coded operations bulletin whose '
                                                'decoded text contains the flag.',
                                 'family': 'encoding',
                                 'filename': 'ops_bulletin.morse',
                                 'inject_paths': ['/opt/radio/logs',
                                                  '/srv/comms',
                                                  '/var/tmp/signals',
                                                  '/home/operator/messages'],
                                 'low_hint': 'The bulletin uses a classic signal encoding.',
                                 'name': 'Encoding: Morse Ops Bulletin',
                                 'produces_extra': ['Encoding(name)',
                                                    'Encoded(value)',
                                                    'Checksum(sha256)']},
 'hash_hmac_message_signature': {'builder': 'hash_hmac',
                                 'description': 'Generate an HMAC-signed operations message where '
                                                'the flag is recovered from the signed body.',
                                 'family': 'hash',
                                 'filename': 'signed_message.hmac',
                                 'inject_paths': ['/srv/messages',
                                                  '/opt/signing',
                                                  '/var/lib/integrity',
                                                  '/tmp/signed_drop'],
                                 'low_hint': 'Inspect the signed message body as well as the HMAC.',
                                 'name': 'Hash: HMAC Message Signature',
                                 'produces_extra': ['Token(service)',
                                                    'Hash(value)',
                                                    'Checksum(sha256)']},
 'hash_sha1_legacy_password': {'builder': 'hash_sha1',
                               'description': 'Generate a SHA1 digest for a deterministic legacy '
                                              'password recovery challenge.',
                               'family': 'hash',
                               'filename': 'legacy_sha1.txt',
                               'inject_paths': ['/etc/security',
                                                '/opt/auth',
                                                '/var/lib/auth',
                                                '/srv/config'],
                               'low_hint': 'The artifact contains a legacy password digest to '
                                           'reverse.',
                               'name': 'Hash: SHA1 Legacy Password',
                               'produces_extra': ['Credential(user,password)',
                                                  'Hash(value)',
                                                  'Checksum(sha256)']},
 'hash_sha256_config_secret': {'builder': 'hash_sha256',
                               'description': 'Generate a SHA256 digest tied to a config backup '
                                              'secret and service account.',
                               'family': 'hash',
                               'filename': 'config_secret.sha256',
                               'inject_paths': ['/etc/app',
                                                '/opt/service/config',
                                                '/var/backups/config',
                                                '/srv/config'],
                               'low_hint': 'Compare the service account note with the SHA256 '
                                           'digest.',
                               'name': 'Hash: SHA256 Config Secret',
                               'produces_extra': ['Credential(user,password)',
                                                  'Hash(value)',
                                                  'Checksum(sha256)']},
 'hash_sha512_audit_phrase': {'builder': 'hash_sha512',
                              'description': 'Generate a SHA512 digest for an audit phrase '
                                             'embedded in a review handoff.',
                              'family': 'hash',
                              'filename': 'audit_phrase.sha512',
                              'inject_paths': ['/srv/audit',
                                               '/opt/review',
                                               '/var/tmp/audit',
                                               '/home/auditor/drop'],
                              'low_hint': 'The note points to a recoverable audit phrase digest.',
                              'name': 'Hash: SHA512 Audit Phrase',
                              'produces_extra': ['Hash(value)', 'Checksum(sha256)']},
 'hash_shadow_style_operator': {'builder': 'hash_shadow',
                                'description': 'Generate a shadow-file-style operator credential '
                                               'with a deterministic salted digest.',
                                'family': 'hash',
                                'filename': 'shadow_operator.fragment',
                                'inject_paths': ['/etc/security',
                                                 '/etc/auth.d',
                                                 '/var/lib/accounts',
                                                 '/srv/identity'],
                                'low_hint': 'Treat the artifact like a small shadow-file fragment.',
                                'name': 'Hash: Shadow Style Operator',
                                'produces_extra': ['Credential(user,password)',
                                                   'Credential(user,hash)',
                                                   'Hash(value)',
                                                   'Checksum(sha256)']},
 'https_backup_index_token': {'builder': 'https_backup',
                              'description': 'Generate a backup index page containing a recovery '
                                             'token and flag-bearing manifest entry.',
                              'family': 'https',
                              'filename': 'backup_index.html',
                              'inject_paths': ['/srv/https/backups',
                                               '/var/www/html/backups',
                                               '/opt/web/backups',
                                               '/srv/http/public/backups'],
                              'low_hint': 'Check the backup index for hidden manifest details.',
                              'name': 'HTTPS: Backup Index Token',
                              'produces_extra': ['Token(service)',
                                                 'Endpoint(path)',
                                                 'Checksum(sha256)']},
 'https_client_config_leak': {'builder': 'https_config',
                              'description': 'Generate a leaked HTTPS client configuration JSON '
                                             'file with a token and flag marker.',
                              'family': 'https',
                              'filename': 'client_config.json',
                              'inject_paths': ['/var/www/html/config',
                                               '/srv/http/public/config',
                                               '/opt/web/static',
                                               '/srv/https/client'],
                              'low_hint': 'Look for a client configuration file exposed over the '
                                          'web path.',
                              'name': 'HTTPS: Client Config Leak',
                              'produces_extra': ['Token(service)',
                                                 'Endpoint(path)',
                                                 'Checksum(sha256)']},
 'https_robots_secret_path': {'builder': 'https_robots',
                              'description': 'Generate a robots.txt style web artifact that points '
                                             'toward a secret flag path.',
                              'family': 'https',
                              'filename': 'robots.txt',
                              'inject_paths': ['/var/www/html',
                                               '/srv/http/public',
                                               '/opt/web/root',
                                               '/home/www-data/public'],
                              'low_hint': 'Start with the robots-style path hint in the injected '
                                          'file.',
                              'name': 'HTTPS: Robots Secret Path',
                              'produces_extra': ['Endpoint(path)', 'Checksum(sha256)']},
 'https_support_runbook_secret': {'builder': 'https_runbook',
                                  'description': 'Generate an HTML runbook note that exposes a '
                                                 'support escalation secret over HTTPS.',
                                  'family': 'https',
                                  'filename': 'support_runbook.html',
                                  'inject_paths': ['/var/www/html/runbooks',
                                                   '/srv/http/docs',
                                                   '/opt/web/runbooks',
                                                   '/home/www-data/public/runbooks'],
                                  'low_hint': 'The runbook title hints at where the escalation '
                                              'note is stored.',
                                  'name': 'HTTPS: Support Runbook Secret',
                                  'produces_extra': ['Credential(user,password)',
                                                     'Endpoint(path)',
                                                     'Checksum(sha256)']},
 'https_tls_status_credentials': {'builder': 'https_status',
                                  'description': 'Generate a TLS status page fragment with '
                                                 'deterministic credentials and a flag-bearing '
                                                 'notice.',
                                  'family': 'https',
                                  'filename': 'tls_status.html',
                                  'inject_paths': ['/var/www/html/docs',
                                                   '/srv/http/public',
                                                   '/opt/web/content',
                                                   '/home/www-data/public'],
                                  'low_hint': 'Visit the injected status page artifact before '
                                              'moving on.',
                                  'name': 'HTTPS: TLS Status Credentials',
                                  'produces_extra': ['Credential(user,password)',
                                                     'Endpoint(path)',
                                                     'Checksum(sha256)']}}

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '{': '-.--.', '}': '-.--.-', '_': '..--.-',
    '-': '-....-', ':': '---...', '/': '-..-.', '.': '.-.-.-', '=': '-...-'
}


def _load_config(config_path: str) -> dict[str, Any]:
    candidates = [config_path, '/inputs/config.json']
    for candidate in candidates:
        if not candidate:
            continue
        try:
            data = json.loads(Path(candidate).read_text(encoding='utf-8'))
            return data if isinstance(data, dict) else {}
        except Exception:
            continue
    return {}


def _digest(*parts: str, length: int = 16) -> str:
    return hashlib.sha256('|'.join(parts).encode('utf-8', 'replace')).hexdigest()[:length]


def _derive_flag(seed: str, variant_id: str, prefix: str) -> str:
    clean_prefix = (prefix or 'FLAG').strip() or 'FLAG'
    return f"{clean_prefix}{{{_digest(seed, variant_id, 'flag', length=24)}}}"


def _safe_filename(raw: Any, default: str) -> str:
    text = str(raw or '').replace('\\', '/').split('/')[-1].strip()
    if not text or text in {'.', '..'}:
        text = default
    safe = ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in text)
    return safe or default


def _derived_credential(seed: str, variant_id: str, cfg: dict[str, Any]) -> tuple[str, str]:
    user = str(cfg.get('username') or cfg.get('user') or '').strip()
    password = str(cfg.get('password') or '').strip()
    if user and password:
        return user, password
    digest = _digest(seed, variant_id, 'credential', length=20)
    return f"svc_{digest[:6]}", f"pw_{digest[6:14]}"


def _context(seed: str, variant_id: str, flag: str, cfg: dict[str, Any]) -> dict[str, str]:
    user, password = _derived_credential(seed, variant_id, cfg)
    token = 'tok_' + _digest(seed, variant_id, 'token', length=24)
    phrase = 'delta-' + _digest(seed, variant_id, 'phrase', length=10)
    return {
        'seed': seed,
        'flag': flag,
        'user': user,
        'password': password,
        'credential': f'{user}:{password}',
        'token': token,
        'phrase': phrase,
        'digest': _digest(seed, variant_id, length=12),
    }


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding='utf-8')


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _morse(text: str) -> str:
    return ' / '.join(' '.join(MORSE.get(ch, ch) for ch in word.upper()) for word in text.split())


def _binary_content(builder: str, ctx: dict[str, str]) -> tuple[bytes, dict[str, Any]]:
    flag = ctx['flag']
    if builder == 'binary_core':
        body = b'CORETG-CORE\x00' + f"pid=4172\nthread=worker\nmarker={flag}\n".encode()
        return body + hashlib.sha256(body).digest(), {'Binary(format)': 'core-dump-segment'}
    if builder == 'binary_pcap':
        body = bytes.fromhex('d4c3b2a1020004000000000000000000ffff000001000000') + f"http.host=internal\nflag={flag}\n".encode()
        return body, {'Binary(format)': 'pcap-like'}
    if builder == 'binary_boot':
        body = b'BOOTREC1' + bytes.fromhex(_digest(flag, length=32)) + f"\nrecovery_slot=A\nflag={flag}\n".encode()
        return body, {'Binary(format)': 'bootloader-image'}
    if builder == 'binary_heap':
        chunks = [b'HEAPSNAP\x00', ctx['token'].encode(), b'\x00session-cache\x00', flag.encode(), b'\x00free-list\x00']
        return b''.join(chunks), {'Binary(format)': 'heap-snapshot'}
    body = b'SYMTAB\x00.debug_str\x00' + f"recover_marker::{flag}\nsource=release-agent\n".encode()
    return body, {'Binary(format)': 'debug-symbol-table'}


def _encoding_content(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    message = f"handoff={ctx['flag']};owner={ctx['user']};ticket={ctx['digest']}"
    if builder == 'enc_base32':
        encoded = base64.b32encode(message.encode()).decode('ascii')
        return encoded + '\n', {'Encoding(name)': 'base32', 'Encoded(value)': encoded}
    if builder == 'enc_ascii85':
        encoded = base64.a85encode(message.encode()).decode('ascii')
        return encoded + '\n', {'Encoding(name)': 'ascii85', 'Encoded(value)': encoded}
    if builder == 'enc_gzip_b64':
        encoded = base64.b64encode(gzip.compress(message.encode())).decode('ascii')
        return encoded + '\n', {'Encoding(name)': 'gzip+base64', 'Encoded(value)': encoded}
    if builder == 'enc_morse':
        encoded = _morse(message)
        return encoded + '\n', {'Encoding(name)': 'morse', 'Encoded(value)': encoded}
    header = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).decode().rstrip('=')
    claims = base64.urlsafe_b64encode(json.dumps({'sub': ctx['user'], 'flag': ctx['flag'], 'ticket': ctx['digest']}).encode()).decode().rstrip('=')
    token = f'{header}.{claims}.'
    return token + '\n', {'Encoding(name)': 'jwt-base64url', 'Encoded(value)': token}


def _hash_content(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == 'hash_sha1':
        digest = hashlib.sha1(ctx['password'].encode()).hexdigest()
        return f"user={ctx['user']}\nsha1={digest}\n", {'Credential(user,password)': ctx['credential'], 'Hash(value)': digest}
    if builder == 'hash_sha256':
        secret = f"{ctx['password']}:{ctx['token']}"
        digest = hashlib.sha256(secret.encode()).hexdigest()
        return f"service=config-sync\nuser={ctx['user']}\nsha256={digest}\n", {'Credential(user,password)': ctx['credential'], 'Hash(value)': digest}
    if builder == 'hash_sha512':
        digest = hashlib.sha512(ctx['phrase'].encode()).hexdigest()
        return f"audit_phrase_hint={ctx['phrase'][:6]}*\nsha512={digest}\nflag={ctx['flag']}\n", {'Hash(value)': digest}
    if builder == 'hash_shadow':
        salt = _digest(ctx['user'], length=8)
        digest = hashlib.sha512((salt + ctx['password']).encode()).hexdigest()
        shadow_hash = f"$6${salt}${digest}"
        return f"{ctx['user']}:{shadow_hash}:19076:0:99999:7:::\n", {'Credential(user,password)': ctx['credential'], 'Credential(user,hash)': f"{ctx['user']}:{shadow_hash}", 'Hash(value)': shadow_hash}
    body = f"message=release approved for {ctx['digest']} with flag {ctx['flag']}\n"
    digest = hmac.new(ctx['token'].encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + f"hmac_sha256={digest}\n", {'Token(service)': ctx['token'], 'Hash(value)': digest}


def _https_content(builder: str, ctx: dict[str, str]) -> tuple[str, dict[str, Any]]:
    if builder == 'https_config':
        body = json.dumps({'endpoint': '/api/client/config', 'token': ctx['token'], 'recovery_flag': ctx['flag']}, indent=2) + '\n'
        return body, {'Token(service)': ctx['token'], 'Endpoint(path)': '/api/client/config'}
    if builder == 'https_robots':
        body = f"User-agent: *\nDisallow: /secure/{ctx['digest']}/\n# recovery marker {ctx['flag']}\n"
        return body, {'Endpoint(path)': f"/secure/{ctx['digest']}/"}
    if builder == 'https_backup':
        body = f"<html><body><h1>Backup Index</h1><p>Token: {ctx['token']}</p><pre>flag={ctx['flag']}</pre></body></html>\n"
        return body, {'Token(service)': ctx['token'], 'Endpoint(path)': '/backups/backup_index.html'}
    if builder == 'https_runbook':
        body = f"<html><body><h1>Support Runbook</h1><p>Escalation: {ctx['credential']}</p><code>{ctx['flag']}</code></body></html>\n"
        return body, {'Credential(user,password)': ctx['credential'], 'Endpoint(path)': '/runbooks/support_runbook.html'}
    body = f"<html><body><h1>TLS Status</h1><p>{ctx['credential']}</p><p class='flag'>{ctx['flag']}</p></body></html>\n"
    return body, {'Credential(user,password)': ctx['credential'], 'Endpoint(path)': '/docs/tls_status.html'}


def build_artifact(variant_id: str, cfg: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    spec = VARIANTS[variant_id]
    seed = str(cfg.get('seed') or os.environ.get('SEED') or 'seed')
    flag_prefix = str(cfg.get('flag_prefix') or os.environ.get('FLAG_PREFIX') or 'FLAG')
    flag = str(cfg.get('Flag(flag_id)') or '').strip() or _derive_flag(seed, variant_id, flag_prefix)
    ctx = _context(seed, variant_id, flag, cfg)
    filename = _safe_filename(cfg.get('File(path)'), spec['filename'])
    rel_path = f'artifacts/{filename}'
    artifact_path = out_dir / rel_path
    builder = spec['builder']
    if builder.startswith('binary_'):
        content, extra = _binary_content(builder, ctx)
    elif builder.startswith('enc_'):
        content, extra = _encoding_content(builder, ctx)
    elif builder.startswith('hash_'):
        content, extra = _hash_content(builder, ctx)
    else:
        content, extra = _https_content(builder, ctx)
    _write(artifact_path, content)
    outputs: dict[str, Any] = {
        'Flag(flag_id)': flag,
        'FlagDelivery(mode)': 'embedded' if spec['family'] in {'binary', 'encoding', 'hash'} else 'file',
        'File(path)': rel_path,
        'Checksum(sha256)': _sha256(artifact_path),
    }
    if outputs['FlagDelivery(mode)'] == 'file':
        outputs['FlagFile(path)'] = rel_path
    outputs.update(extra)
    return {'schema_version': 1, 'generator_id': variant_id, 'outputs': outputs}


def main() -> int:
    parser = argparse.ArgumentParser(description='ScenarioForge installed flag generator variant')
    parser.add_argument('--variant', default=os.environ.get('ARTIFACT_VARIANT_ID') or DEFAULT_VARIANT)
    parser.add_argument('--config', default=os.environ.get('CONFIG_PATH') or '/inputs/config.json')
    parser.add_argument('--out-dir', default=os.environ.get('OUT_DIR') or os.environ.get('OUTPUTS_DIR') or '/outputs')
    args = parser.parse_args()
    variant_id = str(args.variant or DEFAULT_VARIANT).strip()
    if variant_id not in VARIANTS:
        raise SystemExit(f'Unknown variant: {variant_id}')
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = _load_config(args.config)
    cfg.setdefault('generator_id', variant_id)
    result = build_artifact(variant_id, cfg, out_dir)
    (out_dir / 'outputs.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
