import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_VARIANT = "nfs_incident_response_evidence"
VARIANTS = {'nfs_build_cache_share': {'credential': 'none',
                           'description': 'Generate an NFSv4 build cache share with package '
                                          'metadata and a flagged cache manifest.',
                           'flag_file': 'manifests/cache-index.txt',
                           'hostname': 'nfs-buildcache',
                           'inject_paths': ['/srv/nfs/buildcache',
                                            '/mnt/buildcache',
                                            '/opt/build/cache',
                                            '/var/tmp/nfs_build'],
                           'low_hint': 'The build cache manifest is the useful artifact in this '
                                       'export.',
                           'mount_dir': '/mnt/buildcache',
                           'name': 'NFS: Build Cache Share',
                           'pseudo': '/buildcache',
                           'title': 'Build Cache NFS Share'},
 'nfs_engineering_drawings_export': {'credential': 'optional',
                                     'description': 'Generate an NFSv4 share with engineering '
                                                    'drawings and a flagged revision note.',
                                     'flag_file': 'drawings/revision-note.txt',
                                     'hostname': 'nfs-engineering',
                                     'inject_paths': ['/srv/nfs/engineering',
                                                      '/mnt/engineering',
                                                      '/opt/shares/drawings',
                                                      '/var/tmp/nfs_engineering'],
                                     'low_hint': 'Mount the engineering export before continuing '
                                                 'to {{NEXT_NODE_NAME}}.',
                                     'mount_dir': '/mnt/engineering',
                                     'name': 'NFS: Engineering Drawings Export',
                                     'pseudo': '/engineering',
                                     'title': 'Engineering NFS Drawing Share'},
 'nfs_incident_response_evidence': {'credential': 'required',
                                    'description': 'Generate an NFSv4 evidence share with case '
                                                   'notes, credentials, and the incident flag.',
                                    'flag_file': 'cases/IR-2047/flag-note.txt',
                                    'hostname': 'nfs-evidence',
                                    'inject_paths': ['/srv/nfs/evidence',
                                                     '/mnt/evidence',
                                                     '/opt/ir/cases',
                                                     '/var/tmp/nfs_evidence'],
                                    'low_hint': 'Use the case credential to correlate the evidence '
                                                'note.',
                                    'mount_dir': '/mnt/evidence',
                                    'name': 'NFS: Incident Response Evidence',
                                    'pseudo': '/evidence',
                                    'title': 'Incident Response NFS Evidence Share'},
 'nfs_lab_instrument_logs': {'credential': 'none',
                             'description': 'Generate an NFSv4 lab export containing instrument '
                                            'logs and a hidden calibration flag.',
                             'flag_file': 'calibration/calibration-note.txt',
                             'hostname': 'nfs-lablogs',
                             'inject_paths': ['/srv/nfs/lablogs',
                                              '/mnt/lab',
                                              '/opt/instruments/logs',
                                              '/var/tmp/nfs_lab'],
                             'low_hint': 'The lab export contains calibration notes worth '
                                         'reviewing.',
                             'mount_dir': '/mnt/lablogs',
                             'name': 'NFS: Lab Instrument Logs',
                             'pseudo': '/lablogs',
                             'title': 'Lab Instrument NFS Logs'},
 'nfs_legal_hold_archive': {'credential': 'required',
                            'description': 'Generate an NFSv4 legal archive where a required '
                                           'credential unlocks the flagged hold note.',
                            'flag_file': 'sealed/hold-note.enc',
                            'hostname': 'nfs-legalhold',
                            'inject_paths': ['/srv/nfs/legal',
                                             '/mnt/legalhold',
                                             '/opt/archives/legal',
                                             '/var/tmp/nfs_legal'],
                            'low_hint': 'Use the supplied credential when reviewing the legal hold '
                                        'export.',
                            'mount_dir': '/mnt/legalhold',
                            'name': 'NFS: Legal Hold Archive',
                            'pseudo': '/legalhold',
                            'title': 'Legal Hold NFS Archive'}}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _digest(*parts: str, length: int = 16) -> str:
    return hashlib.sha256('|'.join(parts).encode('utf-8', 'replace')).hexdigest()[:length]


def _write(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    if mode is not None:
        path.chmod(mode)


def _parse_credential(raw: Any, seed: str, node_name: str, variant_id: str, mode: str) -> tuple[str, str]:
    text = str(raw or '').strip()
    if text:
        if ':' not in text:
            raise ValueError('Credential(user, password) must use user:password format')
        user, password = text.split(':', 1)
        user = user.strip()
        password = password.strip()
        if not user or not password:
            raise ValueError('Credential(user, password) must include user and password')
        return user, password
    if mode == 'required':
        raise ValueError('Credential(user, password) is required for this generator')
    digest = _digest(seed, node_name, variant_id, 'credential', length=18)
    return f'nfs_{digest[:6]}', f'pw_{digest[6:14]}'


def _port(raw: Any) -> int:
    try:
        port = int(raw or 2049)
    except Exception as exc:
        raise ValueError(f'invalid nfs_port: {raw}') from exc
    if not 1 <= port <= 65535:
        raise ValueError(f'invalid nfs_port: {port}')
    return port


def _flag(seed: str, node_name: str, variant_id: str, prefix: str) -> str:
    clean_prefix = (prefix or 'FLAG').strip() or 'FLAG'
    return f"{clean_prefix}{{{_digest(seed, node_name, variant_id, 'flag', length=20)}}}"


def _ganesha_conf(pseudo: str) -> str:
    return (
        'NFS_Core_Param {\n  Protocols = 4;\n  Enable_NLM = false;\n  Enable_RQUOTA = false;\n}\n\n'
        'DBus {\n  Enabled = false;\n}\n\n'
        'EXPORT {\n'
        '  Export_Id = 1;\n'
        '  Path = /exports;\n'
        f'  Pseudo = {pseudo};\n'
        '  Access_Type = RO;\n'
        '  Squash = no_root_squash;\n'
        '  SecType = sys;\n'
        '  Protocols = 4;\n'
        '  Transports = TCP;\n'
        '  FSAL {\n    Name = VFS;\n  }\n'
        '}\n'
    )


def _dockerfile() -> str:
    return (
        'FROM ubuntu:22.04\n'
        'ENV DEBIAN_FRONTEND=noninteractive\n'
        'RUN apt-get update \\\n'
        '  && apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind netbase iproute2 \\\n'
        '  && rm -rf /var/lib/apt/lists/*\n'
    )


def _compose(nfs_port: int, hostname: str) -> str:
    return (
        'services:\n'
        '  node:\n'
        '    build:\n'
        '      context: .\n'
        '      dockerfile: Dockerfile\n'
        "    command: ['sh','-lc','rpcbind -w -f & ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity']\n"
        '    privileged: true\n'
        '    ports:\n'
        f'      - "{nfs_port}:2049"\n'
        '    volumes:\n'
        '      - ./exports:/exports:ro\n'
        '      - ./ganesha.conf:/etc/ganesha/ganesha.conf:ro\n'
        f'    hostname: {hostname}\n'
    )


def _write_variant_files(exports: Path, spec: dict[str, Any], flag: str, user: str, password: str, digest: str) -> None:
    flag_file = spec['flag_file']
    if spec['credential'] == 'required':
        body = f"Protected case note {digest}\ncredential_user={user}\ncredential_password={password}\nflag={flag}\n"
    elif spec['credential'] == 'optional':
        body = f"Operator handoff {digest}\ncredential={user}:{password}\nflag={flag}\n"
    else:
        body = f"Export note {digest}\nreview_status=complete\nflag={flag}\n"
    _write(exports / flag_file, body)
    _write(exports / 'README.txt', f"NFS export generated for {spec['name']}. Mount the pseudo path {spec['pseudo']}.\n")
    _write(exports / 'inventory' / f"index-{digest}.txt", f"flag_file={flag_file}\nowner={user}\n")
    _write(exports / 'creds.txt', f"{user}:{password}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description='ScenarioForge installed NFS node generator variant')
    parser.add_argument('--variant', default=os.environ.get('NFS_VARIANT_ID') or DEFAULT_VARIANT)
    parser.add_argument('--input', type=Path, default=Path(os.environ.get('INPUTS_DIR') or '/inputs'))
    parser.add_argument('--output', type=Path, default=Path(os.environ.get('OUTPUTS_DIR') or '/outputs'))
    args = parser.parse_args()
    variant_id = str(args.variant or DEFAULT_VARIANT).strip()
    if variant_id not in VARIANTS:
        raise SystemExit(f'Unknown NFS variant: {variant_id}')
    spec = VARIANTS[variant_id]
    cfg = _read_json(args.input / 'config.json')
    try:
        seed = str(cfg.get('seed') or '').strip()
        node_name = str(cfg.get('node_name') or '').strip()
        if not seed or not node_name:
            raise ValueError('seed and node_name are required')
        nfs_port = _port(cfg.get('nfs_port'))
        user, password = _parse_credential(cfg.get('Credential(user, password)'), seed, node_name, variant_id, spec['credential'])
    except ValueError as exc:
        raise SystemExit(f'[validation error] {exc}') from exc
    flag = _flag(seed, node_name, variant_id, str(cfg.get('flag_prefix') or 'FLAG'))
    digest = _digest(seed, node_name, variant_id, length=10)
    outputs_dir = args.output
    outputs_dir.mkdir(parents=True, exist_ok=True)
    exports = outputs_dir / 'exports'
    exports.mkdir(parents=True, exist_ok=True)
    _write_variant_files(exports, spec, flag, user, password, digest)
    _write(outputs_dir / 'ganesha.conf', _ganesha_conf(spec['pseudo']))
    _write(outputs_dir / 'Dockerfile', _dockerfile())
    _write(outputs_dir / 'docker-compose.yml', _compose(nfs_port, spec['hostname']))
    result = {
        'generator_id': str(cfg.get('generator_id') or variant_id),
        'outputs': {
            'Flag(flag_id)': flag,
            'FlagDelivery(mode)': 'file',
            'FlagFile(path)': spec['flag_file'],
            'Credential(user, password)': f'{user}:{password}',
            'File(path)': 'docker-compose.yml',
            'PortForward(host, port)': nfs_port,
            'Directory(host, path)': spec['pseudo'],
        },
    }
    _write(outputs_dir / 'outputs.json', json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
