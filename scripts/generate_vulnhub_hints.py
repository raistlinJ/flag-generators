#!/usr/bin/env python3
"""Build optional guide metadata from the pinned local Vulhub documentation.

Requires PyYAML. Run with --check to compare without modifying files.
The original recipes, documentation, and catalog eligibility remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / 'vulnhub' / 'content'
UPSTREAM_COMMIT = '3af973a39bd0988f288a53fa9ea4b82372774e58'
UPSTREAM = f'https://github.com/vulhub/vulhub/blob/{UPSTREAM_COMMIT}'
EXPLOIT_HEADING = re.compile(r'exploit|expliot|reproduc|poc|proof|method|mistake|test', re.I)
OVERRIDES = yaml.safe_load((ROOT / 'scripts' / 'vulnhub_hint_overrides.yaml').read_text())
SPECIAL_SECTIONS = {
    'activemq/CVE-2016-3088': {'Background brief', 'Vulnerability Details'},
    'struts2/s2-008': {'Reference'},
    'struts2/s2-013': {'Reference'},
}


class Dumper(yaml.SafeDumper):
    pass


def represent_string(dumper, value):
    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style='|' if '\n' in value else None)


Dumper.add_representer(str, represent_string)


def public_url(name: str, filename: str = 'README.md') -> str:
    return f'{UPSTREAM}/{quote(name + "/" + filename, safe="/#")}'


def clean_documentation(text: str, name: str) -> str:
    # Link directly to publicly available artifacts, never an author-only path.
    def link(match):
        label, target = match.groups()
        if not re.match(r'https?://', target):
            target = public_url(name, target)
        return f'{label or "Documentation illustration"}: {target}'

    text = re.sub(r'!?\[([^\]]*)\]\(([^\s)]+)\)', link, text)
    text = re.sub(r'\byour[-_]ip(?:[-_]address)?\b', '{{NODE_IP}}', text, flags=re.I)
    text = re.sub(r'(?m)^(Host:[ \t]*)(?:localhost|192\.168\.[0-9.]+)\b', r'\1{{NODE_IP}}', text)
    if name != 'weblogic/ssrf':
        text = re.sub(r'(https?://)(?:localhost(?:\.lan)?|127\.0\.0\.1)(?=[:/\s`"<>]|$)', r'\1{{NODE_IP}}', text)
    for host in {
        'confluence/CVE-2021-26084': ['192.168.1.162'],
        'jetty/CVE-2021-28164': ['192.168.1.162'],
        'nexus/CVE-2020-10204': ['192.168.1.3'],
        'polkit/CVE-2021-4034': ['192.168.1.163'],
    }.get(name, []):
        text = text.replace(host, '{{NODE_IP}}')
    # Content-Length from a captured request becomes wrong after substitution.
    text = re.sub(r'(?mi)^Content-Length:[ \t]*\d+[ \t]*\r?\n', '', text)
    # Lab deployment is already done. Verification commands run in a target
    # shell, not through the author's Compose project.
    had_target_shell = bool(re.search(r'docker(?: compose| exec)', text))
    text = re.sub(r'docker compose exec\s+[-\w]+\s+', '', text)
    text = re.sub(r'docker exec\s+[-\w]+\s+', '', text)
    text = re.sub(r'docker compose logs(?:\s+[-\w]+)?', '# Inspect the target service logs if your access permits it.', text)
    text = text.replace('docker compose run im bash', 'bash')
    text = re.sub(r'```[^\n]*\n(?:docker compose (?:up|build)[^\n]*\n)+```', '', text)
    text = re.sub(r"If you don't want to wait, you can restart.*?service restarts\.", '', text)
    text = text.replace('The super administrator password is set in `docker-compose.yml`, with a default value of',
                        'The catalog default super administrator password is')
    if had_target_shell:
        text = ('Commands that inspect files or logs inside the target require a shell or equivalent file/log access '
                'on that target. Run them there after gaining that access.\n\n' + text)

    return text.strip()


def published_ports(compose: dict) -> tuple[dict[str, list[str]], list[str]]:
    ports: dict[str, set[str]] = {'tcp': set(), 'udp': set()}
    mappings = []
    for service, config in compose.get('services', {}).items():
        for spec in config.get('ports', []):
            # The pinned catalog uses short syntax; fail on a future format change.
            if not isinstance(spec, str):
                raise ValueError(f'Unsupported port specification: {spec!r}')
            value, _, protocol = spec.partition('/')
            protocol = protocol or 'tcp'
            parts = value.split(':')
            if len(parts) < 2:
                raise ValueError(f'Dynamic published port requires authored guidance: {spec!r}')
            published, internal = parts[-2:]
            if not re.fullmatch(r'\d+(?:-\d+)?', published):
                raise ValueError(f'Nonliteral published port: {spec!r}')
            ports[protocol].add(published)
            mappings.append(f'{service}: {published}/{protocol} → container {internal}/{protocol}')
    return {key: sorted(values, key=lambda p: int(p.split('-')[0])) for key, values in ports.items()}, mappings


def reproduction_sections(text: str, name: str) -> list[tuple[str, str]]:
    if name in OVERRIDES:
        return [(step['title'], step['instructions'].strip()) for step in OVERRIDES[name]]
    split = re.split(r'^##\s+(.+)\n', text, flags=re.M)
    selected = []
    for idx in range(1, len(split), 2):
        title, body = split[idx:idx + 2]
        if name == 'elasticsearch/CVE-2014-3120' and title == 'Vulnerability Reproduction':
            continue
        if EXPLOIT_HEADING.search(title) or title in SPECIAL_SECTIONS.get(name, set()):
            selected.append((title, clean_documentation(body, name)))
    if name == 'bash/CVE-2014-6271':
        selected = [('Reproduce Shellshock', 'The vulnerable CGI endpoint is `/victim.cgi`; `/safe.cgi` is the patched comparison. '
                     'Send a Bash function definition followed by a command in the User-Agent header:\n\n'
                     '```bash\ncurl -A \'() { :; }; echo; /usr/bin/id\' http://{{NODE_IP}}/victim.cgi\n```\n\n'
                     'The vulnerable endpoint executes `id`; the patched endpoint does not.')]
    if not selected or any(not body for _, body in selected):
        raise ValueError(f'No reproduction instructions selected for {name}')
    return selected


def build_metadata(compose_path: Path) -> dict:
    directory = compose_path.parent
    name = directory.relative_to(CONTENT).as_posix()
    readme = (directory / 'README.md').read_text(encoding='utf-8')
    compose = yaml.safe_load(compose_path.read_text(encoding='utf-8'))
    title = re.search(r'^#\s+(.+)', readme, re.M).group(1)
    ports, mappings = published_ports(compose)
    app_name = name.split('/')[0]
    medium = []
    for protocol, values in ports.items():
        if values:
            port_list = ','.join(values)
            scan = '-sT -sV' if protocol == 'tcp' else '-sU -sV'
            sudo = '' if protocol == 'tcp' else 'sudo '
            medium.append(f'Catalog {protocol.upper()} ports: {port_list}. Identify the exposed services:\n\n'
                          f'```bash\n{sudo}nmap -Pn {scan} -p {port_list} {{{{NODE_IP}}}}\n```')
    if mappings:
        medium.append('Catalog port mappings (published → container): ' + '; '.join(mappings) + '. '
                      'These are recipe defaults; use the deployed service port if the scenario remaps it.')
    else:
        medium.append('This recipe publishes no network port. It requires local interaction with the vulnerable application; '
                      'obtain the target access or input-file path supplied by the scenario before reproducing it.')
    # Network entry points belong at medium; keep exploit query strings at high.
    endpoints = list(dict.fromkeys(re.findall(r'https?://your-ip(?::\d+)?(?:/[A-Za-z0-9_./-]*)?', readme)))
    endpoints = [clean_documentation(url, name) for url in endpoints if '?' not in url]
    if endpoints:
        medium.append('Documented target URL(s): ' + ', '.join(f'`{url}`' for url in endpoints[:4]) + '.')
    sections = reproduction_sections(readme, name)
    cves = list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d{4,}', title + ' ' + name, re.I)))
    identity = f'Vulnerability: {title}.'
    if cves:
        identity += '\n\nCVE record(s): ' + ', '.join(f'https://www.cve.org/CVERecord?id={cve.upper()}' for cve in cves)
    # Source reproduction text is included directly; reference URLs are supplemental.
    high = [identity]
    if any(re.search(r'(?m)^(?:GET|POST|PUT|DELETE|PATCH) .* HTTP/1', body) for _, body in sections):
        high.append('Send the raw request examples with an HTTP client that recalculates Content-Length after target and payload substitutions.')
    high.extend(f'{heading}\n\n{body}' for heading, body in sections)
    high.append(f'Publicly available documentation: {public_url(name)}')
    refs = list(dict.fromkeys(re.findall(r'https?://[^\s<>`\])]+', re.split(r'^##\s+', readme, maxsplit=1, flags=re.M)[0])))
    if refs:
        high.append('Additional public references:\n' + '\n'.join(f'- {url.rstrip(".,")}' for url in refs))
    return {
        'schema_version': 1,
        'match': name,
        **({'cve': cves[0].upper()} if cves else {}),
        'hint_levels': {
            'low': [f'Inspect the {app_name} service or application on {{{{NODE_NAME}}}} @ {{{{NODE_IP}}}}.'],
            'medium': medium,
            'high': high,
        },
        'access_instructions': {
            'title': title,
            'steps': [
                {'title': 'Locate the target service', 'instructions': '\n\n'.join(medium)},
                *[{'title': heading, 'instructions': body} for heading, body in sections],
            ],
        },
        'guidance_source': {
            'repository': 'https://github.com/vulhub/vulhub',
            'snapshot_commit': UPSTREAM_COMMIT,
            'documentation_url': public_url(name),
            'readme_sha256': hashlib.sha256((directory / 'README.md').read_bytes()).hexdigest(),
            'compose_sha256': hashlib.sha256(compose_path.read_bytes()).hexdigest(),
            'license': 'MIT; see vulnhub/content/LICENSE',
            'method': 'Tiered discovery hints and adapted reproduction text from the local catalog snapshot. Reproduction commands have not been executed.',
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    paths = sorted(CONTENT.rglob('docker-compose.yml'))
    if len(paths) != 306:
        raise SystemExit(f'Expected 306 pinned recipes, found {len(paths)}; review catalog changes first.')
    outputs = []
    for path in paths:
        metadata = build_metadata(path)
        text = '# Optional ScenarioForge guide hints; derived from the adjacent public Vulhub documentation.\n'
        text += yaml.dump(metadata, Dumper=Dumper, allow_unicode=True, sort_keys=False, width=110)
        outputs.append((path.parent / 'scenarioforge.vuln.yaml', text))
    mismatches = [str(path.relative_to(ROOT)) for path, text in outputs if not path.exists() or path.read_text() != text]
    if args.check and mismatches:
        raise SystemExit('Guidance differs from generated output:\n' + '\n'.join(mismatches))
    if not args.check:
        for path, text in outputs:
            path.write_text(text, encoding='utf-8')
    print(f'{"Checked" if args.check else "Generated"} low/medium/high hints and walkthroughs for {len(outputs)} recipes.')


if __name__ == '__main__':
    main()
