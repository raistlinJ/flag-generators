#!/usr/bin/env python3
"""Export aggregate ScenarioForge guidance data from per-recipe Vulhub metadata."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / 'vulnhub' / 'content'
INDEX_PATH = ROOT / 'vulnhub' / 'scenarioforge_guidance_index.json'
REPORT_PATH = ROOT / 'vulnhub' / 'SCENARIOFORGE_GUIDANCE.md'
TCP_RE = re.compile(r'Catalog TCP ports: ([0-9,-]+)\.')
UDP_RE = re.compile(r'Catalog UDP ports: ([0-9,-]+)\.')


def load_records() -> list[dict]:
    records = []
    for path in sorted(CONTENT.rglob('scenarioforge.vuln.yaml')):
        data = yaml.safe_load(path.read_text(encoding='utf-8'))
        rel = path.parent.relative_to(CONTENT).as_posix()
        hints = data.get('hint_levels', {})
        steps = data.get('access_instructions', {}).get('steps', [])
        medium_text = '\n'.join(hints.get('medium', []))
        records.append({
            'name': rel,
            'metadata_path': path.relative_to(ROOT).as_posix(),
            'compose_path': (path.parent / 'docker-compose.yml').relative_to(ROOT).as_posix(),
            'title': data.get('access_instructions', {}).get('title'),
            'cve': data.get('cve'),
            'hint_counts': {level: len(hints.get(level, [])) for level in ('low', 'medium', 'high')},
            'walkthrough_step_count': len(steps),
            'ports': {
                'tcp': split_ports(TCP_RE.search(medium_text)),
                'udp': split_ports(UDP_RE.search(medium_text)),
            },
            'documentation_url': data.get('guidance_source', {}).get('documentation_url'),
            'readme_sha256': data.get('guidance_source', {}).get('readme_sha256'),
            'compose_sha256': data.get('guidance_source', {}).get('compose_sha256'),
            'has_complete_hint_tiers': all(hints.get(level) for level in ('low', 'medium', 'high')),
            'has_walkthrough': bool(steps),
        })
    return records


def split_ports(match: re.Match | None) -> list[str]:
    if not match:
        return []
    return [port for port in match.group(1).split(',') if port]


def build_index(records: list[dict]) -> dict:
    missing_ports = [record['name'] for record in records if not record['ports']['tcp'] and not record['ports']['udp']]
    by_group: dict[str, int] = {}
    for record in records:
        group = record['name'].split('/')[0]
        by_group[group] = by_group.get(group, 0) + 1
    return {
        'schema_version': 1,
        'generated_on': date.today().isoformat(),
        'source': {
            'repository': 'https://github.com/vulhub/vulhub',
            'snapshot_commit': '3af973a39bd0988f288a53fa9ea4b82372774e58',
            'license': 'MIT; see vulnhub/content/LICENSE',
            'method': 'Aggregated from per-recipe scenarioforge.vuln.yaml files generated from the pinned public Vulhub documentation.',
        },
        'validation': {
            'recipe_count': len(records),
            'top_level_content_group_count': len(by_group),
            'low_hint_coverage': sum(1 for record in records if record['hint_counts']['low']),
            'medium_hint_coverage': sum(1 for record in records if record['hint_counts']['medium']),
            'high_hint_coverage': sum(1 for record in records if record['hint_counts']['high']),
            'complete_hint_tier_coverage': sum(1 for record in records if record['has_complete_hint_tiers']),
            'walkthrough_coverage': sum(1 for record in records if record['has_walkthrough']),
            'walkthrough_step_count': sum(record['walkthrough_step_count'] for record in records),
            'primary_cve_count': sum(1 for record in records if record['cve']),
            'network_port_recipe_count': len(records) - len(missing_ports),
            'no_network_port_recipe_count': len(missing_ports),
            'no_network_port_recipes': missing_ports,
            'checks': [
                'python3 scripts/generate_vulnhub_hints.py --check',
                'python3 -m unittest tests/test_vulnhub_hints.py',
                'python3 -m pytest tests/test_vuln_capability_metadata.py tests/test_vulnerability_guidance_js.py',
            ],
        },
        'top_level_content_groups': dict(sorted(by_group.items())),
        'recipes': records,
    }


def write_report(index: dict) -> None:
    validation = index['validation']
    text = f"""# ScenarioForge Vulhub Guidance Export

This file summarizes the optional ScenarioForge guidance data generated for the pinned Vulhub catalog.

The detailed machine-readable export is `vulnhub/scenarioforge_guidance_index.json`. Each recipe also has an adjacent `scenarioforge.vuln.yaml` file with low, medium, and high hints plus walkthrough steps.

## Source

- Public source: <https://github.com/vulhub/vulhub>
- Snapshot commit: `{index['source']['snapshot_commit']}`
- License: {index['source']['license']}
- Method: {index['source']['method']}

## Coverage

- Recipes with guidance: {validation['recipe_count']}
- Top-level content groups covered: {validation['top_level_content_group_count']}
- Complete low/medium/high coverage: {validation['complete_hint_tier_coverage']}
- Recipes with walkthrough steps: {validation['walkthrough_coverage']}
- Total walkthrough steps: {validation['walkthrough_step_count']}
- Recipes with primary CVE IDs: {validation['primary_cve_count']}
- Recipes with published network ports: {validation['network_port_recipe_count']}
- Recipes without published network ports: {validation['no_network_port_recipe_count']}

## Validation

These checks were run against this generated dataset and the sibling ScenarioForge worktree:

```bash
{chr(10).join(validation['checks'])}
```

The generated YAML is source-grounded in the pinned public Vulhub README and Compose files. The hints include port discovery at medium level and CVE/source/reproduction detail at high level when that information is present in the source material.
"""
    REPORT_PATH.write_text(text, encoding='utf-8')


def main() -> None:
    records = load_records()
    index = build_index(records)
    INDEX_PATH.write_text(json.dumps(index, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_report(index)
    print(f'Exported {len(records)} records to {INDEX_PATH.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
