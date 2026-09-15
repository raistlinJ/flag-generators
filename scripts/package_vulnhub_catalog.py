#!/usr/bin/env python3
"""Build a ScenarioForge ZIP with catalog metadata at the archive root."""
import argparse
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1] / 'vulnhub'


def package_catalog(output):
    output = Path(output).resolve()
    if output.is_relative_to(ROOT.resolve()):
        raise ValueError('Write the ZIP outside vulnhub to avoid including generated archives.')
    recipes = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('docker-compose.yml')}
    notes = json.loads((ROOT / '.scenarioforge/catalog_notes.json').read_text())
    items = json.loads((ROOT / '.scenarioforge/catalog_items.json').read_text())
    note_paths = {item['compose_rel'] for item in notes['notes']}
    if not recipes or note_paths != recipes:
        raise ValueError('Catalog notes must cover exactly the available recipes.')
    if any(item['compose_rel'] not in recipes for item in items['items']):
        raise ValueError('Catalog state refers to a missing recipe.')
    for recipe in recipes:
        if not (ROOT / recipe).with_name('scenarioforge.vuln.yaml').is_file():
            raise ValueError(f'Missing guidance for {recipe}')
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob('*')):
            if path.is_file() and path.name != '.DS_Store' and '__pycache__' not in path.parts:
                archive.write(path, path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP integrity check failed.')
    print(f'Created {output}: {len(recipes)} recipes with notes, state, and guidance.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='Destination ZIP outside the vulnhub directory')
    package_catalog(parser.parse_args().output)
