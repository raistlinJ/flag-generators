"""Check hint coverage and recover actual generated artifacts with the published commands."""
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = sorted(p for family in ['flag_generators', 'flag_node_generators']
                   for p in (ROOT / family).rglob('manifest.yaml'))
TOKEN = re.compile(r'\{\{(.*?)\}\}')


def load_module(path):
    spec = importlib.util.spec_from_file_location('reviewed_generator', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GeneratorHintTests(unittest.TestCase):
    def test_coverage_templates_and_tiering(self):
        self.assertEqual(len(MANIFESTS), 148)
        for path in MANIFESTS:
            with self.subTest(generator=str(path.parent)):
                manifest = yaml.safe_load(path.read_text())
                hints = manifest['hint_levels']
                self.assertTrue(all(hints.get(level) for level in ['low', 'medium', 'high']))
                self.assertIn('Answer: {{OUTPUT.Flag(flag_id)}}', hints['high'])
                self.assertNotIn('OUTPUT.', '\n'.join(hints['low']))
                self.assertNotIn('OUTPUT.Flag(flag_id)', '\n'.join(hints['medium']))
                self.assertNotIn('OUTPUT.Credential', '\n'.join(hints['medium']))
                all_hints = '\n'.join(sum(hints.values(), []))
                self.assertNotIn('complete workflow', all_hints)
                declared = {key.replace(' ', '') for key in manifest['artifacts']['produces']}
                for token in TOKEN.findall(all_hints):
                    if token == 'THIS_NODE_NAME':
                        continue
                    self.assertTrue(token.startswith('OUTPUT.'), token)
                    key = token[7:].split(':', 1)[0].replace(' ', '')
                    self.assertIn(key, declared)
                if manifest['kind'] == 'flag-node-generator':
                    self.assertNotIn('OUTPUT.File(path)', all_hints)

    def test_shell_examples_parse(self):
        for path in MANIFESTS:
            hints = yaml.safe_load(path.read_text())['hint_levels']
            for command in re.findall(r'```bash\n(.*?)```', '\n'.join(sum(hints.values(), [])), re.S):
                command = TOKEN.sub('example', command)
                for placeholder in ['<username>', '<password>', '<prior-value>']:
                    command = command.replace(placeholder, 'example')
                result = subprocess.run(['sh', '-n'], input=command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, f'{path}: {result.stderr}')

    def test_artifact_recovery_commands(self):
        checked = 0
        for path in MANIFESTS:
            manifest = yaml.safe_load(path.read_text())
            if manifest['kind'] != 'flag-generator':
                continue
            module = load_module(path.with_name('generator.py'))
            if not hasattr(module, 'build_artifact'):
                continue
            variant = manifest.get('env', {}).get('ARTIFACT_VARIANT_ID', str(manifest['id']))
            builder = module.VARIANTS[variant]['builder']
            if builder.startswith('hash_') and builder not in {'hash_hmac', 'hash_sha512'}:
                continue  # One-way hash recipes use the direct answer, not a fictitious recovery.
            with self.subTest(generator=variant), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                expected = 'CHECK{abcDEF012345}'
                result = module.build_artifact(variant, {'seed': 'hint-review', 'Flag(flag_id)': expected}, folder)
                artifact = folder / result['outputs']['File(path)']
                shutil.copyfile(artifact, folder / artifact.name)
                high = '\n'.join(manifest['hint_levels']['high'])
                command = re.search(r'```bash\n(.*?)```', high, re.S)[1]
                command = command.replace('{{OUTPUT.File(path):basename}}', artifact.name)
                recovered = subprocess.run(['sh', '-c', command], cwd=folder, capture_output=True, text=True, timeout=10)
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                expected = expected.upper() if builder == 'enc_morse' else expected
                self.assertIn(expected, recovered.stdout)
                checked += 1
        self.assertGreaterEqual(checked, 40)


if __name__ == '__main__':
    unittest.main()
