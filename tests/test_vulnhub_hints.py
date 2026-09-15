"""Source-grounded checks for tiering, port parsing, and reproduction preservation."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hints', ROOT / 'scripts/generate_vulnhub_hints.py')
hints = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hints)


class GuidanceTests(unittest.TestCase):
    def test_complete_catalog_and_tiering(self):
        paths = sorted(hints.CONTENT.rglob('docker-compose.yml'))
        self.assertEqual(len(paths), 306)
        for path in paths:
            with self.subTest(recipe=path.parent):
                record = hints.build_metadata(path)
                stored = hints.yaml.safe_load((path.parent / 'scenarioforge.vuln.yaml').read_text())
                self.assertEqual(record, stored)
                for level in ('low', 'medium', 'high'):
                    self.assertTrue(record['hint_levels'][level])
                self.assertNotIn('CVE-', '\n'.join(record['hint_levels']['low']))
                self.assertNotIn('CVERecord', '\n'.join(record['hint_levels']['medium']))
                self.assertGreaterEqual(len(record['access_instructions']['steps']), 2)
                self.assertTrue(any('Publicly available documentation:' in text for text in record['hint_levels']['high']))
                self.assertNotIn('To be completed.', str(record))
                self.assertNotIn('docker compose exec', str(record))
                self.assertNotIn('docker compose up', str(record))
                self.assertEqual(record['guidance_source']['readme_sha256'], hints.hashlib.sha256((path.parent / 'README.md').read_bytes()).hexdigest())

    def test_port_mapping_preserves_protocols_and_ranges(self):
        ports, mappings = hints.published_ports({'services': {'test': {'ports': ['5353:53/udp', '8080:80', '9000-9002:9000-9002']}}})
        self.assertEqual(ports, {'tcp': ['8080', '9000-9002'], 'udp': ['5353']})
        self.assertIn('test: 5353/udp → container 53/udp', mappings)
        self.assertEqual(hints.published_ports({'services': {'test': {}}})[0], {'tcp': [], 'udp': []})
        with self.assertRaises(ValueError):
            hints.published_ports({'services': {'test': {'ports': ['8080']}}})

    def test_target_substitution_preserves_internal_ssrf_address(self):
        self.assertIn('http://{{NODE_IP}}:8080', hints.clean_documentation('http://localhost:8080', 'spring/CVE-2022-22965'))
        self.assertIn('http://127.0.0.1:7001', hints.clean_documentation('operator=http://127.0.0.1:7001', 'weblogic/ssrf'))

    def test_raw_request_separator_and_literal_payload_braces(self):
        request = 'POST / HTTP/1.1\nHost: your-ip:8080\nContent-Length: 9\n\n{{7*7}}'
        cleaned = hints.clean_documentation(request, 'example/test')
        self.assertIn('Host: {{NODE_IP}}:8080\n\n{{7*7}}', cleaned)
        self.assertNotIn('Content-Length:', cleaned)

    def test_no_network_port_does_not_invent_a_service(self):
        record = hints.build_metadata(hints.CONTENT / 'imagemagick/CVE-2020-29599/docker-compose.yml')
        self.assertNotIn('nmap ', str(record['hint_levels']['medium']))
        self.assertIn('publishes no network port', record['hint_levels']['medium'][0])

    def test_screenshot_supplements_include_command_text(self):
        for name, command in [('redis/4-unacc', 'redis-master.py'), ('php/fpm', 'python fpm3.py'), ('tomcat/CVE-2020-1938', 'python2 CNVD-2020-10487')]:
            record = hints.build_metadata(hints.CONTENT / name / 'docker-compose.yml')
            self.assertIn(command, str(record['hint_levels']['high']))


if __name__ == '__main__':
    unittest.main()
