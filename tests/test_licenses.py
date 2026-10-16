"""Checks for release notice coverage and dependency selection."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    'collect_licenses', Path(__file__).resolve().parents[1] / 'scripts' / 'collect_licenses.py')
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class LicenseTests(unittest.TestCase):
    def test_runtime_graph_excludes_build_and_dev_edges_but_keeps_shared_runtime(self):
        def edge(package, kind=None):
            return {'pkg': package, 'dep_kinds': [{'kind': kind}]}
        metadata = {
            'packages': [{'id': name, 'name': name, 'version': '1'}
                         for name in ['app', 'runtime', 'shared', 'builder', 'test']],
            'resolve': {'root': 'app', 'nodes': [
                {'id': 'app', 'deps': [edge('runtime'), edge('builder', 'build'), edge('test', 'dev')]},
                {'id': 'runtime', 'deps': [edge('shared')]},
                {'id': 'shared', 'deps': [edge('runtime')]},
                {'id': 'builder', 'deps': [edge('shared')]},
                {'id': 'test', 'deps': []},
            ]},
        }
        self.assertEqual([p['name'] for p in collector.runtime_packages(metadata)],
                         ['runtime', 'shared'])

    def test_missing_license_text_fails_even_when_notice_exists(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'NOTICE').write_text('Author attribution', encoding='utf-8')
            package = {'name': 'new-dependency', 'version': '1.0', 'license': 'MIT',
                       'manifest_path': str(path / 'Cargo.toml'), 'license_file': None}
            with self.assertRaisesRegex(ValueError, 'new-dependency 1.0.*license text'):
                collector.package_notices(package)

    def test_nested_notices_are_retained_and_test_fixtures_are_excluded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'LICENSE').write_text('Original license', encoding='utf-8')
            (path / 'src').mkdir()
            (path / 'src' / 'NOTICE').write_text('Nested attribution', encoding='utf-8')
            (path / 'tests').mkdir()
            (path / 'tests' / 'COPYRIGHT').write_text('Fixture only', encoding='utf-8')
            package = {'name': 'example', 'version': '1.0', 'license': 'MIT',
                       'manifest_path': str(path / 'Cargo.toml'), 'license_file': None}
            notices = collector.package_notices(package)
            self.assertEqual([name for name, _ in notices], ['LICENSE', 'src/NOTICE'])
            self.assertIn(('src/NOTICE', 'Nested attribution'), notices)

    def test_fallback_requires_reviewed_version_and_matching_declaration(self):
        with tempfile.TemporaryDirectory() as temp:
            package = {'name': 'hexf-parse', 'version': '0.2.1', 'license': 'CC0-1.0',
                       'manifest_path': str(Path(temp) / 'Cargo.toml'), 'license_file': None}
            self.assertIn('CC0', collector.package_notices(package)[0][0])
            package['license'] = 'MIT'
            with self.assertRaisesRegex(ValueError, 'no longer matches'):
                collector.package_notices(package)
            package.update(version='0.2.2', license='CC0-1.0')
            with self.assertRaisesRegex(ValueError, 'missing usable license text'):
                collector.package_notices(package)


if __name__ == '__main__':
    unittest.main()
