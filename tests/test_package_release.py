"""Release archives must contain the tested binaries, licenses and matching hashes."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    'package_release', Path(__file__).resolve().parents[1] / 'scripts/package_release.py')
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class PackageTests(unittest.TestCase):
    def test_archives_preserve_binaries_licenses_and_release_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'assets').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nversion = "1.2.3"\n')
            (root / 'CHANGELOG.md').write_text('# Changes\n\n## Не выпущено\nFuture\n\n'
                                               '## 1.2.3 — 2026-10-16\n\n### Fixed\n- Port cleanup.\n\n'
                                               '## 1.2.2\nOld changes\n', encoding='utf-8')
            (root / 'LICENSE').write_text('GPL test notice')
            for name in ['krot.png', 'krot.ico']:
                (root / 'assets' / name).write_bytes(b'icon')
            builds, output, notes = root / 'builds', root / 'output', root / 'notes.md'
            for runner, suffix in [('Linux', ''), ('Windows', '.exe')]:
                source = builds / f'krot-rust-{runner}-X64'
                source.mkdir(parents=True)
                for name in ['krot', 'krot-cli']:
                    (source / (name + suffix)).write_bytes((runner + name).encode())
                (source / 'THIRD_PARTY_NOTICES.txt').write_text(runner + ' licenses')
            with patch.object(packager, 'ROOT', root):
                packager.package('v1.2.3', builds, output, notes)
            self.assertEqual(notes.read_text(), '### Fixed\n- Port cleanup.\n')
            self.assertEqual(len(list(output.iterdir())), 10)
            for line in (output / 'SHA256SUMS').read_text().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())
            with zipfile.ZipFile(output / 'krot-1.2.3-windows-x64.zip') as archive:
                self.assertEqual(archive.read('krot.exe'), b'Windowskrot')
                self.assertEqual(archive.read('LICENSE'), b'GPL test notice')
                self.assertEqual(archive.read('THIRD_PARTY_NOTICES.txt'), b'Windows licenses')
                self.assertIn(b'/tree/v1.2.3', archive.read('README.txt'))
            with tarfile.open(output / 'krot-1.2.3-linux-x64.tar.gz') as archive:
                self.assertEqual(archive.extractfile('krot-1.2.3/krot-cli').read(), b'Linuxkrot-cli')
                self.assertEqual(archive.getmember('krot-1.2.3/krot-cli').mode & 0o777, 0o755)
                self.assertEqual(archive.extractfile('krot-1.2.3/THIRD_PARTY_NOTICES.txt').read(), b'Linux licenses')
                self.assertEqual(archive.extractfile('krot-1.2.3/LICENSE').read(), b'GPL test notice')

    def test_invalid_tag_and_missing_notes_fail_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[package]\nversion = "1.2.3"\n')
            (root / 'CHANGELOG.md').write_text('## 1.2.2\nOld\n')
            with patch.object(packager, 'ROOT', root):
                for tag in ['v1.2.4', 'v1.2.3']:
                    with self.subTest(tag=tag), self.assertRaises(ValueError):
                        packager.package(tag, root / 'builds', root / 'output', root / 'notes')
                    self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
