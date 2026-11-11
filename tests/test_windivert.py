"""The shipped WinDivert files are pinned once and the helper refuses anything else."""
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('fetch_windivert', ROOT / 'scripts/fetch_windivert.py')
fetcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetcher)


def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as bundle:
        for member, content in files.items():
            bundle.writestr(f'WinDivert-{fetcher.VERSION}/{member}', content)
    return buffer.getvalue()


class WinDivertTests(unittest.TestCase):
    def test_helper_and_fetcher_pin_the_same_files(self):
        source = (ROOT / 'src/divert.rs').read_text(encoding='utf-8')
        pinned = dict(re.findall(r'pub const (DLL|SYS)_SHA256: &str = "([0-9a-f]{64})";', source))
        self.assertEqual(pinned['DLL'], fetcher.FILES['x64/WinDivert.dll'][1])
        self.assertEqual(pinned['SYS'], fetcher.FILES['x64/WinDivert64.sys'][1])

    def test_published_names_match_what_the_application_downloads(self):
        source = (ROOT / 'src/divert.rs').read_text(encoding='utf-8')
        packager = (ROOT / 'scripts/package_release.py').read_text(encoding='utf-8')
        for name in re.findall(r'name: "(WinDivert[^"]+)"', source):
            self.assertIn(name, [shipped for shipped, _ in fetcher.FILES.values()])
            self.assertIn(f"'{name}'", packager)

    def test_only_the_pinned_archive_and_files_are_extracted(self):
        files = {'x64/WinDivert.dll': b'dll', 'x64/WinDivert64.sys': b'sys', 'LICENSE': b'LGPL'}
        good = archive(files)
        digests = {
            'x64/WinDivert.dll': ('WinDivert.dll', hashlib.sha256(b'dll').hexdigest()),
            'x64/WinDivert64.sys': ('WinDivert64.sys', hashlib.sha256(b'sys').hexdigest()),
            'LICENSE': ('WinDivert-LICENSE.txt', None),
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            with self.assertRaises(ValueError):
                fetcher.extract(good, output)
            self.assertFalse(output.exists())
            with patch.object(fetcher, 'ARCHIVE_SHA256', hashlib.sha256(good).hexdigest()):
                with self.assertRaises(ValueError):
                    fetcher.extract(good, output)
                with patch.object(fetcher, 'FILES', digests):
                    fetcher.extract(good, output)
            self.assertEqual((output / 'WinDivert.dll').read_bytes(), b'dll')
            self.assertEqual((output / 'WinDivert64.sys').read_bytes(), b'sys')
            self.assertEqual((output / 'WinDivert-LICENSE.txt').read_bytes(), b'LGPL')


if __name__ == '__main__':
    unittest.main()
