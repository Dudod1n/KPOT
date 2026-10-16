"""Icon checks compare pixels and structure independently of PNG compression."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'build_icons', Path(__file__).resolve().parents[1] / 'scripts' / 'build_icons.py')
icons = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(icons)


class IconTests(unittest.TestCase):
    def test_check_accepts_recompressed_png_and_ico(self):
        compress = icons.zlib.compress
        with patch.object(icons.zlib, 'compress', lambda data, level: compress(data, 1)):
            assets = {'krot.svg': icons.svg(), 'krot.png': icons.png(256),
                      'krot-tray.png': icons.png(32), 'krot.ico': icons.ico()}
        self.assertNotEqual(assets['krot.png'], icons.png(256))
        self.assertNotEqual(assets['krot.ico'], icons.ico())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'assets').mkdir()
            for name, content in assets.items():
                (root / 'assets' / name).write_bytes(content)
            with patch.object(icons, 'ROOT', root), patch('sys.argv', ['build_icons.py', '--check']):
                icons.main()

    def test_changed_pixels_are_rejected_with_valid_png_structure(self):
        with patch.dict(icons.PALETTE, {'o': (1, 2, 3, 255)}):
            changed = icons.png(32)
        with self.assertRaisesRegex(AssertionError, 'pixels'):
            icons.validate_png(changed, 32)


if __name__ == '__main__':
    unittest.main()
