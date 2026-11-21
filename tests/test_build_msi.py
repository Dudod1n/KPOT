"""The installer build names the package as the updater expects and passes numeric versions."""
import importlib.util
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('build_msi', ROOT / 'scripts/build_msi.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class BuildMsiTests(unittest.TestCase):
    def test_package_versions_are_numeric_and_within_windows_installer_limits(self):
        self.assertEqual(builder.package_version('0.7.2'), '0.7.2')
        self.assertEqual(builder.package_version('1.0.0-rc.1'), '1.0.0')
        for version in ['1.2', '256.0.0', '1.2.65536', 'v1.2.3']:
            with self.subTest(version=version), self.assertRaises(ValueError):
                builder.package_version(version)

    def test_command_and_name_match_the_updater(self):
        command = builder.command('wix', Path('bin'), Path('out.msi'), '0.7.2')
        self.assertEqual(command[:2], ['wix', 'build'])
        self.assertIn('Version=0.7.2', command)
        self.assertEqual(builder.package_name('0.7.2'), 'krot-0.7.2-windows-x64.msi')
        # src/update.rs looks the package up by the same name.
        update = (ROOT / 'src/update.rs').read_text(encoding='utf-8')
        self.assertIn('format!("krot-{version}-windows-x64.msi")', update)

    def test_the_source_installs_every_input_and_the_service(self):
        source = builder.SOURCE.read_text(encoding='utf-8')
        for name in builder.INPUTS:
            self.assertIn(f'$(var.Binaries)\\{name}', source)
        self.assertRegex(source, r'ServiceInstall Id="KrotDivert" Name="KrotDivert"')
        self.assertIn('Account="LocalSystem"', source)
        self.assertIn('Arguments="service"', source)
        self.assertIn('ExeCommand="uninstall-cleanup"', source)
        service = (ROOT / 'src/service.rs').read_text(encoding='utf-8')
        self.assertTrue(re.search(r'pub const NAME: &str = "KrotDivert";', service))


if __name__ == '__main__':
    unittest.main()
