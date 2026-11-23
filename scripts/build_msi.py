"""Build the Windows Installer package of КРОТ with WiX Toolset 5.

The package takes the release binaries, the pinned WinDivert files and the license texts
from --binaries. The executables must be signed before this step and the package after it,
once a signing certificate exists (see docs/RELEASING.md).
"""
import argparse
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'installer' / 'krot.wxs'
# The wizard's dialogs and their Russian texts; CI adds the extension with `wix extension add -g`.
UI_EXTENSION = 'WixToolset.UI.wixext/5.0.2'
INPUTS = ['krot.exe', 'krot-cli.exe', 'WinDivert.dll', 'WinDivert64.sys',
          'WinDivert-LICENSE.txt', 'THIRD_PARTY_NOTICES.txt']


def cargo_version():
    return tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']


def package_version(version):
    """The numeric part that Windows Installer compares; it ignores anything after three fields."""
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:[-+].*)?', version)
    if not match:
        raise ValueError(f'Unsupported version: {version}')
    major, minor, patch = (int(part) for part in match.groups())
    if major > 255 or minor > 255 or patch > 65535:
        raise ValueError(f'Windows Installer cannot hold version {version}')
    return f'{major}.{minor}.{patch}'


def package_name(version):
    return f'krot-{version}-windows-x64.msi'


def command(wix, binaries, output, version):
    return [str(wix), 'build', str(SOURCE), '-arch', 'x64',
            '-ext', UI_EXTENSION, '-culture', 'ru-RU',
            '-d', f'Version={package_version(version)}',
            '-d', f'Binaries={binaries}',
            '-d', f'Root={ROOT}',
            '-o', str(output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='package path; by default next to the binaries')
    parser.add_argument('--version', help='package version instead of the one in Cargo.toml')
    parser.add_argument('--wix', default='wix', help='the wix command')
    args = parser.parse_args()
    version = args.version or cargo_version()
    binaries = args.binaries.resolve()
    for name in INPUTS:
        if not (binaries / name).is_file():
            raise SystemExit(f'Missing installer input: {binaries / name}')
    output = args.output or binaries / package_name(version)
    subprocess.run(command(args.wix, binaries, output, version), check=True)
    print(output)


if __name__ == '__main__':
    main()
