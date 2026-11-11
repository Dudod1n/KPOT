"""Download the official signed WinDivert files that the Windows build ships."""
import argparse
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile


VERSION = '2.2.2-A'
URL = f'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-{VERSION}.zip'
ARCHIVE_SHA256 = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
# Archive member -> (shipped name, SHA-256 or None for the license text).
FILES = {
    'x64/WinDivert.dll': (
        'WinDivert.dll', 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'),
    'x64/WinDivert64.sys': (
        'WinDivert64.sys', '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'),
    'LICENSE': ('WinDivert-LICENSE.txt', None),
}


def extract(archive_bytes, output):
    if hashlib.sha256(archive_bytes).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('WinDivert archive does not match the pinned SHA-256')
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for member, (name, digest) in FILES.items():
            content = archive.read(f'WinDivert-{VERSION}/{member}')
            if digest and hashlib.sha256(content).hexdigest() != digest:
                raise ValueError(f'{name} does not match the pinned SHA-256')
            (output / name).write_bytes(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with urllib.request.urlopen(URL, timeout=60) as response:
        extract(response.read(), args.output)


if __name__ == '__main__':
    main()
