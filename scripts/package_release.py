"""Package checked binaries, licenses and user-facing release notes."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def release_notes(version):
    lines = (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8').splitlines()
    heading = re.compile(r'## \[?' + re.escape(version) + r'\]?(?:\s.*)?$')
    start = next((i + 1 for i, line in enumerate(lines) if heading.fullmatch(line)), None)
    if start is None:
        raise ValueError(f'CHANGELOG.md has no section for {version}')
    end = next((i for i in range(start, len(lines)) if lines[i].startswith('## ')), len(lines))
    notes = '\n'.join(lines[start:end]).strip()
    if not notes:
        raise ValueError(f'CHANGELOG.md section for {version} is empty')
    return notes + '\n'


def package(tag, builds, output, notes_path):
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tag != 'v' + version:
        raise ValueError('Release tag must match a stable Cargo.toml version')
    notes = release_notes(version)
    platforms = [('linux', 'Linux', ''), ('windows', 'Windows', '.exe')]
    common = [ROOT / 'LICENSE', ROOT / 'assets/krot.png', ROOT / 'assets/krot.ico']
    for platform, runner, suffix in platforms:
        source = builds / f'krot-rust-{runner}-X64'
        for path in [source / ('krot' + suffix), source / ('krot-cli' + suffix),
                     source / 'THIRD_PARTY_NOTICES.txt', *common]:
            if not path.is_file() or not path.stat().st_size:
                raise ValueError(f'Missing release input: {path}')
    output.mkdir(parents=True)
    readme = (f'КРОТ {version} — менеджер SSH-туннелей.\n\n'
              'Распакуйте оба бинарника в каталог с правом записи.\n'
              'Запустите krot.exe на Windows или ./krot на Linux.\n'
              'Перед ручной заменой файлов полностью остановите КРОТ через меню трея.\n'
              'Конфигурация хранится отдельно от программы.\n\n'
              'Код КРОТа распространяется по GNU GPL версии 3: см. LICENSE.\n'
              'Лицензии зависимостей: THIRD_PARTY_NOTICES.txt.\n'
              f'Руководство и соответствующие исходники: https://github.com/Dudod1n/KPOT/tree/{tag}\n')
    for platform, runner, suffix in platforms:
        source = builds / f'krot-rust-{runner}-X64'
        binaries = []
        for binary in ['krot', 'krot-cli']:
            destination = output / f'{binary}-{platform}-x64{suffix}'
            shutil.copy2(source / (binary + suffix), destination)
            if platform == 'linux':
                destination.chmod(0o755)
            binaries.append((destination, binary + suffix))
        notices = output / f'THIRD_PARTY_NOTICES-{platform}-x64.txt'
        shutil.copy2(source / 'THIRD_PARTY_NOTICES.txt', notices)
        files = [*binaries, (notices, 'THIRD_PARTY_NOTICES.txt'),
                 *((path, path.name) for path in common)]
        if platform == 'windows':
            with zipfile.ZipFile(output / f'krot-{version}-windows-x64.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
                for path, name in files:
                    archive.write(path, name)
                archive.writestr('README.txt', readme)
        else:
            import io
            with tarfile.open(output / f'krot-{version}-linux-x64.tar.gz', 'w:gz') as archive:
                prefix = f'krot-{version}/'
                for path, name in files:
                    entry = archive.gettarinfo(path, arcname=prefix + name)
                    entry.mode = 0o755 if name in ('krot', 'krot-cli') else 0o644
                    with path.open('rb') as content:
                        archive.addfile(entry, content)
                content = readme.encode('utf-8')
                entry = tarfile.TarInfo(prefix + 'README.txt')
                entry.size, entry.mode = len(content), 0o644
                archive.addfile(entry, io.BytesIO(content))
    shutil.copy2(ROOT / 'LICENSE', output / 'LICENSE')
    files = sorted(output.iterdir())
    (output / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
        for path in files), encoding='utf-8')
    notes_path.write_text(notes, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--builds', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--notes', type=Path, required=True)
    args = parser.parse_args()
    package(args.tag, args.builds, args.output, args.notes)


if __name__ == '__main__':
    main()
