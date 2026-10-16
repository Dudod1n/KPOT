"""Collect release notices from the locked target dependency graph (stdlib only)."""
import argparse
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
NOTICE_NAME = re.compile(r'^(?:licen[cs]e|unlicense|copying|copyright|notice|thirdpartynotices)(?:$|[._-])', re.I)
# These published crate versions omit their declared standard license text.
FALLBACKS = {
    **{(name, '0.33.3'): 'Apache-2.0' for name in (
        'ecolor', 'eframe', 'egui-wgpu', 'egui-winit', 'egui', 'egui_glow',
        'emath', 'epaint', 'epaint_default_fonts')},
    ('delegate', '0.13.5'): 'Apache-2.0',
    ('pageant', '0.2.2'): 'Apache-2.0',
    ('profiling', '1.0.18'): 'Apache-2.0',
    ('russh-cryptovec', '0.62.0'): 'Apache-2.0',
    ('russh-util', '0.52.0'): 'Apache-2.0',
    ('russh', '0.63.3'): 'Apache-2.0',
    ('unicode-casefold', '0.2.0'): 'Apache-2.0',
    ('clipboard-win', '5.4.1'): 'BSL-1.0',
    ('hexf-parse', '0.2.1'): 'CC0-1.0',
}


def runtime_packages(metadata):
    nodes = {node['id']: node for node in metadata['resolve']['nodes']}
    root = metadata['resolve']['root']
    pending, selected = [root], set()
    while pending:
        package = pending.pop()
        if package in selected:
            continue
        selected.add(package)
        pending.extend(dep['pkg'] for dep in nodes[package]['deps']
                       if any(kind['kind'] is None for kind in dep['dep_kinds']))
    return sorted((p for p in metadata['packages'] if p['id'] in selected and p['id'] != root),
                  key=lambda p: (p['name'], p['version']))


def package_notices(package):
    directory = Path(package['manifest_path']).parent
    files = {p for p in directory.rglob('*') if p.is_file() and NOTICE_NAME.match(p.name)
             and not {'tests', 'examples', 'benches', 'target', '.git'}.intersection(
                 p.relative_to(directory).parts[:-1])}
    license_file = package.get('license_file')
    if license_file:
        path = directory / license_file
        if not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
            raise ValueError(f"{package['name']} {package['version']}: invalid license_file")
        files.add(path)
    notices = [(p.relative_to(directory).as_posix(), p.read_text(encoding='utf-8'))
               for p in sorted(files) if p.stat().st_size]
    has_license = any(re.match(r'^(?:licen[cs]e|unlicense|copying)', Path(name).name, re.I)
                      for name, _ in notices)
    fallback = FALLBACKS.get((package['name'], package['version']))
    if fallback:
        declaration = package.get('license') or ''
        if fallback not in re.split(r'[\s()/]+', declaration):
            raise ValueError(f"{package['name']}: fallback no longer matches declared license")
        path = ROOT / 'licenses' / 'standard' / (fallback + '.txt')
        notices.append((f'Standard {fallback} (selected from declared license)',
                        path.read_text(encoding='utf-8')))
        has_license = True
    if package['name'] == 'epaint_default_fonts' and package['version'] == '0.33.3':
        notices.extend(('fonts/' + p.name, p.read_text(encoding='utf-8'))
                       for p in sorted((ROOT / 'licenses' / 'fonts').glob('*.txt')))
    if not has_license:
        raise ValueError(f"{package['name']} {package['version']}: missing usable license text; "
                         'review upstream licensing and add a version-specific fallback')
    return notices


def cargo(*arguments):
    return subprocess.check_output(['cargo', *arguments], cwd=ROOT, text=True, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    metadata = json.loads(cargo('metadata', '--locked', '--format-version=1',
                                '--filter-platform', args.target))
    # Metadata also lists inactive optional edges; cargo tree resolves active features.
    tree = cargo('tree', '--locked', '--offline', '--target', args.target, '--edges', 'normal',
                 '--prefix', 'none', '--format', '{p}')
    active = set(re.findall(r'^(\S+) v(\S+)', tree, re.M))
    packages = [p for p in runtime_packages(metadata) if (p['name'], p['version']) in active]
    if not packages:
        raise ValueError('Cargo returned no active runtime dependencies')
    sections = [f'KROT third-party notices — {args.target}\n\n'
                'KROT application code is GPL-3.0-only. Dependencies and embedded fonts\n'
                'retain their original licenses. This file preserves upstream license\n'
                'and attribution texts for the locked runtime dependency graph.\n']
    for package in packages:
        sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\n"
                        f"Declared license: {package['license']}\n"
                        f"Source: {package.get('repository') or 'https://crates.io/crates/' + package['name']}\n")
        for name, contents in package_notices(package):
            sections.append(f'\n--- {name} ---\n{contents.rstrip()}\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(sections), encoding='utf-8')
    print(f'Collected notices for {len(packages)} runtime packages: {args.output}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'License collection failed: {error}') from error
