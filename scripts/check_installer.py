"""Install, use, upgrade and remove the КРОТ package on this Windows computer, checking each step.

For CI on a disposable runner with administrator rights: it changes the system. It checks
that the service runs from Program Files as LocalSystem, that nobody but administrators can
change the installed files, that the installed КРОТ gets its interception helper from the
service, that an upgrade keeps the service working and that removal leaves nothing behind.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


PROGRAM_FILES = Path(os.environ.get('ProgramW6432', r'C:\Program Files'))
PROGRAM_DATA = Path(os.environ.get('ProgramData', r'C:\ProgramData'))
INSTALL = PROGRAM_FILES / 'KROT'
DATA = PROGRAM_DATA / 'KROT'
SHORTCUT = PROGRAM_DATA / r'Microsoft\Windows\Start Menu\Programs\КРОТ.lnk'
SERVICE = 'KrotDivert'
FILES = ['krot.exe', 'krot-cli.exe', 'WinDivert.dll', 'WinDivert64.sys',
         'LICENSE.txt', 'THIRD_PARTY_NOTICES.txt', 'WinDivert-LICENSE.txt']
SYSTEM, ADMINISTRATORS = 'S-1-5-18', 'S-1-5-32-544'
TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
# DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
WRITE_RIGHTS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
INHERIT_ONLY = 2


def step(text):
    print(f'== {text}', flush=True)


def powershell(script, **variables):
    environment = dict(os.environ, **{f'KROT_{key.upper()}': str(value) for key, value in variables.items()})
    prologue = '[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = "Stop"; '
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', prologue + script],
                            capture_output=True, env=environment, check=False)
    output = result.stdout.decode('utf-8', 'replace').strip()
    if result.returncode != 0:
        raise AssertionError(f'PowerShell failed: {result.stderr.decode("utf-8", "replace")}\n{output}')
    return json.loads(output) if output else None


def as_list(value):
    return [] if value is None else value if isinstance(value, list) else [value]


def msiexec(log, *arguments):
    result = subprocess.run(['msiexec', *arguments, '/qn', '/norestart', '/l*v', str(log)], check=False)
    if result.returncode != 0:
        print(Path(log).read_text(encoding='utf-16', errors='replace')[-20000:])
        raise AssertionError(f'msiexec {" ".join(arguments)} exited with {result.returncode}')


def acl(path):
    return powershell(
        '$acl = Get-Acl -LiteralPath $env:KROT_PATH; '
        '[pscustomobject]@{ owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; '
        'protected = $acl.AreAccessRulesProtected; '
        'rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { '
        '[pscustomobject]@{ sid = $_.IdentityReference.Value; rights = [long]$_.FileSystemRights.value__; '
        'allow = ($_.AccessControlType -eq "Allow"); propagation = [int]$_.PropagationFlags } }) } '
        '| ConvertTo-Json -Depth 4 -Compress', path=path)


def check_admin_only(path, owners=(SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER)):
    """Only SYSTEM, administrators and TrustedInstaller may change `path` or own it."""
    info = acl(path)
    assert info['owner'] in owners, f'{path}: owner {info["owner"]}'
    for rule in as_list(info['rules']):
        if not rule['allow'] or rule['propagation'] & INHERIT_ONLY:
            continue
        if rule['sid'] not in (SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER):
            assert not rule['rights'] & 0xFFFFFFFF & WRITE_RIGHTS, f'{path}: {rule["sid"]} may write'
    return info


def service():
    return powershell(
        f'Get-CimInstance Win32_Service -Filter "Name=\'{SERVICE}\'" | '
        'Select-Object State, StartMode, StartName, PathName | ConvertTo-Json -Compress')


def uninstall_entries():
    return as_list(powershell(
        'Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall | '
        'ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -eq "КРОТ" } | '
        'Select-Object DisplayName, DisplayVersion | ConvertTo-Json -Compress'))


def helpers():
    """Owners of the running helpers that the service started."""
    return as_list(powershell(
        'Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*divert-service*" } | '
        'ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } | ConvertTo-Json -Compress'))


def krot_processes():
    return as_list(powershell(
        'Get-Process -Name krot, krot-cli -ErrorAction SilentlyContinue | '
        'Select-Object Id, Path | ConvertTo-Json -Compress'))


def wait(condition, what, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(1)
    raise AssertionError(f'Timed out: {what}')


def cli(config, *arguments, check=True):
    result = subprocess.run([str(INSTALL / 'krot-cli.exe'), '--config', str(config), *arguments],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', check=False)
    if check and result.returncode != 0:
        raise AssertionError(f'krot-cli {" ".join(arguments)}: {result.stdout}{result.stderr}')
    return result


def attached(config):
    result = cli(config, 'metrics', check=False)
    try:
        return result.returncode == 0 and json.loads(result.stdout).get('helper_attached') is True
    except json.JSONDecodeError:
        return False


def task_name(registration, executable):
    digest = hashlib.sha256(executable.replace('/', '\\').lower().encode()).hexdigest()
    return f'\\{registration}-logon-{digest[:8]}'


def task_exists(name):
    return subprocess.run(['schtasks', '/query', '/tn', name], capture_output=True, check=False).returncode == 0


def create_task(name, executable):
    subprocess.run(['schtasks', '/create', '/tn', name, '/tr', f'"{executable}" serve', '/sc', 'onlogon', '/f'],
                   check=True, capture_output=True)


def run_values():
    return powershell(
        '$key = Get-Item HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; '
        '@($key.GetValueNames() | Where-Object { $_ -like "krot-*" }) | ConvertTo-Json -Compress')


def check_installed(version):
    step('files, rights and registration')
    for name in FILES:
        assert (INSTALL / name).is_file(), f'missing {name}'
        check_admin_only(INSTALL / name)
    check_admin_only(INSTALL)
    data = check_admin_only(DATA, owners=(SYSTEM, ADMINISTRATORS))
    assert data['protected'], 'ProgramData\\KROT inherits access rules'
    assert {rule['sid'] for rule in as_list(data['rules'])} <= {SYSTEM, ADMINISTRATORS}, data
    assert SHORTCUT.is_file(), 'no Start menu shortcut'
    entries = uninstall_entries()
    assert len(entries) == 1 and entries[0]['DisplayVersion'] == version, entries
    state = service()
    assert state and state['State'] == 'Running' and state['StartMode'] == 'Auto', state
    assert state['StartName'] == 'LocalSystem', state
    assert state['PathName'].lower().startswith(f'"{INSTALL / "krot.exe"}" '.lower()), state


def check_interception(config):
    step('the installed КРОТ gets its helper from the service')
    cli(config, 'background')
    wait(lambda: attached(config), 'helper attached to the background КРОТ')
    owners = helpers()
    assert owners and all(owner == 'SYSTEM' for owner in owners), owners


def check_stopped(config):
    cli(config, 'stop')
    wait(lambda: not helpers(), 'helper ends with the background КРОТ', 30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--upgrade', type=Path, required=True, help='a package of a higher version')
    parser.add_argument('--version', required=True)
    parser.add_argument('--upgrade-version', required=True)
    args = parser.parse_args()
    if sys.platform != 'win32':
        raise SystemExit('Windows only')
    work = Path(tempfile.mkdtemp(prefix='krot-installer-'))
    config = work / 'config.json'
    rule = {'id': 'curl', 'name': 'curl', 'path': r'C:\Windows\System32\curl.exe',
            'tunnel_id': 'absent', 'enabled': True, 'on_tunnel_down': 'block', 'children': False}
    (work / 'config.json.apps.json').write_text(json.dumps({'version': 1, 'rules': [rule]}), encoding='utf-8')
    installed = str(INSTALL / 'krot.exe')
    own_task = task_name('krot-0123456789abcdef', installed)
    foreign_task = task_name('krot-0123456789abcdef', r'C:\Portable\KROT\krot.exe')

    step('install')
    msiexec(work / 'install.log', '/i', str(args.package.resolve()))
    check_installed(args.version)
    check_interception(config)
    cli(config, 'autostart', 'enable')
    assert run_values(), 'autostart did not create a Run value'
    create_task(own_task, installed)
    create_task(foreign_task, r'C:\Portable\KROT\krot.exe')
    check_stopped(config)

    step('upgrade')
    msiexec(work / 'upgrade.log', '/i', str(args.upgrade.resolve()))
    check_installed(args.upgrade_version)
    assert run_values() and task_exists(own_task), 'the upgrade removed autostart'
    check_interception(config)

    step('remove with КРОТ running')
    msiexec(work / 'remove.log', '/x', str(args.upgrade.resolve()))
    assert not INSTALL.exists(), list(INSTALL.rglob('*'))
    assert not DATA.exists(), 'ProgramData\\KROT remains'
    assert not SHORTCUT.exists(), 'the Start menu shortcut remains'
    assert service() is None, 'the service remains'
    assert not uninstall_entries(), 'the Installed apps entry remains'
    assert powershell('Test-Path HKLM:\\SOFTWARE\\KROT | ConvertTo-Json') is False, 'HKLM\\SOFTWARE\\KROT remains'
    assert not as_list(run_values()), 'Run values remain'
    assert not task_exists(own_task), 'the logon task of the installed copy remains'
    assert task_exists(foreign_task), 'the task of another copy was removed'
    subprocess.run(['schtasks', '/delete', '/tn', foreign_task, '/f'], check=True, capture_output=True)
    assert not krot_processes(), krot_processes()
    rules = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=KROT-service-relay'],
                           capture_output=True, check=False)
    assert rules.returncode != 0, 'firewall rules of the service remain'
    step('done')


if __name__ == '__main__':
    main()
