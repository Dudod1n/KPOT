"""Check the Rust executable against real loopback SSH; Python is test-only.

Run after cargo build: .venv/bin/python scripts/check_rust.py -v
KROT_RUST_BIN can select an independently built executable.
"""
import asyncio
import contextlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))

import asyncssh
from ssh_support import Client, Config, Endpoint, SSHFixtures, Store

BINARY = Path(os.environ.get('KROT_RUST_BIN', ROOT / 'target' / 'debug' / ('krot-cli.exe' if os.name == 'nt' else 'krot-cli'))).resolve()


class RustIntegration(unittest.IsolatedAsyncioTestCase):
    server = SSHFixtures.server
    tunnel = SSHFixtures.tunnel
    echo_bytes = SSHFixtures.echo_bytes
    exchange = SSHFixtures.exchange
    assert_closed = SSHFixtures.assert_closed

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='krot-rust-')
        self.path = Path(self.temp.name)
        self.store = Store(self.path / 'config.json')
        self.client = Client(self.store.path)
        self.connections, self.servers = set(), []
        self.auths, self.forwarded, self.prompts = [], [], []
        self.process = None
        self.echo = await asyncio.start_server(self.echo_bytes, '127.0.0.1', 0)
        self.echo_port = self.echo.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        with contextlib.suppress(Exception):
            await self.request('shutdown')
        if self.process:
            try:
                await asyncio.wait_for(self.process.wait(), 8)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        for connection in list(self.connections):
            connection.abort()
        await asyncio.gather(*(c.wait_closed() for c in list(self.connections)), return_exceptions=True)
        for server in self.servers:
            server.close()
            await server.wait_closed()
        self.echo.close()
        await self.echo.wait_closed()
        self.temp.cleanup()

    async def request(self, command, payload=None):
        return await asyncio.to_thread(self.client.request, command, payload)

    async def cli(self, *args):
        proc = await asyncio.create_subprocess_exec(
            str(BINARY), '--config', str(self.store.path), *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 20)
        return proc.returncode, out.decode('utf-8'), err.decode('utf-8')

    async def start(self, config):
        self.store.save(config)
        self.process = await asyncio.create_subprocess_exec(
            str(BINARY), '--config', str(self.store.path), 'serve',
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(15):
            while True:
                if self.process.returncode is not None:
                    self.fail((await self.process.stderr.read()).decode('utf-8'))
                try:
                    return await self.request('snapshot')
                except ValueError:
                    await asyncio.sleep(.03)

    async def wait(self, tunnel, expected=('running',), *, credentials=None, trust=True):
        credentials = credentials or {}
        last = None
        async with asyncio.timeout(30):
            while True:
                last = await self.request('snapshot')
                pending = last['prompts'].get(tunnel.id)
                if pending:
                    prompt = pending['request']
                    answer = trust if prompt['kind'] in ('trust', 'hostchanged') else credentials.get(prompt['endpoint']['port'])
                    if answer is not None:
                        self.prompts.append(prompt)
                        await self.request('answer', {'id': pending['id'], 'value': answer})
                status = last['runtimes'].get(tunnel.id, {})
                if status.get('state') in expected:
                    return status
                if status.get('state') == 'error' and 'error' not in expected:
                    self.fail(f"{tunnel.name}: {status.get('message')}")
                await asyncio.sleep(.025)

    async def pending(self, tunnel, kind):
        async with asyncio.timeout(20):
            while True:
                snapshot = await self.request('snapshot')
                pending = snapshot['prompts'].get(tunnel.id)
                if pending:
                    if pending['request']['kind'] == kind:
                        return pending
                    self.assertEqual(pending['request']['kind'], 'trust')
                    await self.request('answer', {'id':pending['id'], 'value':True})
                elif snapshot['runtimes'].get(tunnel.id, {}).get('state') == 'error':
                    self.fail(snapshot['runtimes'][tunnel.id]['message'])
                await asyncio.sleep(.025)

    async def test_cli_checks_without_display_or_writing_configuration(self):
        code, out, err = await self.cli('check')
        self.assertEqual(code, 0, err)
        self.assertIn('SSH не запускается', out)
        self.assertFalse(self.store.path.exists())
        self.store.path.write_text('{broken', encoding='utf-8')
        code, _, err = await self.cli('check')
        self.assertNotEqual(code, 0)
        self.assertIn('КРОТ', err)
        self.assertEqual(self.store.path.read_text(), '{broken')

    async def test_local_remote_socks_and_listener_cleanup(self):
        server = await self.server()
        tunnels = [self.tunnel(server, kind=kind) for kind in ('L', 'R', 'D')]
        for index, tunnel in enumerate(tunnels):
            tunnel.name = f'tunnel-{index}'
        await self.start(Config(tunnels=tunnels))
        for tunnel in tunnels:
            await self.request('start', tunnel.id)
            status = await self.wait(tunnel)
            self.assertIsNotNone(status['started_at'])
            await self.exchange(tunnel.port, socks=tunnel.kind == 'D')
            await self.request('stop', tunnel.id)
            await self.assert_closed(tunnel.port)
            saved = self.store.load()
            self.assertFalse(next(t for t in saved.tunnels if t.id == tunnel.id).enabled)
        self.assertEqual([p['kind'] for p in self.prompts], ['trust'])

    async def test_two_jumps_password_and_encrypted_key(self):
        key = asyncssh.generate_private_key('ssh-ed25519')
        key_path = self.path / 'encrypted key'
        key_path.write_bytes(key.export_private_key('openssh', passphrase='key-passphrase'))
        first = await self.server(password='jump-password')
        second = await self.server(client_key=key.convert_to_public())
        target = await self.server(password='target-password')
        tunnel = self.tunnel(target)
        tunnel.server.auth = 'password'
        tunnel.jumps_enabled = True
        tunnel.jumps = [Endpoint(host='127.0.0.1', port=first.get_port(), user='ops', auth='password'),
                        Endpoint(host='127.0.0.1', port=second.get_port(), user='deploy', auth='key', key=str(key_path))]
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start', tunnel.id)
        await self.wait(tunnel, credentials={first.get_port():'jump-password',second.get_port():'key-passphrase',target.get_port():'target-password'})
        await self.exchange(tunnel.port)
        self.assertEqual([p['kind'] for p in self.prompts], ['trust','password','trust','passphrase','trust','password'])
        snapshot = json.dumps(await self.request('snapshot'))
        for secret in ('jump-password','target-password','key-passphrase'):
            self.assertNotIn(secret, snapshot)
            self.assertNotIn(secret, self.store.path.read_text())
        await self.request('stop', tunnel.id)
        await self.assert_closed(tunnel.port)
        async with asyncio.timeout(5):
            while self.connections:
                await asyncio.sleep(.02)

    @unittest.skipUnless(os.name != 'nt' and shutil.which('ssh-agent') and shutil.which('ssh-add'),
                         'Requires local OpenSSH agent executables')
    async def test_real_ssh_agent_signs_for_connection(self):
        key = asyncssh.generate_private_key('ssh-ed25519')
        key_path = self.path / 'agent_key'
        key_path.write_bytes(key.export_private_key())
        key_path.chmod(0o600)
        agent_path = str(self.path / 'agent.sock')
        agent = await asyncio.create_subprocess_exec(
            'ssh-agent', '-D', '-a', agent_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        try:
            async with asyncio.timeout(3):
                while not Path(agent_path).exists():
                    await asyncio.sleep(.01)
            environment = {**os.environ, 'SSH_AUTH_SOCK': agent_path}
            add = await asyncio.create_subprocess_exec(
                'ssh-add', str(key_path), env=environment,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            self.assertEqual(await add.wait(), 0)
            server = await self.server(client_key=key.convert_to_public())
            tunnel = self.tunnel(server)
            with patch.dict(os.environ, {'SSH_AUTH_SOCK': agent_path}):
                await self.start(Config(tunnels=[tunnel]))
            await self.request('start', tunnel.id)
            await self.wait(tunnel)
            await self.exchange(tunnel.port)
            self.assertEqual([p['kind'] for p in self.prompts], ['trust'])
            await self.request('shutdown')
            await self.process.wait()
        finally:
            agent.terminate()
            await agent.wait()

    async def test_deferred_password_does_not_block_other_tunnel(self):
        protected = await self.server(password='only-in-memory')
        normal = await self.server()
        waiting = self.tunnel(protected)
        waiting.name = 'waiting'
        waiting.server.auth = 'password'
        waiting.enabled = True
        running = self.tunnel(normal)
        running.name = 'running'
        running.enabled = True
        await self.start(Config(tunnels=[waiting,running]))
        pending = await self.pending(waiting, 'password')
        await self.wait(running)
        await self.exchange(running.port)
        with self.assertRaises(ValueError):
            await self.request('answer', {'id':pending['id'],'value':True})
        self.assertEqual((await self.request('snapshot'))['prompts'][waiting.id]['id'], pending['id'])
        await self.request('answer', {'id':pending['id'],'value':'only-in-memory'})
        await self.wait(waiting)
        await self.exchange(waiting.port)

    async def test_changed_key_requires_confirmation_before_authentication(self):
        original = await self.server(password='key-check-password')
        port = original.get_port()
        tunnel = self.tunnel(original)
        tunnel.server.auth = 'password'
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start',tunnel.id)
        await self.wait(tunnel,credentials={port:'key-check-password'})
        await self.request('stop',tunnel.id)
        trust_before = self.store.known_hosts_path.read_bytes()
        original.close()
        await original.wait_closed()
        await self.server(port=port,password='key-check-password')
        auth_count = len(self.auths)
        await self.request('start',tunnel.id)
        pending = await self.pending(tunnel,'hostchanged')
        self.assertNotEqual(pending['request']['old_fingerprint'],pending['request']['new_fingerprint'])
        await self.request('answer',{'id':pending['id'],'value':False})
        await self.wait(tunnel,('error',),trust=False)
        self.assertEqual(len(self.auths),auth_count, 'Changed host must be accepted before any password is sent')
        self.assertEqual(self.store.known_hosts_path.read_bytes(),trust_before)
        await self.request('start',tunnel.id)
        await self.wait(tunnel,credentials={port:'key-check-password'})
        await self.exchange(tunnel.port)
        self.assertNotEqual(self.store.known_hosts_path.read_bytes(),trust_before)

    async def test_immediate_cancel_and_shutdown_preserve_intent(self):
        server = await self.server()
        tunnel = self.tunnel(server)
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start',tunnel.id)
        await self.request('stop',tunnel.id)
        self.assertFalse((await self.request('snapshot'))['prompts'])
        await self.assert_closed(tunnel.port)
        await self.request('start',tunnel.id)
        await self.wait(tunnel)
        await self.request('shutdown')
        await asyncio.wait_for(self.process.wait(),8)
        self.assertFalse(self.store.path.with_name('config.json.background.json').exists())
        self.assertTrue(self.store.load().tunnels[0].enabled)
        await self.assert_closed(tunnel.port)

    async def test_network_reconnect_reuses_memory_password(self):
        server = await self.server(password='memory-password')
        tunnel = self.tunnel(server)
        tunnel.server.auth = 'password'
        tunnel.reconnect = True
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start',tunnel.id)
        first = await self.wait(tunnel,credentials={server.get_port():'memory-password'})
        for connection in list(self.connections):
            connection.abort()
        async with asyncio.timeout(20):
            while True:
                snapshot = await self.request('snapshot')
                self.assertFalse(snapshot['prompts'])
                status = snapshot['runtimes'][tunnel.id]
                if status['state'] == 'running' and status['started_at'] != first['started_at']:
                    break
                await asyncio.sleep(.05)
        await self.exchange(tunnel.port)

    async def test_background_command_detaches_and_duplicate_owner_fails(self):
        self.store.save(Config())
        code, out, err = await self.cli('background')
        self.assertEqual(code,0,err)
        self.assertIn('в фоне',out)
        self.assertEqual((await self.request('snapshot'))['config']['version'],1)
        code, _, _ = await self.cli('serve')
        self.assertNotEqual(code,0)
        code, _, err = await self.cli('stop')
        self.assertEqual(code,0,err)

    async def test_ipc_rejects_unknown_commands_and_corrupt_configuration(self):
        await self.start(Config())
        for command,payload in [('not-a-command',{'password':'must-not-echo'}),('save',{'version':1,'settings':{},'tunnels':[],'password':'must-not-echo'})]:
            with self.assertRaises(ValueError) as error:
                await self.request(command,payload)
            self.assertNotIn('must-not-echo',str(error.exception))
        self.assertEqual((await self.request('snapshot'))['config']['tunnels'],[])
        if os.name != 'nt':
            endpoint = self.store.path.with_name('config.json.background.json')
            self.assertEqual(endpoint.stat().st_mode & 0o777,0o600)

    async def test_native_client_rejects_fake_server_before_sending_token(self):
        received = []
        finished = asyncio.Event()
        async def fake(reader, writer):
            try:
                received.append(await reader.readline())
                writer.write(json.dumps({'proof':'0' * 64}).encode() + b'\n')
                await writer.drain()
                received.append(await reader.read())
            finally:
                writer.close()
                finished.set()
        server = await asyncio.start_server(fake,'127.0.0.1',0)
        self.servers.append(server)
        self.store.save(Config())
        endpoint = self.store.path.with_name('config.json.background.json')
        endpoint.write_text(json.dumps({'port':server.sockets[0].getsockname()[1],'token':'a' * 64}))
        code, _, _ = await self.cli('status')
        self.assertNotEqual(code,0)
        await asyncio.wait_for(finished.wait(),3)
        self.assertEqual(set(json.loads(received[0])),{'nonce'})
        self.assertEqual(received[1],b'', 'Client must not send its bearer token to an unverified server')
        endpoint.unlink()

    async def test_activation_preserves_running_tunnel(self):
        server = await self.server()
        tunnel = self.tunnel(server)
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start', tunnel.id)
        state = await self.wait(tunnel)
        before = await self.request('snapshot')
        self.assertEqual(before['activation'], 0)
        with self.assertRaises(ValueError):
            await self.request('activate', 'invalid')
        await self.request('activate')
        await self.request('activate')
        after = await self.request('snapshot')
        self.assertEqual(after['activation'], 2)
        self.assertEqual(after['runtimes'][tunnel.id]['started_at'], state['started_at'])
        self.assertEqual(after['config'], before['config'])
        await self.exchange(tunnel.port)

    async def test_stale_settings_save_cannot_restart_stopped_tunnel(self):
        server = await self.server()
        tunnel = self.tunnel(server)
        await self.start(Config(tunnels=[tunnel]))
        await self.request('start',tunnel.id)
        await self.wait(tunnel)
        before = (await self.request('snapshot'))['config']
        candidate = json.loads(json.dumps(before))
        candidate['settings']['motion'] = False
        await self.request('stop',tunnel.id)
        with self.assertRaisesRegex(ValueError,'Конфигурация изменилась'):
            await self.request('save_checked',{'before':before,'config':candidate})
        self.assertFalse(self.store.load().tunnels[0].enabled)
        self.assertEqual((await self.request('snapshot'))['runtimes'][tunnel.id]['state'],'stopped')
        await self.assert_closed(tunnel.port)
        fresh = (await self.request('snapshot'))['config']
        candidate = json.loads(json.dumps(fresh))
        candidate['settings']['motion'] = False
        await self.request('save_checked',{'before':fresh,'config':candidate})
        self.assertFalse(self.store.load().settings.motion)
        self.assertFalse(self.store.load().tunnels[0].enabled)


if __name__ == '__main__':
    if not BINARY.is_file():
        raise SystemExit(f'Build Rust first: cargo build (missing {BINARY})')
    unittest.main()
