"""Independent loopback SSH server, JSON fixtures and authenticated test IPC.

Configuration objects only describe test input; the Rust executable validates it.
"""
import asyncio
from dataclasses import asdict, dataclass, field
import hmac
import json
from pathlib import Path
import re
import secrets
import socket
import time
from uuid import uuid4

import asyncssh

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
AUTH_TIMEOUT = 2.0
REQUEST_TIMEOUT = 15.0


@dataclass
class Endpoint:
    host: str = ''
    port: int = 22
    user: str = ''
    auth: str = 'agent'
    key: str = '~/.ssh/id_ed25519'


@dataclass
class Tunnel:
    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = ''
    kind: str = 'L'
    server: Endpoint = field(default_factory=Endpoint)
    bind: str = '127.0.0.1'
    port: int = 8080
    target: str = ''
    target_port: int = 80
    reconnect: bool = True
    jumps_enabled: bool = False
    jumps: list[Endpoint] = field(default_factory=list)
    enabled: bool = False


@dataclass
class Settings:
    theme: str = 'dark'
    motion: bool = True
    splash: bool = True


@dataclass
class Config:
    tunnels: list[Tunnel] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)


class Store:
    def __init__(self, path):
        self.path = Path(path).resolve()

    @property
    def known_hosts_path(self):
        return self.path.with_name(self.path.name + '.known_hosts.json')

    def save(self, config):
        self.path.write_text(json.dumps({'version': 1, **asdict(config)},
                                        ensure_ascii=False, allow_nan=False), encoding='utf-8')

    def load(self):
        data = json.loads(self.path.read_text(encoding='utf-8'))
        tunnels = []
        for item in data['tunnels']:
            item['server'] = Endpoint(**item['server'])
            item['jumps'] = [Endpoint(**hop) for hop in item['jumps']]
            tunnels.append(Tunnel(**item))
        return Config(tunnels=tunnels, settings=Settings(**data['settings']))


def endpoint_path(path: Path) -> Path:
    return Path(path).with_name(Path(path).name + '.background.json')


def _json(raw: bytes):
    def invalid_constant(value):
        raise ValueError('Недопустимое число JSON.')
    return json.loads(raw.decode('utf-8'), parse_constant=invalid_constant)


def _metadata(path: Path) -> dict:
    with path.open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('Некорректный адрес фонового процесса.')
    data = _json(raw)
    if (not isinstance(data, dict) or set(data) != {'port', 'token'}
            or type(data['port']) is not int or not 1 <= data['port'] <= 65535
            or not isinstance(data['token'], str)
            or re.fullmatch('[0-9a-f]{64}', data['token']) is None):
        raise ValueError('Некорректный адрес фонового процесса.')
    return data


def _receive_line(connection: socket.socket, deadline: float, max_bytes: int) -> bytes:
    raw = bytearray()
    while len(raw) <= max_bytes and b'\n' not in raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        chunk = connection.recv(min(65536, max_bytes + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > max_bytes or not raw.endswith(b'\n'):
        raise ValueError('Некорректный ответ фонового процесса.')
    return bytes(raw)


class Client:
    def __init__(self, path: Path):
        self.path = Path(path).expanduser().resolve()

    def request(self, command: str, payload=None):
        return self._request(command, payload, REQUEST_TIMEOUT)

    def _request(self, command: str, payload=None, timeout=REQUEST_TIMEOUT):
        try:
            if not isinstance(command, str):
                raise ValueError('Некорректная команда.')
            metadata = _metadata(endpoint_path(self.path))
            request = json.dumps({'token': metadata['token'], 'command': command, 'payload': payload},
                                 ensure_ascii=False, allow_nan=False).encode('utf-8') + b'\n'
            if len(request) > MAX_MESSAGE_BYTES:
                raise ValueError('Запрос превышает допустимый размер.')
            deadline = time.monotonic() + timeout
            auth_deadline = min(deadline, time.monotonic() + AUTH_TIMEOUT)
            with socket.create_connection(('127.0.0.1', metadata['port']),
                                          timeout=min(timeout, AUTH_TIMEOUT)) as connection:
                nonce = secrets.token_hex(32)
                connection.settimeout(max(.001, auth_deadline - time.monotonic()))
                connection.sendall(json.dumps({'nonce': nonce}).encode('ascii') + b'\n')
                proof = _json(_receive_line(connection, auth_deadline, 4096))
                expected = hmac.digest(metadata['token'].encode('ascii'), nonce.encode('ascii'), 'sha256').hex()
                if (not isinstance(proof, dict) or set(proof) != {'proof'}
                        or not isinstance(proof['proof'], str)
                        or re.fullmatch('[0-9a-f]{64}', proof['proof']) is None
                        or not hmac.compare_digest(proof['proof'], expected)):
                    raise ValueError('Не удалось подтвердить фоновый процесс КРОТ.')
                connection.settimeout(max(.001, deadline - time.monotonic()))
                connection.sendall(request)
                raw = _receive_line(connection, deadline, MAX_MESSAGE_BYTES)
            response = _json(raw)
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
            raise ValueError('Не удалось связаться с фоновым процессом КРОТ.') from exc
        if not isinstance(response, dict) or type(response.get('ok')) is not bool:
            raise ValueError('Некорректный ответ фонового процесса.')
        if response['ok'] is True and set(response) == {'ok', 'value'}:
            return response['value']
        if (response['ok'] is False and set(response) == {'ok', 'error'}
                and isinstance(response['error'], str) and len(response['error']) <= 4096):
            raise ValueError(response['error'])
        raise ValueError('Некорректный ответ фонового процесса.')


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Server(asyncssh.SSHServer):
    def __init__(self, owner, password, client_key):
        self.owner, self.password, self.client_key = owner, password, client_key

    def connection_made(self, conn):
        self.conn = conn
        self.owner.connections.add(conn)

    def connection_lost(self, exc):
        self.owner.connections.discard(self.conn)

    def begin_auth(self, username):
        return self.password is not None or self.client_key is not None

    def password_auth_supported(self):
        return self.password is not None

    def validate_password(self, username, password):
        self.owner.auths.append((username, password))
        return password == self.password

    def public_key_auth_supported(self):
        return self.client_key is not None

    def validate_public_key(self, username, key):
        return key == self.client_key

    def connection_requested(self, host, port, orig_host, orig_port):
        self.owner.forwarded.append(port)
        return True

    def server_requested(self, host, port):
        return True


class SSHFixtures:
    async def echo_bytes(self, reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def server(self, *, port=0, key=None, password=None, client_key=None):
        server = await asyncssh.listen(
            '127.0.0.1', port, config=None,
            server_factory=lambda: Server(self, password, client_key),
            server_host_keys=[key or asyncssh.generate_private_key('ssh-ed25519')],
        )
        self.servers.append(server)
        return server

    def tunnel(self, server, **kw):
        return Tunnel(name='test', server=Endpoint(host='127.0.0.1', port=server.get_port(), user='test'),
                      port=unused_port(), target='127.0.0.1', target_port=self.echo_port,
                      reconnect=False, **kw)

    async def exchange(self, port, *, socks=False):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        try:
            if socks:
                writer.write(b'\x05\x01\x00')
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b'\x05\x00')
                writer.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + self.echo_port.to_bytes(2, 'big'))
                await writer.drain()
                answer = await reader.readexactly(10)
                self.assertEqual(answer[:2], b'\x05\x00')
            payload = b'KROT actual forwarding\x00\xff' * 100
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 3), payload)
        finally:
            writer.close()
            await writer.wait_closed()

    async def assert_closed(self, port):
        try:
            _, writer = await asyncio.open_connection('127.0.0.1', port)
        except OSError:
            return
        writer.close()
        await writer.wait_closed()
        self.fail(f'Listener on port {port} is still open')
