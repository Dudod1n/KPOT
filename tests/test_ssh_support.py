"""Checks for the independent integration-test fixtures and IPC boundary."""
import asyncio
from dataclasses import asdict
import hmac
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock

from ssh_support import Client, Config, Endpoint, SSHFixtures, Store, Tunnel, _metadata, _receive_line


class FixtureTests(unittest.TestCase):
    def test_configuration_round_trip_preserves_nested_endpoints(self):
        config = Config(tunnels=[Tunnel(
            name='test', server=Endpoint(host='127.0.0.1', user='test'),
            jumps=[Endpoint(host='127.0.0.2', user='jump')])])
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'config.json')
            store.save(config)
            self.assertEqual(json.loads(store.path.read_text())['version'], 1)
            self.assertEqual(asdict(store.load()), asdict(config))

    def test_invalid_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'endpoint.json'
            for data in ({'port': True, 'token': 'a' * 64},
                         {'port': 1234, 'token': 'invalid'},
                         {'port': 1234, 'token': 'a' * 64, 'extra': 1},
                         'x' * 4097):
                with self.subTest(data=data):
                    path.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        _metadata(path)

    def test_response_frames_require_newline_and_respect_size_limit(self):
        for chunks, expected in (([b'123', b'\n'], b'123\n'),
                                 ([b'12345'], None), ([b'123', b''], None)):
            with self.subTest(chunks=chunks):
                connection = Mock()
                connection.recv.side_effect = chunks
                if expected is None:
                    with self.assertRaises(ValueError):
                        _receive_line(connection, time.monotonic() + 1, 4)
                else:
                    self.assertEqual(_receive_line(connection, time.monotonic() + 1, 4), expected)


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, trusted, response):
        received = []
        finished = asyncio.Event()

        async def serve(reader, writer):
            try:
                nonce = json.loads(await reader.readline())
                received.append(nonce)
                proof = hmac.digest(b'a' * 64, nonce['nonce'].encode(), 'sha256').hex()
                writer.write(json.dumps({'proof': proof if trusted else '0' * 64}).encode() + b'\n')
                await writer.drain()
                raw = await reader.readline()
                if raw:
                    received.append(json.loads(raw))
                    writer.write(json.dumps(response).encode() + b'\n')
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                finished.set()

        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'config.json')
            async with await asyncio.start_server(serve, '127.0.0.1', 0) as server:
                store.path.with_name('config.json.background.json').write_text(json.dumps({
                    'port': server.sockets[0].getsockname()[1], 'token': 'a' * 64}))
                try:
                    result = await asyncio.to_thread(Client(store.path).request, 'snapshot')
                except ValueError as error:
                    result = error
                await asyncio.wait_for(finished.wait(), 3)
        return result, received

    async def test_unverified_server_never_receives_token(self):
        result, received = await self.exchange(False, None)
        self.assertIsInstance(result, ValueError)
        self.assertEqual(len(received), 1)
        self.assertEqual(set(received[0]), {'nonce'})

    async def test_authenticated_response_and_errors(self):
        for response, expected in (({'ok': True, 'value': {'version': 1}}, {'version': 1}),
                                   ({'ok': False, 'error': 'rejected'}, ValueError),
                                   ({'ok': True, 'value': None, 'extra': 1}, ValueError)):
            with self.subTest(response=response):
                result, received = await self.exchange(True, response)
                self.assertEqual(received[1], {'token': 'a' * 64, 'command': 'snapshot', 'payload': None})
                if expected is ValueError:
                    self.assertIsInstance(result, ValueError)
                else:
                    self.assertEqual(result, expected)


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    assert_closed = SSHFixtures.assert_closed

    async def close_connection(self, reader, writer):
        self.connected.set()
        writer.close()
        await writer.wait_closed()

    async def test_listener_close_can_finish_after_the_first_probe(self):
        self.connected = asyncio.Event()
        server = await asyncio.start_server(self.close_connection, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]

        async def stop_after_probe():
            await self.connected.wait()
            server.close()
            await server.wait_closed()

        stopping = asyncio.create_task(stop_after_probe())
        try:
            await self.assert_closed(port)
            await stopping
        finally:
            server.close()
            await server.wait_closed()
            stopping.cancel()
            await asyncio.gather(stopping, return_exceptions=True)

    async def test_persistent_listener_is_rejected(self):
        self.connected = asyncio.Event()
        async with await asyncio.start_server(self.close_connection, '127.0.0.1', 0) as server:
            with self.assertRaisesRegex(AssertionError, 'still open'):
                await self.assert_closed(server.sockets[0].getsockname()[1])


if __name__ == '__main__':
    unittest.main()
