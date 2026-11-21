"""Checks for the port-closure probe that the integration tests rely on.

A probe that passes too early would let a leaked listener go unnoticed.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

import ssh_support
from ssh_support import SSHFixtures


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

    async def test_slow_refusal_does_not_count_against_the_deadline(self):
        async def connect(host, port):
            calls.append(port)
            if len(calls) == 1:
                return Mock(), Mock(wait_closed=AsyncMock())
            await asyncio.sleep(.2)
            raise ConnectionRefusedError
        calls = []
        with (patch.object(ssh_support, 'CLOSE_TIMEOUT', .1),
              patch.object(ssh_support.asyncio, 'open_connection', connect)):
            await self.assert_closed(1)
        self.assertEqual(len(calls), 2)

    async def test_unanswered_probe_is_rejected(self):
        async def connect(host, port):
            await asyncio.sleep(10)
        with (patch.object(ssh_support, 'PROBE_TIMEOUT', .05),
              patch.object(ssh_support.asyncio, 'open_connection', connect),
              self.assertRaisesRegex(AssertionError, 'timed out')):
            await self.assert_closed(1)


if __name__ == '__main__':
    unittest.main()
