import asyncio
import unittest

# Constants for the JDWP handshake
JDWP_HANDSHAKE_REQUEST = b"JDWP-Handshake"
JDWP_HANDSHAKE_RESPONSE = b"JDWP-Handshake"

class MockJdwpServer:
    """A mock TCP server to simulate JDWP service responses."""

    def __init__(self, host, port, vulnerable=True):
        self.host = host
        self.port = port
        self.vulnerable = vulnerable
        self.server = None

    async def handle_client(self, reader, writer):
        """Handles incoming client connections."""
        addr = writer.get_extra_info('peername')
        print(f"Received connection from {addr}")

        try:
            data = await asyncio.wait_for(reader.read(100), timeout=2.0)
            message = data.decode()
            print(f"Received from client: {message!r}")

            if message == JDWP_HANDSHAKE_REQUEST.decode():
                if self.vulnerable:
                    print("Simulating vulnerable JDWP service.")
                    writer.write(JDWP_HANDSHAKE_RESPONSE)
                    await writer.drain()
                else:
                    print("Simulating non-vulnerable service (bad response).")
                    writer.write(b"NOT-JDWP")
                    await writer.drain()
            else:
                print("Client sent incorrect handshake.")
        except asyncio.TimeoutError:
            print("Timeout waiting for client data.")
        except ConnectionResetError:
            print("Client closed the connection unexpectedly.")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print("Closing client connection.")
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Starts the mock server."""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port)
        addr = self.server.sockets[0].getsockname()
        print(f'Mock JDWP server serving on {addr}')

    async def stop(self):
        """Stops the mock server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("Mock JDWP server stopped.")

class TestJdwpDetector(unittest.IsolatedAsyncioTestCase):
    """Unit tests for the JDWP detector logic (conceptually)."""

    async def asyncSetUp(self):
        self.loop = asyncio.get_event_loop()
        self.mock_server_vulnerable = None
        self.mock_server_non_vulnerable_wrong_response = None

    async def asyncTearDown(self):
        if self.mock_server_vulnerable:
            await self.mock_server_vulnerable.stop()
        if self.mock_server_non_vulnerable_wrong_response:
            await self.mock_server_non_vulnerable_wrong_response.stop()

    async def _test_jdwp_handshake(self, server_ip, server_port):
        """
        Helper function to test JDWP handshake.
        Returns True if JDWP handshake is successful, False otherwise.
        """
        try:
            reader, writer = await asyncio.open_connection(server_ip, server_port)
        except ConnectionRefusedError:
            print(f"Connection refused by server at {server_ip}:{server_port}")
            return False # Cannot perform handshake

        print(f"Test: Connecting to {server_ip}:{server_port}")
        writer.write(JDWP_HANDSHAKE_REQUEST)
        await writer.drain()
        print(f"Test: Sent '{JDWP_HANDSHAKE_REQUEST.decode()}'")

        response_data = b""
        try:
            response_data = await asyncio.wait_for(reader.read(len(JDWP_HANDSHAKE_RESPONSE) + 10), timeout=3.0)
            print(f"Test: Received '{response_data.decode()!r}'")
        except asyncio.TimeoutError:
            print("Test: Timeout waiting for response.")
        except ConnectionResetError:
            print("Test: Connection reset by server.")
        finally:
            writer.close()
            await writer.wait_closed()

        return response_data == JDWP_HANDSHAKE_RESPONSE

    async def test_vulnerable_service(self):
        """Tests detection against a vulnerable JDWP service."""
        host = "127.0.0.1"
        port = 12345
        self.mock_server_vulnerable = MockJdwpServer(host, port, vulnerable=True)
        await self.mock_server_vulnerable.start()

        print("Test Case: Vulnerable Service")
        is_vuln = await self._test_jdwp_handshake(host, port)
        self.assertTrue(is_vuln, "Detector failed to identify a vulnerable service.")
        print("Test Case: Vulnerable Service PASSED")

    async def test_non_vulnerable_service_wrong_response(self):
        """Tests detection against a non-vulnerable service (wrong response)."""
        host = "127.0.0.1"
        port = 12346
        self.mock_server_non_vulnerable_wrong_response = MockJdwpServer(host, port, vulnerable=False)
        await self.mock_server_non_vulnerable_wrong_response.start()

        print("Test Case: Non-Vulnerable Service (Wrong Response)")
        is_vuln = await self._test_jdwp_handshake(host, port)
        self.assertFalse(is_vuln, "Detector incorrectly identified a non-vulnerable service as vulnerable.")
        print("Test Case: Non-Vulnerable Service (Wrong Response) PASSED")

    async def test_non_vulnerable_service_no_response(self):
        """Tests detection against a service that does not respond as expected."""
        host = "127.0.0.1"
        port = 12347 # Unused port

        print("Test Case: Non-Vulnerable Service (No Response/Connection Refused)")
        is_vuln = await self._test_jdwp_handshake(host, port)
        self.assertFalse(is_vuln, "Detector incorrectly identified a non-responding service as vulnerable.")
        print("Test Case: Non-Vulnerable Service (No Response/Connection Refused) PASSED")

if __name__ == '__main__':
    unittest.main()
