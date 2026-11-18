import io
import json
import socket
import socketserver
import threading
import unittest
from unittest.mock import patch

import oauth_proxy_transport as t


class TransportTests(unittest.TestCase):
    def test_reject_private_endpoints_without_losing_public_socks_support(self):
        for host in ('172.19.0.1', '127.0.0.1', '10.0.0.1', '::1', 'localhost'):
            self.assertFalse(t.locally_routable(dict(protocol='http', host=host, port=80)))
        self.assertTrue(t.locally_routable(dict(protocol='socks5', host='8.8.8.8', port=1187, username='u', password='p')))

    def test_gateway_only_accepts_explicit_loopback_proxy(self):
        self.assertEqual(t.gateway_address('http://127.0.0.1:7890'), ('127.0.0.1', 7890))
        for value in ('http://8.8.8.8:80', 'http://u:p@localhost:80', 'https://localhost:80', 'http://localhost:80/other'):
            with self.assertRaises(ValueError):
                t.gateway_address(value)

    def test_socks_authentication_and_bridge_relay(self):
        observed = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                s = self.request
                s.settimeout(3)
                observed.append(t.receive(s, 3))
                s.sendall(bytes([5, 2]))
                version, length = t.receive(s, 2)
                user = t.receive(s, length)
                password = t.receive(s, t.receive(s, 1)[0])
                observed.append((version, user, password))
                s.sendall(bytes([1, 0]))
                header = t.receive(s, 5)
                host = t.receive(s, header[4])
                port = int.from_bytes(t.receive(s, 2), 'big')
                observed.append((host, port))
                s.sendall(bytes([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]))
                observed.append(t.receive(s, 4))
                s.sendall(b'pong')
        with socketserver.TCPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            proxy = dict(protocol='socks5', host='127.0.0.1', port=server.server_address[1], username='test-user', password='test-pass')
            try:
                with t.ProxyBridge(proxy) as bridge:
                    with socket.create_connection(('127.0.0.1', bridge.profile['port']), timeout=3) as client:
                        client.settimeout(3)
                        t.http_connect(client, 'auth.openai.com:443')
                        client.sendall(b'ping')
                        self.assertEqual(t.receive(client, 4), b'pong')
            finally:
                server.shutdown()
                thread.join(2)
        self.assertEqual(observed[0], bytes([5, 1, 2]))
        self.assertEqual(observed[1], (1, b'test-user', b'test-pass'))
        self.assertEqual(observed[2], (b'auth.openai.com', 443))
        self.assertEqual(observed[3], b'ping')

    def test_bridge_rejects_non_https_targets(self):
        with t.ProxyBridge(dict(protocol='http', host='unused.invalid', port=8080)) as bridge:
            with socket.create_connection(('127.0.0.1', bridge.profile['port']), timeout=3) as client:
                with self.assertRaises(t.RouteError):
                    t.http_connect(client, 'example.com:80')

    def test_ipv4_bridge_resolves_connect_target_and_relays_original_tls_bytes(self):
        upstream, remote = socket.socketpair()
        try:
            with t.ProxyBridge(dict(protocol='http', host='unused.invalid', port=8080), force_ipv4=True) as bridge:
                with socket.create_connection(('127.0.0.1', bridge.profile['port']), timeout=3) as client:
                    with patch.object(t.socket, 'getaddrinfo', return_value=[
                            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('198.51.100.7', 443))]) as resolve, \
                         patch.object(t, 'open_tunnel', return_value=upstream) as tunnel:
                        t.http_connect(client, 'auth.openai.com:443')
                        resolve.assert_called_once_with('auth.openai.com', 443, socket.AF_INET, socket.SOCK_STREAM)
                        self.assertEqual(tunnel.call_args.args[1:3], ('198.51.100.7', 443))
                        client.sendall(b'client-tls-bytes')
                        self.assertEqual(t.receive(remote, 16), b'client-tls-bytes')
                        remote.sendall(b'server-tls-bytes')
                        self.assertEqual(t.receive(client, 16), b'server-tls-bytes')
        finally:
            upstream.close()
            remote.close()

    def test_exit_verification_fails_closed_on_ip_mismatch_or_unknown(self):
        bridge = t.ProxyBridge({})
        bridge.profile = dict(port=12345)
        for data in ({'success':True, 'ip':'1.2.3.4'}, {'ip':'8.8.8.8'}):
            with patch.object(t, 'build_opener') as build:
                build.return_value.open.return_value = io.BytesIO(json.dumps(data).encode())
                with self.assertRaises(t.RouteError):
                    bridge.verify_exit('8.8.8.8')

    def test_rejects_truncated_socks_reply(self):
        left, right = socket.socketpair()
        try:
            right.sendall(bytes([5]))
            right.close()
            with self.assertRaises(t.RouteError):
                t.receive(left, 2)
        finally:
            left.close()
            right.close()


if __name__ == '__main__':
    unittest.main()
