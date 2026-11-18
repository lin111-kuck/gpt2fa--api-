"""Loopback HTTP CONNECT bridge for authenticated upstream proxies.

The optional HTTP gateway transports the connection to the upstream proxy;
it never replaces the selected account's exit proxy.
"""
import ipaddress
import json
import select
import socket
import socketserver
import ssl
import threading
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener
import base64


class RouteError(RuntimeError):
    pass


def gateway_address(url):
    if not url:
        return None
    p = urlsplit(url)
    if (p.scheme != 'http' or p.hostname not in ('127.0.0.1', 'localhost', '::1')
            or not p.port or p.username or p.password or p.path not in ('', '/')
            or p.query or p.fragment):
        raise ValueError('Gateway must be a loopback HTTP proxy, e.g. http://127.0.0.1:7890')
    return p.hostname, p.port


def locally_routable(proxy):
    host = str(proxy.get('host') or '')
    if proxy.get('protocol') not in ('http', 'https', 'socks5') or not host:
        return False
    if type(proxy.get('port')) is not int or not 1 <= proxy['port'] <= 65535:
        return False
    try:
        return ipaddress.ip_address(host.strip('[]')).is_global
    except ValueError:
        return host.lower() != 'localhost' and not host.lower().endswith(('.local', '.internal'))


def receive(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RouteError('Proxy closed the connection')
        data += chunk
    return data


def read_headers(sock):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        if len(data) >= 16384:
            raise RouteError('Oversized proxy response')
        data.extend(receive(sock, 1))
    return bytes(data)


def http_connect(sock, target, authorization=None):
    header = f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n'
    if authorization:
        header += 'Proxy-Authorization: Basic ' + authorization + '\r\n'
    sock.sendall((header + '\r\n').encode('ascii'))
    first = read_headers(sock).split(b'\r\n', 1)[0].split()
    if len(first) < 2 or first[1] != b'200':
        code = first[1].decode('ascii', 'replace') if len(first) >= 2 else 'invalid'
        raise RouteError('Proxy CONNECT rejected: ' + code)


def open_tunnel(proxy, host, port, gateway=None, timeout=15):
    sock = None
    try:
        endpoint = (proxy['host'], proxy['port'])
        sock = socket.create_connection(gateway or endpoint, timeout=timeout)
        sock.settimeout(timeout)
        if gateway:
            http_connect(sock, f'{endpoint[0]}:{endpoint[1]}')
        scheme = proxy['protocol']
        if scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=proxy['host'])
        if scheme in ('http', 'https'):
            auth = None
            if proxy.get('username') or proxy.get('password'):
                auth = base64.b64encode((str(proxy.get('username') or '') + ':' + str(proxy.get('password') or '')).encode()).decode()
            authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            http_connect(sock, authority, auth)
        elif scheme == 'socks5':
            user = str(proxy.get('username') or '').encode()
            password = str(proxy.get('password') or '').encode()
            methods = b'\x02' if user or password else b'\x00'
            sock.sendall(b'\x05' + bytes([len(methods)]) + methods)
            version, method = receive(sock, 2)
            if version != 5 or method not in methods:
                raise RouteError('SOCKS5 authentication method rejected')
            if method == 2:
                if len(user) > 255 or len(password) > 255:
                    raise RouteError('SOCKS5 credentials exceed protocol limit')
                sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                if receive(sock, 2) != b'\x01\x00':
                    raise RouteError('SOCKS5 authentication rejected')
            name = host.encode('idna')
            if len(name) > 255:
                raise RouteError('SOCKS5 target hostname too long')
            sock.sendall(bytes([5, 1, 0, 3, len(name)]) + name + port.to_bytes(2, 'big'))
            version, reply, reserved, kind = receive(sock, 4)
            if version != 5 or reply != 0 or reserved != 0:
                raise RouteError('SOCKS5 target connection rejected')
            length = {1: 4, 4: 16}.get(kind)
            if kind == 3:
                length = receive(sock, 1)[0]
            if length is None:
                raise RouteError('Invalid SOCKS5 response address')
            receive(sock, length + 2)
        else:
            raise RouteError('Unsupported upstream protocol')
        return sock
    except Exception:
        if sock:
            sock.close()
        raise


class ProxyBridge:
    def __init__(self, proxy, gateway=None, *, force_ipv4=False):
        self.proxy = dict(proxy)
        self.gateway = gateway_address(gateway)
        self.force_ipv4 = force_ipv4
        self.errors = []
        self.stopping = threading.Event()

    def __enter__(self):
        bridge = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = None
                established = False
                try:
                    self.request.settimeout(20)
                    line = read_headers(self.request).split(b'\r\n', 1)[0].decode('ascii')
                    method, authority, version = line.split()
                    target = urlsplit('//' + authority)
                    if method != 'CONNECT' or not target.hostname or target.port != 443 or target.username or target.password:
                        raise RouteError('Only HTTPS CONNECT on port 443 is allowed')
                    host = target.hostname
                    if bridge.force_ipv4:
                        addresses = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
                        if not addresses:
                            raise RouteError('HTTPS target has no IPv4 address')
                        host = addresses[0][4][0]
                    upstream = open_tunnel(bridge.proxy, host, 443, bridge.gateway)
                    self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    established = True
                    while not bridge.stopping.is_set():
                        ready, _, _ = select.select([self.request, upstream], [], [], 1)
                        for source in ready:
                            chunk = source.recv(65536)
                            if not chunk:
                                return
                            (upstream if source is self.request else self.request).sendall(chunk)
                except Exception as exc:
                    bridge.errors.append(type(exc).__name__)
                    if not established:
                        try:
                            self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                        except OSError:
                            pass
                finally:
                    if upstream:
                        upstream.close()
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = False
        self.server = Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.profile = dict(protocol='http', host='127.0.0.1', port=self.server.server_address[1])
        return self

    def verify_exit(self, expected_ip):
        address = 'http://127.0.0.1:' + str(self.profile['port'])
        opener = build_opener(ProxyHandler({'https': address, 'http': address}))
        try:
            with opener.open('https://ipwho.is/', timeout=25) as response:
                data = json.load(response)
        except Exception as exc:
            raise RouteError('Local proxy exit verification failed: ' + type(exc).__name__) from None
        if data.get('success') is not True or data.get('ip') != expected_ip:
            raise RouteError('Local proxy exit differs from backend selected exit or cannot be verified')
        return {key: data.get(key) for key in ('ip', 'country', 'country_code', 'region', 'city')}

    def __exit__(self, *args):
        self.stopping.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
