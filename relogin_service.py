# SPDX-License-Identifier: AGPL-3.0-only
"""A self-hosted implementation of ranxi Sub2API's /api/v1/relogin contract."""
import argparse
from dataclasses import dataclass, field
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import queue
import re
import threading
from urllib.parse import urlsplit

import batch_login as batch
from mailbox_api import validate_url, MailboxError
from protocol_login import login, ProtocolError, NETWORK_FIELDS, make_session, network_details

STAGES = frozenset(('network_checking', 'network_verifying', 'identity_verified',
                    'authorize', 'email_submitted', 'password_submitted', 'totp_challenge',
                    'email_otp_waiting', 'email_otp_received', 'email_otp_resent',
                    'email_otp_rejected', 'workspace_selected', 'token_exchange', 'login_verified'))


@dataclass
class Config:
    proxy_url: str = field(repr=False)
    country_code: str = ''
    expected_exit_ip: str = ''
    mailboxes: dict = field(default_factory=dict, repr=False)
    account_proxies: dict = field(default_factory=dict, repr=False)
    ipv4_only: bool = False
    timeout: float = 600
    mail_timeout: float = 180
    workers: int = 3
    heartbeat: float = 15

    def validate(self):
        try:
            p = urlsplit(self.proxy_url)
            if (p.scheme not in ('http', 'https', 'socks5', 'socks5h') or not p.hostname or not p.port
                    or p.query or p.fragment or p.path not in ('', '/')):
                raise ValueError()
        except ValueError:
            raise ValueError('Configure a complete HTTP/HTTPS/SOCKS5 login proxy URL') from None
        if type(self.workers) is not int or not 1 <= self.workers <= 8:
            raise ValueError('workers must be in 1..8')
        if type(self.ipv4_only) is not bool:
            raise ValueError('ipv4_only must be a boolean')
        for value in (self.timeout, self.mail_timeout, self.heartbeat):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError('Timeout values must be positive finite numbers')
        if self.timeout > 1200 or self.mail_timeout > self.timeout or self.heartbeat > 30:
            raise ValueError('Timeout exceeds the supported relogin contract limits')
        if self.country_code and not re.fullmatch('[A-Z]{2}', self.country_code):
            raise ValueError('country_code must be an uppercase ISO country code')
        if self.expected_exit_ip:
            import ipaddress
            ipaddress.ip_address(self.expected_exit_ip)
        if not isinstance(self.mailboxes, dict):
            raise ValueError('mailboxes must map account emails to mailbox API URLs')
        self.mailboxes = {str(k).lower(): v for k, v in self.mailboxes.items()}
        for email, url in self.mailboxes.items():
            if not batch.EMAIL_RE.fullmatch(email) or not isinstance(url, str):
                raise ValueError('Invalid mailbox mapping')
            try:
                validate_url(url, email)
            except MailboxError:
                raise ValueError('Invalid mailbox API URL or recipient mismatch') from None
        if not isinstance(self.account_proxies, dict):
            raise ValueError('account_proxies must map account emails to fixed proxy routes')
        routes = {}
        for email, route in self.account_proxies.items():
            if (not isinstance(email, str) or not batch.EMAIL_RE.fullmatch(email)
                    or not isinstance(route, dict) or 'proxy_url' not in route
                    or set(route) - {'proxy_url', 'country_code', 'expected_exit_ip'}):
                raise ValueError('Invalid account proxy route')
            Config(**route).validate()
            normalized = email.lower()
            if normalized in routes:
                raise ValueError('Duplicate account proxy route')
            routes[normalized] = dict(route)
        self.account_proxies = routes
        return self


def parse_request(payload, config):
    if not isinstance(payload, dict) or payload.get('action') != 'start':
        raise ValueError('Unsupported relogin action')
    if payload.get('auth_mode') not in ('password_2fa', 'email_otp'):
        raise ValueError('Unsupported auth_mode')
    for key in ('email', 'password', 'mfa_secret', 'mail_url', 'otp_url'):
        if key in payload and (not isinstance(payload[key], str) or len(payload[key]) > 8192):
            raise ValueError('Invalid login fields')
    email = payload.get('email', '').strip().lower()
    password, secret = payload.get('password', ''), payload.get('mfa_secret', '')
    if len(email) > 320 or len(password) > 4096 or len(secret) > 4096:
        raise ValueError('Invalid login fields')
    explicit = [payload[k] for k in ('mail_url', 'otp_url') if payload.get(k)]
    if len(set(explicit)) > 1:
        raise ValueError('Conflicting mailbox API fields')
    mail_url = next(iter(explicit), '') or config.mailboxes.get(email, '')
    # Reuse account-line validation, but do not permit separator injection in HTTP fields.
    if any('----' in value or '\n' in value or '\r' in value for value in (email, password, secret, mail_url)):
        raise ValueError('Invalid login fields')
    source = '----'.join((email, password, secret, mail_url)) if mail_url else '----'.join((email, password, secret))
    try:
        entries = batch.parse_entries(source)
    except batch.ApiError:
        raise ValueError('Invalid account, TOTP secret, or mailbox API URL') from None
    return entries[0]


def make_server(address, config, api_key, login_fn=None):
    config.validate()
    if not isinstance(api_key, str) or len(api_key) < 24 or any(c.isspace() for c in api_key):
        raise ValueError('RELOGIN_API_KEY must contain at least 24 non-whitespace characters')
    engine = login_fn or login
    slots = threading.BoundedSemaphore(config.workers)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):
            # Do not log account inputs, URLs, headers, OTPs or credential responses.
            pass

        def json_response(self, status, payload):
            data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            self.wfile.write(data)

        def do_POST(self):
            self.connection.settimeout(30)
            if self.path != '/api/v1/relogin':
                return self.json_response(404, {'error': {'code': 'not_found'}})
            authorization = self.headers.get('Authorization', '')
            if not hmac.compare_digest(authorization.encode('utf-8'), ('Bearer ' + api_key).encode('utf-8')):
                return self.json_response(401, {'error': {'code': 'unauthorized'}})
            if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                return self.json_response(400, {'error': {'code': 'invalid_request'}})
            try:
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not lengths[0].isdecimal():
                    raise ValueError()
                length = int(lengths[0])
                if not 0 < length <= 65536:
                    raise ValueError()
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError()
                entry = parse_request(json.loads(body), config)
            except (ValueError, UnicodeError, OSError):
                return self.json_response(400, {'error': {'code': 'invalid_request'}})
            if not slots.acquire(blocking=False):
                return self.json_response(429, {'error': {'code': 'busy'}})
            stop = threading.Event()
            events = queue.Queue()

            def on_step(stage):
                if stage in STAGES and not stop.is_set():
                    events.put({'type': 'progress', 'payload': {'stage': stage}})

            def on_network(network):
                phase = network.get('phase')
                if phase in ('matched', 'verified') and not stop.is_set():
                    fields = {k: network[k] for k in NETWORK_FIELDS if isinstance(network.get(k), str)}
                    events.put({'type': 'progress', 'payload': {'stage': 'network_' + phase, **fields}})

            def run():
                try:
                    route = config.account_proxies.get(entry.email, {})
                    credential = engine(entry, route.get('proxy_url', config.proxy_url),
                                        country_code=route.get('country_code', config.country_code),
                                        expected_exit_ip=route.get('expected_exit_ip', config.expected_exit_ip), on_network=on_network,
                                        timeout=config.timeout, mail_timeout=config.mail_timeout,
                                        stop_event=stop, on_step=on_step, ipv4_only=config.ipv4_only)
                    batch.verify_login_identity(credential, entry.email)
                    if not all(isinstance(credential.get(k), str) and credential[k]
                               for k in ('access_token', 'refresh_token', 'id_token')):
                        raise ValueError('Incomplete credential')
                    # Same field accepted by ranxi readGuardResult + relogin().
                    events.put({'type': 'result', 'payload': {'status': 'success', 'credential': credential}})
                except Exception as error:
                    code = 'relogin_failed'
                    if isinstance(error, ProtocolError):
                        known = {'network', 'sentinel', 'sentinel_http', 'mailbox', 'phone_required',
                                 'security_check', 'manual_required', 'unsupported_state',
                                 'totp_secret_required', 'factor_binding_required', 'mailbox_required',
                                 'proxy_required', 'exit_detection_failed', 'exit_ip_mismatch',
                                 'exit_country_mismatch', 'unsupported_exit_country',
                                 'exit_timezone_invalid', 'exit_timezone_changed'}
                        if error.code in known:
                            code = error.code
                        if error.upstream_status == 429:
                            code = 'rate_limited'
                    events.put({'type': 'result', 'payload': {'status': 'failed', 'error': {'code': code}}})
                finally:
                    slots.release()

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-ndjson; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Accel-Buffering', 'no')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                while not stop.is_set():
                    try:
                        event = events.get(timeout=config.heartbeat)
                    except queue.Empty:
                        event = {'type': 'heartbeat'}
                    self.wfile.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')
                    self.wfile.flush()
                    if event['type'] == 'result':
                        break
            except (OSError, ValueError):
                pass
            finally:
                stop.set()
                worker.join(timeout=0.1)

        def do_GET(self):
            if self.path == '/health':
                return self.json_response(200, {'status': 'ok'})
            self.json_response(404, {'error': {'code': 'not_found'}})

    return ThreadingHTTPServer(address, Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True, help='Local JSON config; contains private mailbox URLs')
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--check-network', action='store_true',
                        help='Detect the configured proxy exit and show its matched profile; no account login')
    args = parser.parse_args()
    try:
        raw = json.loads(args.config.read_text(encoding='utf-8-sig'))
        config = Config(**raw).validate()
        if args.check_network:
            session, fingerprint = make_session(config.proxy_url, config.country_code,
                                                expected_exit_ip=config.expected_exit_ip)
            try:
                print(json.dumps(network_details(fingerprint, 'matched'), ensure_ascii=False))
            finally:
                session.close()
            return
        server = make_server((args.bind, args.port), config, os.getenv('RELOGIN_API_KEY', ''))
    except ProtocolError as error:
        parser.exit(2, str(error) + '\n')
    except (ValueError, TypeError, OSError):
        parser.exit(2, 'Invalid configuration or missing RELOGIN_API_KEY. See LOCAL_LOGIN_ZH.md.\n')
    print(f'Relogin service listening on {args.bind}:{server.server_port}; no login payloads are logged.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
