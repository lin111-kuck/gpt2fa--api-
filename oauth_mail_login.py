#!/usr/bin/env python3
"""Browser OAuth with fresh mailbox OTP, TOTP, proxy checks and JSON export."""
import argparse
import base64
import getpass
import hashlib
import hmac
import html
import json
import math
import os
import re
import struct
import sys
import time
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass, field
from contextlib import ExitStack, nullcontext
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import batch_login as batch
from oauth_proxy_transport import ProxyBridge, RouteError, gateway_address, locally_routable
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parent
OAUTH = '/api/v1/admin/openai'


class BrowserNetworkError(batch.ApiError):
    """Stop the batch when the local browser cannot reach the proxy route."""


class ManualActionRequired(batch.ApiError):
    """The login requires the account owner's intervention."""


class SecurityVerificationSkipped(ManualActionRequired):
    pass


class PhoneVerificationRequired(ManualActionRequired):
    pass


def human_verification(body):
    return bool(re.search(r'verify you are human|just a moment|checking your browser|cf-chl-|确认您是真人|验证您是人类|完成人机验证|正在进行安全验证|验证成功[，,、\s]*正在等待', body, re.I))


def verification_requires_action(body):
    return bool(re.search(r'verify you are human by|complete the (?:security check|captcha)|请(?:点击|勾选)|请完成(?:人机|安全)验证|点击.*验证.*真人', body, re.I))


def page_diagnostic(page):
    return dict(path=urlsplit(page.url).path,
                headings=page.locator('h1,h2,[role=alert]').all_inner_texts()[:8],
                buttons=page.get_by_role('button').all_inner_texts()[:12])


def wait_security_check(page, timeout, on_step, on_diagnostic):
    started = time.monotonic()
    next_progress = started
    clear_count = 0
    on_step('security_check_wait_started')
    while time.monotonic() - started < timeout:
        try:
            body = page.locator('body').inner_text(timeout=5000)
        except Exception:
            if page.is_closed():
                raise batch.ApiError('OAuth browser tab was closed')
            page.wait_for_timeout(500)
            continue
        if body.strip() and not human_verification(body):
            clear_count += 1
            if clear_count >= 3:
                on_step('security_check_completed')
                return
            page.wait_for_timeout(1000)
            continue
        clear_count = 0
        if verification_requires_action(body):
            on_diagnostic(page_diagnostic(page))
            manual_pause('页面明确要求人工完成安全验证；请在当前浏览器完成后返回终端继续。')
        now = time.monotonic()
        if now >= next_progress:
            on_step('security_check_wait_' + str(int(now - started)) + 's')
            next_progress = now + 30
        page.wait_for_timeout(1000)
    on_diagnostic(page_diagnostic(page))
    raise ManualActionRequired('Automatic security check did not complete within ' + str(int(timeout)) + ' seconds; browser intervention is required')


def clean_page_diagnostic(client, data):
    result = dict(path=str(data.get('path', '')).split('?', 1)[0],
                  headings=[client.clean(str(x))[:160] for x in data.get('headings', [])[:8]],
                  buttons=[client.clean(str(x))[:80] for x in data.get('buttons', [])[:12]])
    for key in ('network_event', 'method', 'resource_type', 'error_code'):
        if key in data:
            result[key] = client.clean(str(data[key]))[:80]
    if isinstance(data.get('http_status'), int):
        result['http_status'] = data['http_status']
    for key in ('redirect_from', 'redirect_to'):
        if key in data:
            result[key] = client.clean(urlsplit(str(data[key])).path)[:160]
    if data.get('cf_challenge') is True:
        result['cf_challenge'] = True
    return result


def login_navigation(page, url):
    try:
        response = page.goto(url, wait_until='domcontentloaded', timeout=60000)
        if response is not None and isinstance(response.status, int) and response.status >= 400:
            reason = ''
            try:
                headers = response.headers
                body = response.text().lower()
                if headers.get('cf-mitigated') == 'challenge' or human_verification(body):
                    reason = '; human verification required'
                elif any(x in body for x in ('unsupported_country', 'country_not_supported', 'unsupported region')):
                    reason = '; region is not supported'
                elif any(x in body for x in ('invalid_request', 'invalid_client', 'invalid_scope', 'invalid code_challenge')):
                    reason = '; OAuth authorization parameters rejected'
            except Exception:
                pass
            if 'human verification' not in reason:
                raise batch.ApiError('OAuth login page returned HTTP ' + str(response.status) + reason)
            # A challenge response can complete in the browser; let the normal page loop wait.

        return response
    except Exception as exc:
        codes = sorted(set(re.findall(r'(?:net::)?ERR_[A-Z_]+', str(exc))))
        if codes or type(exc).__name__ == 'TimeoutError':
            raise BrowserNetworkError('Local browser cannot reach OAuth through selected proxy: ' + ', '.join(codes or ['navigation timeout'])) from None
        raise


@dataclass
class Account:
    email: str
    password: str = field(repr=False)
    mfa_secret: str = field(repr=False)
    mail_url: str = field(default='', repr=False)


def load_accounts(text):
    entries = batch.parse_entries(text)
    accounts = []
    for entry in entries:
        mail_url = entry.mail_url
        if mail_url:
            p = urlsplit(mail_url)
            recipient = parse_qs(p.query).get('e', [''])[0].split(':', 1)[0].lower()
            if (p.scheme != 'https' or p.hostname != 'api.wdmail.top' or p.port not in (None, 443)
                    or p.username or p.password or recipient != entry.email):
                raise batch.ApiError('Mailbox URL must belong to this email on https://api.wdmail.top')
        accounts.append(Account(entry.email, entry.password, entry.mfa_secret, mail_url))
    return accounts


class PlainHTML(HTMLParser):
    def __init__(self, depth=0):
        super().__init__(convert_charrefs=True)
        self.depth, self.hidden, self.parts = depth, 0, []

    def handle_starttag(self, tag, attrs):
        if tag in ('style', 'script'):
            self.hidden += 1
        if tag == 'iframe' and self.depth < 4:
            srcdoc = dict(attrs).get('srcdoc')
            if srcdoc:
                self.parts.append(visible_text(srcdoc, self.depth + 1))
        if tag in ('div', 'p', 'br', 'h1', 'h2', 'h3', 'article', 'section', 'td', 'time'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('style', 'script'):
            self.hidden = max(0, self.hidden - 1)
        if tag in ('div', 'p', 'h1', 'h2', 'h3', 'article', 'section', 'td', 'time'):
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def visible_text(source, depth=0):
    parser = PlainHTML(depth)
    parser.feed(source)
    return ''.join(parser.parts)


@dataclass
class MailCode:
    received: datetime
    code: str = field(repr=False)
    fingerprint: str = ''


def mailbox_codes(source, email):
    text = visible_text(source)
    chunks = re.split(r'(?=发件人\s*[:：]|From\s*:)', text, flags=re.I)
    found = {}
    for chunk in chunks:
        recipient = re.search(r'(?:邮箱|收件人|To)\s*[:：]\s*([^\s<>]+@[^\s<>]+)', chunk, re.I)
        if not recipient or recipient.group(1).lower().rstrip('，,;；') != email.lower():
            continue
        if not re.search(r'OpenAI|ChatGPT', chunk, re.I):
            continue
        stamp = re.search(r'(?:时间|Date)\s*[:：]\s*(\d{4}-\d\d-\d\d[ T]\d\d:\d\d(?::\d\d(?:\.\d+)?)?(?:[+-]\d\d:\d\d|Z)?)', chunk, re.I)
        if not stamp:
            continue
        try:
            received = datetime.fromisoformat(stamp.group(1).replace('Z', '+00:00'))
        except ValueError:
            continue
        if received.tzinfo is None:
            received = received.replace(tzinfo=batch.SHANGHAI)
        # Ignore HTML/CSS/URLs and date numbers: only standalone code lines qualify.
        codes = set(re.findall(r'(?m)^\s*(\d{6})\s*$', chunk))
        if len(codes) != 1 or not re.search(r'验证码|verification\s+code|temporary\s+code', chunk, re.I):
            continue
        code = codes.pop()
        identity = email.lower() + '|' + received.isoformat() + '|' + code
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        found[fingerprint] = MailCode(received, code, fingerprint)
    return list(found.values())


def fresh_mail_code(messages, baseline, started_at):
    fresh = [m for m in messages if m.fingerprint not in baseline
             and started_at.timestamp() - 90 <= m.received.timestamp() <= time.time() + 120]
    if not fresh:
        return None
    latest = max(m.received for m in fresh)
    candidates = {m.code for m in fresh if m.received == latest}
    return candidates.pop() if len(candidates) == 1 else None


def totp(secret, timestamp=None):
    raw = base64.b32decode(secret.upper() + '=' * ((-len(secret)) % 8))
    digest = hmac.new(raw, struct.pack('>Q', int(time.time() if timestamp is None else timestamp) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def permitted_location(location):
    country = str(location.get('country') or '').strip().casefold()
    if not country or country in ('unknown', 'none', 'xx', 'n/a', 'hk', 'hkg', 'tw', 'twn'):
        return False
    text = ' '.join(str(location.get(k) or '') for k in ('country', 'region', 'city')).casefold().replace(' ', '')
    return not any(s in text for s in ('hongkong', 'taiwan', '香港', '台湾', '台灣'))


def browser_proxy(proxy):
    scheme = str(proxy.get('protocol') or '').lower()
    if scheme not in ('http', 'https', 'socks5'):
        raise batch.ApiError('Unsupported browser proxy protocol')
    if scheme == 'socks5' and (proxy.get('username') or proxy.get('password')):
        raise batch.ApiError('Authenticated SOCKS5 is unsupported by Chromium; select HTTP/HTTPS')
    host = str(proxy.get('host') or '')
    port = proxy.get('port')
    if not host or type(port) is not int or not 1 <= port <= 65535:
        raise batch.ApiError('Proxy connection host/port is missing')
    if ':' in host and not host.startswith('['):
        host = '[' + host + ']'
    config = dict(server=f'{scheme}://{host}:{port}')
    for key in ('username', 'password'):
        if proxy.get(key):
            config[key] = str(proxy[key])
    return config


class RegionClient(batch.SafeClient):
    """Keep every proxy's occupancy while excluding unsuitable browser routes."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.catalog, self.verified_locations, self.last_tests = {}, {}, {}

    def list_proxies(self, page_size):
        proxies = super().list_proxies(page_size)
        self.catalog = {p['id']: dict(p) for p in proxies}
        result = []
        for p in proxies:
            copy = dict(p)
            if not locally_routable(p):
                copy['status'] = 'inactive'
            if p.get('country') and not permitted_location(p):
                copy['status'] = 'inactive'
            result.append(copy)
        return result

    def request(self, method, path, body=None, **kwargs):
        result = super().request(method, path, body, **kwargs)
        if (method == 'POST' and path.startswith('/api/v1/admin/proxies/') and path.endswith('/test')
                and isinstance(result, dict) and result.get('success') is True):
            pid = int(path.split('/')[-2])
            ip = batch.normalize_ip(result.get('ip_address'))
            old = self.catalog.get(pid, {})
            location = result if result.get('country') else self.verified_locations.get(ip, {})
            if not location and ip == batch.normalize_ip(old.get('ip_address')):
                location = old
            if not ip or not permitted_location(location):
                return dict(success=False, message='Exit country excluded or unverified')
            self.verified_locations[ip] = {k: location.get(k) for k in ('country', 'region', 'city')}
            self.last_tests[pid] = dict(result, **self.verified_locations[ip])
        return result


def recheck_same_proxy(client, chosen, max_per_ip, allow_full=False):
    proxies = client.list_proxies(100)
    selected = next((p for p in proxies if p['id'] == chosen['proxy_id']), None)
    if not selected or not batch.active(selected):
        raise batch.ApiError('Selected proxy is no longer available')
    test = client.request('POST', f"/api/v1/admin/proxies/{selected['id']}/test")
    if not isinstance(test, dict) or test.get('success') is not True:
        raise batch.ApiError('Selected proxy connectivity/country check failed')
    ip = batch.normalize_ip(test.get('ip_address'))
    if ip != chosen['exit_ip']:
        raise batch.ApiError('Proxy exit IP changed during OAuth; account was not imported')
    selected['ip_address'] = ip
    used = batch.occupancy(proxies, selected, ip)
    if used is None or used > max_per_ip or (used == max_per_ip and not allow_full):
        raise batch.ApiError('Exit IP has no free account capacity')
    return used


def oauth_session(client, proxy_id):
    data = client.request('POST', OAUTH + '/generate-auth-url', dict(proxy_id=proxy_id))
    if not isinstance(data, dict) or not data.get('session_id'):
        raise batch.ApiError('OAuth session response has no session_id')
    auth_url = data.get('auth_url', '')
    p = urlsplit(auth_url)
    q = parse_qs(p.query)
    if p.scheme != 'https' or p.hostname != 'auth.openai.com':
        raise batch.ApiError('Unexpected OAuth authorization host')
    state = q.get('state', [''])[0]
    redirect_uri = q.get('redirect_uri', [''])[0]
    redirect = urlsplit(redirect_uri)
    if not state or redirect.hostname not in ('localhost', '127.0.0.1', '::1') or redirect.scheme not in ('http', 'https'):
        raise batch.ApiError('OAuth state or expected loopback redirect is missing')
    return dict(auth_url=auth_url, session_id=data['session_id'], state=state, redirect_uri=redirect_uri)


def callback_code(url, session):
    p, wanted = urlsplit(url), urlsplit(session['redirect_uri'])
    if (p.scheme, p.netloc, p.path) != (wanted.scheme, wanted.netloc, wanted.path):
        return None
    q = parse_qs(p.query)
    if q.get('state', [''])[0] != session['state']:
        raise batch.ApiError('OAuth callback state mismatch')
    if q.get('error'):
        raise batch.ApiError('OAuth authorization was declined or failed')
    code = q.get('code', [''])[0]
    if not code:
        raise batch.ApiError('OAuth callback contains no authorization code')
    return code


class Mailbox:
    def __init__(self, context, account):
        self.account, self.page = account, None
        self.baseline, self.available = set(), False
        if account.mail_url:
            try:
                self.page = context.new_page()
                self.page.goto(account.mail_url, wait_until='domcontentloaded', timeout=30000)
                text = self.page.locator('body').inner_text(timeout=10000)
                if account.email.lower() not in text.lower() or not re.search('最近.*邮件|发件人|收件人|邮箱', text):
                    raise batch.ApiError('Mailbox page unavailable')
                self.baseline = {m.fingerprint for m in self.messages()}
                self.available = True
            except Exception:
                print('  邮箱页面暂不可读，遇到邮件验证时将提示手工输入。', flush=True)

    def messages(self):
        # srcdoc frames are parsed at their parent position. External iframe text
        # is not trusted without the surrounding recipient/date metadata.
        return mailbox_codes(self.page.content(), self.account.email)

    def wait_code(self, started_at, seconds=90):
        if not self.available:
            return None
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                self.page.reload(wait_until='domcontentloaded', timeout=15000)
                code = fresh_mail_code(self.messages(), self.baseline, started_at)
                if code:
                    return code
            except Exception:
                pass
            self.page.wait_for_timeout(3000)
        return None


def visible_first(locator):
    for index in range(locator.count()):
        item = locator.nth(index)
        if item.is_visible():
            return item
    return None


def fill_login_field(page, field, value, timeout=10000):
    # DOMContentLoaded alone does not guarantee that the form is interactive.
    # Wait for the field's own form, then verify that initialization did not
    # replace/reset the value before allowing a submission. No values are logged.
    page.wait_for_load_state('domcontentloaded', timeout=timeout)
    field.wait_for(state='visible', timeout=timeout)
    deadline = time.monotonic() + timeout / 1000
    ready = """field => {
        const form = field.form || field.closest('form');
        return document.readyState !== 'loading' && field.isConnected &&
            !field.disabled && !field.readOnly &&
            !field.closest('[aria-busy="true"]') &&
            !(form && form.querySelector('[aria-busy="true"]'));
    }"""
    while not field.evaluate(ready):
        if time.monotonic() >= deadline:
            raise ManualActionRequired('Login form did not become ready; nothing was submitted')
        page.wait_for_timeout(100)
    field.fill(value, timeout=max(1, int((deadline - time.monotonic()) * 1000)))
    for _ in range(2):
        page.wait_for_timeout(100)
        if not field.evaluate(ready) or field.input_value() != value:
            raise ManualActionRequired('Login form changed during initialization; nothing was submitted')


def auth_response_diagnostic(response):
    parsed = urlsplit(response.url)
    if parsed.hostname not in ('auth.openai.com', 'auth0.openai.com', 'chatgpt.com'):
        return None
    request = response.request
    if response.status < 300 and request.resource_type not in ('document', 'fetch', 'xhr'):
        return None
    result = dict(network_event='response', path=parsed.path,
                  method=request.method, resource_type=request.resource_type,
                  http_status=response.status)
    previous = request.redirected_from
    if previous is not None:
        result['redirect_from'] = urlsplit(previous.url).path
    if 300 <= response.status < 400:
        location = response.header_value('location')
        if location:
            result['redirect_to'] = urlsplit(location).path
    if response.header_value('cf-mitigated') == 'challenge':
        result['cf_challenge'] = True
    return result


def auth_failure_diagnostic(request):
    parsed = urlsplit(request.url)
    if parsed.hostname not in ('auth.openai.com', 'auth0.openai.com', 'chatgpt.com'):
        return None
    # Playwright failure messages can include full URLs; keep only a net error.
    code = re.search(r'ERR_[A-Z_]+', request.failure or '')
    return dict(network_event='request_failed', path=parsed.path,
                method=request.method, resource_type=request.resource_type,
                error_code=code.group() if code else 'REQUEST_FAILED')


def submit_login_form(page, field):
    form = field.locator('xpath=ancestor::form[1]')
    scope = form if form.count() else page
    button = visible_first(scope.locator('button[type="submit"],input[type="submit"]'))
    if button is None:
        button = visible_first(scope.get_by_role('button', name=re.compile(r'^(Continue|Next|Verify|Sign in|Log in|继续|下一步|验证|登录|確認|确认)$', re.I)))
    if button is not None:
        button.click()
        return 'button'
    raise ManualActionRequired('No visible login submit button; nothing was submitted')


def verification_kind(path, body):
    if '/email-verification' in path or '/email-otp' in path:
        return 'email'
    if '/mfa' in path or '/totp' in path:
        return 'totp'
    if re.search(r'authenticator|authentication app|身份验证器|身份验证应用|身份验证代码', body, re.I):
        return 'totp'
    if re.search(r'收件箱|邮箱.*验证码|电子邮件|check your inbox|sent.*code|email.*code', body, re.I):
        return 'email'
    return 'unknown'


def manual_pause(message):
    if not sys.stdin.isatty():
        raise ManualActionRequired('Manual action required: ' + message)
    print('  ' + message, flush=True)
    input('  在浏览器处理完成后按回车继续（Ctrl+C 停止）：')


def callback_server(session):
    target = urlsplit(session['redirect_uri'])
    if target.scheme != 'http' or target.hostname not in ('127.0.0.1', 'localhost'):
        raise batch.ApiError('Manual browser requires an HTTP localhost callback')
    captured = {}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            incoming = urlsplit(self.path)
            query = parse_qs(incoming.query)
            status, message = 400, 'Invalid OAuth callback'
            if incoming.path == target.path and query.get('state', [''])[0] == session['state']:
                try:
                    captured['code'] = callback_code(session['redirect_uri'] + ('?' + incoming.query if incoming.query else ''), session)
                    status, message = 200, '授权回调已接收，Python 正在核验并导入账号。'
                except batch.ApiError as exc:
                    captured['error'] = str(exc)
                    message = 'OAuth authorization failed'
            encoded = message.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    try:
        server = ThreadingHTTPServer(('127.0.0.1', target.port if target.port is not None else 80), Handler)
    except OSError:
        raise batch.ApiError('OAuth callback port is unavailable; close the previous local callback listener first') from None
    server.timeout = 1
    server.daemon_threads = True
    return server, captured


def chrome_executable():
    choices = [Path(os.environ.get(key, '')) / suffix for key, suffix in (
        ('PROGRAMFILES', 'Google/Chrome/Application/chrome.exe'),
        ('PROGRAMFILES(X86)', 'Google/Chrome/Application/chrome.exe'),
        ('LOCALAPPDATA', 'Google/Chrome/Application/chrome.exe'))]
    found = next((path for path in choices if path.is_file()), None)
    if found is None:
        raise batch.ApiError('Installed Google Chrome executable was not found')
    return str(found)


def run_manual_browser(proxy, session, timeout=600, on_step=None):
    on_step = on_step or (lambda step: None)
    server, captured = callback_server(session)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='sub2api-chrome-', ignore_cleanup_errors=True) as directory:
            process = subprocess.Popen([chrome_executable(), '--incognito', '--new-window', '--no-first-run',
                                        '--no-default-browser-check', '--disable-background-mode',
                                        '--user-data-dir=' + directory,
                                        '--proxy-server=' + browser_proxy(proxy)['server'], session['auth_url']],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            on_step('manual_chrome_incognito_opened')
            print('已打开普通 Google Chrome 无痕窗口；请在窗口内手工登录并授权，Python 将自动接收回调。', flush=True)
            deadline = time.monotonic() + timeout
            next_progress = time.monotonic() + 30
            try:
                while time.monotonic() < deadline:
                    if captured.get('error'):
                        raise batch.ApiError(captured['error'])
                    if captured.get('code'):
                        on_step('manual_oauth_callback_received')
                        return captured['code']
                    if process.poll() is not None:
                        raise ManualActionRequired('Manual Chrome was closed before OAuth authorization completed')
                    server.handle_request()
                    if time.monotonic() >= next_progress:
                        on_step('waiting_for_manual_login')
                        next_progress = time.monotonic() + 30
                raise ManualActionRequired('Manual login timed out before an OAuth callback was received')
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    finally:
        server.server_close()


def run_browser(playwright, account, proxy, session, channel='chrome', timeout=600, headless=False, on_step=None, on_diagnostic=None, verification_wait=180, skip_security_verification=False):
    on_step = on_step or (lambda step: None)
    on_diagnostic = on_diagnostic or (lambda data: None)
    # Use the real loopback callback instead of routing browser requests.
    # Even a narrowly scoped Playwright route disables the HTTP cache.
    with ExitStack() as cleanup:
        server, captured = callback_server(session)
        cleanup.callback(server.server_close)
        receiver = threading.Thread(target=server.serve_forever, daemon=True)
        receiver.start()
        cleanup.callback(receiver.join, 5)
        cleanup.callback(server.shutdown)
        proxy_settings = dict(browser_proxy(proxy), bypass='localhost,127.0.0.1,[::1]')
        browser = playwright.chromium.launch(channel=channel, headless=headless, proxy=proxy_settings, args=['--incognito'])
        cleanup.callback(browser.close)
        context = browser.new_context(locale='zh-CN')
        cleanup.callback(context.close)
        page = context.new_page()

        def observe_response(response):
            parsed = urlsplit(response.url)
            if parsed.hostname == 'auth.openai.com' and parsed.path in (
                    '/api/accounts/email-otp/send', '/api/accounts/email-otp/resend', '/api/accounts/email-otp/validate'):
                on_step('email_otp_' + parsed.path.rsplit('/', 1)[-1] + '_http_' + str(response.status))
            try:
                diagnostic = auth_response_diagnostic(response)
            except Exception:
                # Diagnostics must not interrupt a login if a response vanished.
                on_step('response_diagnostic_unavailable')
                return
            if diagnostic:
                on_diagnostic(diagnostic)

        def observe_failure(request):
            diagnostic = auth_failure_diagnostic(request)
            if diagnostic:
                on_diagnostic(diagnostic)

        page.on('response', observe_response)
        page.on('requestfailed', observe_failure)
        started_at = datetime.now(timezone.utc)
        page.bring_to_front()
        login_navigation(page, session['auth_url'])
        on_step('login_page_opened')
        mailbox = Mailbox(context, account)
        page.bring_to_front()
        deadline = time.monotonic() + timeout
        submitted, otp_submitted = set(), {}
        unknown_since = time.monotonic()
        verification_remaining = verification_wait
        while time.monotonic() < deadline:
            if captured.get('error'):
                raise batch.ApiError(captured['error'])
            if captured.get('code'):
                return captured['code']
            if page.is_closed():
                raise batch.ApiError('OAuth browser tab was closed')
            p = urlsplit(page.url)
            if p.scheme != 'https' or p.hostname not in ('auth.openai.com', 'auth0.openai.com', 'chatgpt.com'):
                page.wait_for_timeout(500)
                continue
            body = page.locator('body').inner_text(timeout=10000)
            if p.path.rstrip('/') == '/add-phone':
                on_diagnostic(page_diagnostic(page))
                raise PhoneVerificationRequired('Phone number verification is required before OAuth authorization can complete')
            if human_verification(body):
                if skip_security_verification:
                    on_step('security_verification_skipped')
                    on_diagnostic(page_diagnostic(page))
                    raise SecurityVerificationSkipped('Skipped: website requires human/security verification')
                if verification_remaining <= 0:
                    on_diagnostic(page_diagnostic(page))
                    raise ManualActionRequired('Repeated security checks exceeded the total waiting budget')
                check_started = time.monotonic()
                wait_security_check(page, min(verification_remaining, max(1, deadline - time.monotonic())), on_step, on_diagnostic)
                verification_remaining -= time.monotonic() - check_started
                unknown_since = time.monotonic()
                continue
            email_input = visible_first(page.locator('input[type="email"],input[name="username"],input[name="email"]'))
            password_input = visible_first(page.locator('input[type="password"]'))
            code_input = visible_first(page.locator('input[autocomplete="one-time-code"],input[name="code"],input[name="otp"],input[inputmode="numeric"]'))
            if password_input and 'password' not in submitted:
                fill_login_field(page, password_input, account.password)
                on_step('password_submit_' + submit_login_form(page, password_input))
                submitted.add('password')
                on_step('password_submitted')
                unknown_since = time.monotonic()
            elif email_input and 'email' not in submitted:
                fill_login_field(page, email_input, account.email)
                on_step('email_submit_' + submit_login_form(page, email_input))
                submitted.add('email')
                on_step('email_submitted')
                unknown_since = time.monotonic()
            elif code_input:
                kind = verification_kind(p.path, body)
                is_totp, is_mail = kind == 'totp', kind == 'email'
                if kind in otp_submitted:
                    if time.monotonic() - otp_submitted[kind] > 12:
                        manual_pause('验证码提交后页面仍未继续，请检查浏览器提示并手工处理。')
                        otp_submitted[kind] = time.monotonic()
                    page.wait_for_timeout(500)
                    continue
                if is_totp:
                    while time.time() % 30 > 25:
                        page.wait_for_timeout(500)
                    code = totp(account.mfa_secret)
                elif is_mail:
                    print('  检测到邮箱验证，正在查找本次登录的新邮件。', flush=True)
                    code = mailbox.wait_code(started_at)
                    if not code:
                        if not sys.stdin.isatty():
                            raise ManualActionRequired('Fresh email verification code required; automatic mailbox retrieval unavailable')
                        code = getpass.getpass('  输入该账号本次收到的邮箱验证码（输入不回显）：').strip()
                else:
                    if not sys.stdin.isatty():
                        raise ManualActionRequired('Verification type requires manual identification')
                    code = getpass.getpass('  验证码类型不明确，请手工输入当前验证码（不回显）：').strip()
                if not re.fullmatch(r'\d{6}', code):
                    raise batch.ApiError('Expected a six-digit verification code')
                fill_login_field(page, code_input, code)
                on_step(kind + '_submit_' + submit_login_form(page, code_input))
                code = None
                otp_submitted[kind] = time.monotonic()
                on_step(kind + '_code_submitted')
                unknown_since = time.monotonic()
            else:
                consent_page = (p.path.rstrip('/') == '/sign-in-with-chatgpt/codex/consent' or
                                bool(re.search(r'sign in to|connect.*(?:Codex|ChatGPT)|allow.*access|授权|允许.*访问|登录到|登录至', body, re.I)))
                names = r'^(Allow|Authorize|授权|允许|同意|Continue|继续)$' if consent_page else r'^(Allow|Authorize|授权|允许|同意)$'
                consent = visible_first(page.get_by_role('button', name=re.compile(names, re.I)))
                if consent and 'consent' not in submitted:
                    consent.click()
                    submitted.add('consent')
                    on_step('consent_submitted')
                    unknown_since = time.monotonic()
                elif time.monotonic() - unknown_since > 20:
                    on_diagnostic(dict(path=urlsplit(page.url).path,
                                       headings=page.locator('h1,h2,[role=alert]').all_inner_texts()[:8],
                                       buttons=page.get_by_role('button').all_inner_texts()[:12]))
                    manual_pause('当前页面需要手工继续；请在授权浏览器中操作。')
                    unknown_since = time.monotonic()
            page.wait_for_timeout(500)
        raise batch.ApiError('OAuth browser timed out; no account was imported')


def exchange(client, session, code, proxy_id, email):
    result = client.request('POST', OAUTH + '/exchange-code', dict(session_id=session['session_id'], code=code, state=session['state'], proxy_id=proxy_id))
    if not isinstance(result, dict) or not result.get('access_token') or not result.get('refresh_token'):
        raise batch.ApiError('OAuth exchange did not return access_token and refresh_token')
    batch.verify_login_identity(result, email)
    allowed = ('access_token', 'refresh_token', 'id_token', 'email', 'expires_at', 'chatgpt_account_id',
               'chatgpt_user_id', 'organization_id', 'plan_type', 'client_id', 'subscription_expires_at')
    return {k: result[k] for k in allowed if result.get(k) is not None}


def proxy_record(proxy):
    keys = ('name', 'protocol', 'host', 'port', 'username', 'password', 'status', 'fallback_mode')
    result = {k: proxy.get(k) for k in keys}
    result['username'], result['password'] = proxy.get('username') or '', proxy.get('password') or ''
    result['status'] = 'active'
    result['fallback_mode'] = proxy.get('fallback_mode') or 'none'
    result['proxy_key'] = '|'.join(str(result[k]) for k in ('protocol', 'host', 'port', 'username', 'password'))
    return result


def export_account(email, credential, proxy_key):
    return dict(name=email, platform='openai', type='oauth', credentials=credential, proxy_key=proxy_key,
                extra={'cost_multiplier': 0.1, 'openai_request_timezone': 'Asia/Singapore',
                       'openai_oauth_responses_websockets_v2_enabled': False,
                       'openai_oauth_responses_websockets_v2_mode': 'off'},
                concurrency=10, priority=1, rate_multiplier=1, group_rate_multiplier=1,
                auto_pause_on_expired=True)


def write_json(path, data):
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def release_unbound_failure(picker, email):
    # Only call before import has started: no account was bound on this attempt.
    for owners in (picker.proxy_owners, picker.ip_owners):
        for key in [key for key, owner in owners.items() if owner == email]:
            del owners[key]


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--file', type=Path, default=ROOT / 'batch_results/unsuccessful_accounts_20261115.txt')
    p.add_argument('--base-url', default=os.getenv('SUB2API_BASE_URL', ''),
                   help='Your HTTPS backend origin; defaults to SUB2API_BASE_URL')
    p.add_argument('--email', default=os.getenv('SUB2API_EMAIL', ''))
    p.add_argument('--group-ids', nargs='+', default=['6,15,23'])
    p.add_argument('--limit', type=int, default=1, help='Default 1; use 0 for the whole file')
    p.add_argument('--import', dest='do_import', action='store_true', help='Also import after obtaining OAuth credentials')
    p.add_argument('--continue-after-login-failure', action='store_true', help='Release temporary proxy reservations after a failed login that never reached import, so the next account can use remaining capacity')
    p.add_argument('--verify-only', action='store_true', help='Verify OAuth login, including existing accounts; do not import or save tokens')
    p.add_argument('--only-email', help='Limit the run to this email from the original account file')
    p.add_argument('--channel', choices=('msedge', 'chrome'), default='chrome')
    p.add_argument('--headless', action='store_true')
    p.add_argument('--manual-browser', action='store_true', help='Open ordinary Chrome incognito for manual login; Python receives and imports the OAuth callback')
    p.add_argument('--gateway', help='Loopback HTTP transport to reach the selected upstream proxy, e.g. http://127.0.0.1:7890')
    p.add_argument('--max-per-ip', type=int, default=5)
    p.add_argument('--max-latency', type=float, default=300)
    p.add_argument('--browser-timeout', type=int, default=600)
    p.add_argument('--skip-security-verification', action='store_true', help='Immediately mark and skip security-check pages without waiting')
    p.add_argument('--verification-wait', type=int, default=180, help='Wait for automatic security checks before reporting manual action')
    p.add_argument('--resume-journal', type=Path, action='append', default=[])
    p.add_argument('--output-dir', type=Path, default=ROOT / 'oauth_results')
    args = p.parse_args(argv)
    u = urlsplit(args.base_url)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path not in ('', '/') or u.query or u.fragment:
        p.error('Set --base-url or SUB2API_BASE_URL to your HTTPS backend origin')
    if args.limit < 0 or not 1 <= args.max_per_ip <= 5 or not math.isfinite(args.max_latency) or args.max_latency <= 0 or args.browser_timeout <= 0 or args.verification_wait <= 0:
        p.error('Invalid limits; max-per-ip must be 1..5')
    try:
        gateway_address(args.gateway)
    except ValueError as exc:
        p.error(str(exc))
    if args.verify_only and args.do_import:
        p.error('--verify-only cannot be combined with --import')
    if args.verify_only and args.manual_browser:
        p.error('--verify-only tests the automated login flow')
    if args.manual_browser and (args.headless or args.channel != 'chrome'):
        p.error('--manual-browser requires visible Chrome')
    args.group_ids = batch.parse_group_ids(args.group_ids)
    return args


def main(argv=None):
    args = parse_args(argv)
    accounts = load_accounts(args.file.read_text(encoding='utf-8-sig'))
    if args.only_email:
        accounts = [a for a in accounts if a.email == args.only_email.strip().lower()]
        if not accounts:
            raise batch.ApiError('Requested email was not found in the supplied account file')
    if not args.manual_browser:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise batch.ApiError('Install the dependency first: python -m pip install playwright') from None
    token = os.getenv('SUB2API_TOKEN')
    password = None if token else os.getenv('SUB2API_PASSWORD') or getpass.getpass('后台管理员密码（不回显）：')
    secrets = [s for a in accounts for s in (a.password, a.mfa_secret, a.mail_url) if s]
    client = RegionClient(args.base_url, args.email, password, token, 45, direct=True, secrets=secrets)
    if args.gateway:
        client.opener = build_opener(ProxyHandler({'https': args.gateway, 'http': args.gateway}), batch.NoRedirect())
    if not token:
        client.login()
    client.password = None
    batch.resolve_groups(client, [], group_ids=args.group_ids)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = args.output_dir / datetime.now(batch.SHANGHAI).strftime('oauth_%Y%m%d_%H%M%S_%f')
    exported = dict(exported_at=datetime.now(timezone.utc).isoformat(), proxies=[], accounts=[])
    exported_keys, rows = set(), []
    attempted = 0
    virtual = {} if not args.do_import else None
    with batch.batch_lock(ROOT), stem.with_suffix('.jsonl').open('x', encoding='utf-8') as log:
        def journal(event, **data):
            log.write(json.dumps(dict(time=batch.now(), event=event, **data), ensure_ascii=False) + '\n')
            log.flush()
        picker = batch.ProxyPicker(client, args.max_per_ip, args.max_latency, journal, virtual=virtual)
        batch.restore_reservations(picker, args.resume_journal)
        browser_manager = nullcontext(None) if args.manual_browser else sync_playwright()
        with browser_manager as playwright:
            for account in accounts:
                if args.limit and attempted >= args.limit:
                    break
                row = dict(email=account.email, status='pending')
                stage = 'precheck'
                print(account.email + '：开始处理', flush=True)
                try:
                    existing = batch.existing_account(client, account.email)
                    if existing and not args.verify_only:
                        row.update(status='skipped_existing', account_id=existing['id'])
                    else:
                        attempted += 1
                        if existing and args.verify_only:
                            proxies = client.list_proxies(100)
                            selected = client.catalog.get(existing.get('proxy_id'))
                            if not selected or not batch.active(selected) or not locally_routable(selected):
                                raise batch.ApiError('Existing account proxy is unavailable from this machine')
                            result = client.request('POST', f"/api/v1/admin/proxies/{selected['id']}/test")
                            if not result.get('success'):
                                raise batch.ApiError('Existing account proxy test failed')
                            ip = batch.normalize_ip(result.get('ip_address'))
                            used = batch.occupancy(proxies, selected, ip)
                            if not ip or used is None or used > args.max_per_ip:
                                raise batch.ApiError('Existing account exit occupancy exceeds the configured limit')
                            chosen = picker.reserve(dict(proxy_id=selected['id'], proxy_name=selected.get('name', ''),
                                                         exit_ip=ip, latency_ms=result.get('latency_ms'), occupancy_before=used,
                                                         relaxed_latency=bool(result.get('latency_ms', 0) >= args.max_latency)), account.email)
                        else:
                            chosen = picker.choose(account.email)
                        row.update(proxy_id=chosen['proxy_id'], exit_ip=chosen['exit_ip'], proxy_name=chosen['proxy_name'])
                        proxy = client.catalog[chosen['proxy_id']]
                        client.secrets.extend(str(proxy.get(k) or '') for k in ('username', 'password') if proxy.get(k))
                        stage = 'proxy_preflight'
                        with ProxyBridge(proxy, gateway=args.gateway) as transport:
                            location = transport.verify_exit(chosen['exit_ip'])
                            if not permitted_location(dict(location, country=location.get('country_code') or location.get('country'))):
                                raise batch.ApiError('Local proxy exit country is excluded or unknown')
                            journal('local_proxy_verified', email=account.email, proxy_id=chosen['proxy_id'],
                                    exit_ip=location['ip'], country=location.get('country_code'))
                            session = oauth_session(client, chosen['proxy_id'])
                            stage = 'browser'
                            if args.manual_browser:
                                code = run_manual_browser(transport.profile, session, args.browser_timeout,
                                                          on_step=lambda step: journal('login_step', email=account.email, step=step))
                            else:
                                code = run_browser(playwright, account, transport.profile, session, args.channel, args.browser_timeout, args.headless,
                                                   on_step=lambda step: journal('login_step', email=account.email, step=step),
                                                   on_diagnostic=lambda data: journal('page_diagnostic', email=account.email,
                                                       details=clean_page_diagnostic(client, data)), verification_wait=args.verification_wait,
                                                       skip_security_verification=args.skip_security_verification)
                            transport.verify_exit(chosen['exit_ip'])
                        recheck_same_proxy(client, chosen, args.max_per_ip, allow_full=bool(args.verify_only and existing))
                        stage = 'exchange'
                        credential = exchange(client, session, code, chosen['proxy_id'], account.email)
                        client.secrets.extend(str(credential.get(k) or '') for k in ('access_token', 'refresh_token', 'id_token'))
                        code = None
                        recheck_same_proxy(client, chosen, args.max_per_ip, allow_full=bool(args.verify_only and existing))
                        if args.verify_only:
                            credential = None
                            row.update(status='login_verified', login_verified=True)
                            if existing:
                                row['account_id'] = existing['id']
                            rows.append(row)
                            journal('result', **row)
                            print(account.email + ': login_verified', flush=True)
                            continue
                        record = proxy_record(proxy)
                        if record['proxy_key'] not in exported_keys:
                            exported['proxies'].append(record)
                            exported_keys.add(record['proxy_key'])
                        exported['accounts'].append(export_account(account.email, credential, record['proxy_key']))
                        write_json(stem.with_suffix('.accounts.json'), exported)
                        row['login_verified'] = True
                        if args.do_import:
                            stage = 'import'
                            existing = batch.existing_account(client, account.email)
                            if existing:
                                row.update(status='skipped_existing', account_id=existing['id'])
                            else:
                                outcome = batch.import_new(client, account, credential, chosen, args.group_ids, None, journal)
                                row.update(outcome)
                                if outcome.get('status') == 'created' and (outcome.get('occupancy_after') is None or outcome['occupancy_after'] > args.max_per_ip):
                                    raise batch.HaltBatch('Imported account requires IP occupancy review; see journal')
                        else:
                            virtual[chosen['exit_ip']] = virtual.get(chosen['exit_ip'], 0) + 1
                            row['status'] = 'exported'
                        credential = None
                except Exception as exc:
                    uncertain = stage == 'import' or isinstance(exc, batch.HaltBatch)
                    row.update(status='needs_review' if uncertain else 'skipped_security_verification' if isinstance(exc, SecurityVerificationSkipped) else 'needs_phone_verification' if isinstance(exc, PhoneVerificationRequired) else 'needs_manual' if isinstance(exc, ManualActionRequired) else 'blocked_proxy' if isinstance(exc, batch.NoProxyAvailable) else 'failed', stage=stage,
                               message=client.clean(exc) if isinstance(exc, (batch.ApiError, RouteError)) else 'Browser/runtime error: ' + type(exc).__name__)
                    if args.continue_after_login_failure and not uncertain and stage in ('browser', 'proxy_preflight', 'exchange'):
                        release_unbound_failure(picker, account.email)
                        journal('unbound_proxy_released', email=account.email, stage=stage)
                    stop_for_network = isinstance(exc, BrowserNetworkError) and not args.continue_after_login_failure
                    if isinstance(exc, batch.NoProxyAvailable) or stop_for_network or uncertain:
                        rows.append(row)
                        journal('result', **row)
                        print(row['email'] + '：' + row['status'], flush=True)
                        break
                rows.append(row)
                journal('result', **row)
                print(row['email'] + '：' + row['status'], flush=True)
        if args.limit == 0 and len(rows) < len(accounts):
            recorded = {r['email'] for r in rows}
            stop_reason = rows[-1].get('message', 'Batch stopped before this account') if rows else 'Batch stopped before this account'
            for account in accounts:
                if account.email in recorded:
                    continue
                row = dict(email=account.email, status='not_attempted', stage='precheck', message=stop_reason)
                try:
                    existing = batch.existing_account(client, account.email)
                    if existing and not args.verify_only:
                        row = dict(email=account.email, status='skipped_existing', account_id=existing['id'])
                except batch.ApiError:
                    pass
                rows.append(row)
                journal('result', **row)
    pending_emails = {r['email'] for r in rows if r['status'] not in ('created', 'skipped_existing', 'login_verified', 'exported')}
    if pending_emails:
        with stem.with_suffix('.remaining.txt').open('x', encoding='utf-8') as remaining:
            for account in accounts:
                if account.email in pending_emails:
                    remaining.write('----'.join([account.email, account.password, account.mfa_secret] + ([account.mail_url] if account.mail_url else [])) + '\n')
    summary = dict(input_count=len(accounts), processed_count=len(rows),
                   exported=len(exported['accounts']), created=sum(r['status'] == 'created' for r in rows),
                   group_ids=args.group_ids, excluded_countries=['HK', 'TW'], max_per_ip=args.max_per_ip,
                   mode='verify' if args.verify_only else 'import' if args.do_import else 'export', attempted=attempted, gateway=args.gateway, items=rows)
    write_json(stem.with_suffix('.report.json'), summary)
    print('结果报告：' + str(stem.with_suffix('.report.json')))
    if args.verify_only:
        print('全自动登录验证通过：' + str(sum(r['status'] == 'login_verified' for r in rows)) + ' 个账号；验证模式不保存 Token、不重复导入。')
    else:
        print('OAuth JSON：' + str(stem.with_suffix('.accounts.json')) if exported['accounts'] else '没有取得可导入的 OAuth 凭据。')
    if not args.do_import and not args.verify_only:
        print('JSON 不包含分组；导入时选择分组 ' + ','.join(map(str, args.group_ids)) + '，并重新核对 IP 容量。')
    return 2 if any(r['status'] in ('failed', 'needs_review', 'needs_manual', 'blocked_proxy', 'not_attempted', 'skipped_security_verification', 'needs_phone_verification') for r in rows) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n已停止。再次运行前检查 oauth_results 中的日志和报告。', file=sys.stderr)
        sys.exit(130)
    except (batch.ApiError, OSError, ValueError, EOFError) as exc:
        print('错误：' + str(exc) if isinstance(exc, batch.ApiError) else '配置或文件错误：' + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
