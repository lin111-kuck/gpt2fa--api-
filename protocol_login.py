# SPDX-License-Identifier: AGPL-3.0-only
"""Local Codex PKCE login. See login_vendor/SOURCE.md and LICENSE."""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import shutil
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from batch_login import ApiError, BatchStopped, verify_login_identity
from mailbox_api import MailboxAPI, MailboxError

AUTH = 'https://auth.openai.com'
CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'
REDIRECT = 'http://localhost:1455/auth/callback'
EXIT_LOOKUP = 'https://ipwho.is/'
NETWORK_FIELDS = ('exit_ip', 'country_code', 'timezone', 'language', 'user_agent', 'browser')


class ProtocolError(ApiError):
    def __init__(self, message, code='', upstream_status=None):
        super().__init__(message)
        self.code, self.upstream_status = code, upstream_status


def totp(secret, timestamp=None):
    raw = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
    counter = int(time.time() if timestamp is None else timestamp) // 30
    digest = hmac.new(raw, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'


def decode_object(value):
    try:
        return json.loads(base64.urlsafe_b64decode(value + '=' * ((-len(value)) % 4)))
    except (ValueError, UnicodeError):
        return {}


def callback_code(url, state):
    p, expected = urlsplit(url), urlsplit(REDIRECT)
    if (p.scheme, p.netloc, p.path) != (expected.scheme, expected.netloc, expected.path) or p.fragment:
        raise ProtocolError('OAuth 回调地址不匹配')
    q = parse_qs(p.query, keep_blank_values=True)
    if q.get('state') != [state] or len(q.get('code', [])) != 1 or not q['code'][0] or 'error' in q:
        raise ProtocolError('OAuth 回调 state 或授权码无效')
    return q['code'][0]


def state_from_url(url):
    path = urlsplit(url).path
    for fragment, kind in (
            ('/log-in/password', 'login_password'), ('/mfa-challenge', 'mfa_challenge'),
            ('/email-verification', 'email_otp_verification'), ('/add-phone', 'add_phone'),
            ('/phone-verification', 'phone_verification'), ('/choose-an-account', 'choose_account'),
            ('/consent', 'consent'), ('/workspace', 'workspace'),
            ('/create-account', 'registration_required'), ('/about-you', 'profile_required')):
        if fragment in path:
            return kind
    if path in ('/log-in', '/log-in-or-create-account'):
        return 'login'
    return ''


def detect_exit(session, expected_exit_ip='', country_code='', timeout=15, stop_event=None):
    """Probe via the authentication transport; never fall back to a direct connection."""
    from login_vendor.fingerprint import supported_country_codes
    if stop_event is not None and stop_event.is_set():
        raise BatchStopped('任务已停止')
    expected = None
    try:
        if expected_exit_ip:
            expected = ipaddress.ip_address(expected_exit_ip)
    except ValueError:
        raise ProtocolError('预期代理出口 IP 无效', 'exit_ip_mismatch') from None
    response = None
    try:
        response = session.request('GET', EXIT_LOOKUP, timeout=min(15, timeout),
                                   allow_redirects=False,
                                   headers={'accept': 'application/json', 'cache-control': 'no-cache'})
        if response.status_code != 200:
            raise ProtocolError('无法检测代理出口（HTTP 非 200）；未继续登录', 'exit_detection_failed')
        data = response.json()
    except ProtocolError:
        raise
    except Exception:
        raise ProtocolError('无法检测代理出口；请检查代理连接和 IP 检测服务', 'exit_detection_failed') from None
    finally:
        if response is not None and callable(getattr(response, 'close', None)):
            response.close()
    if stop_event is not None and stop_event.is_set():
        raise BatchStopped('任务已停止')
    if not isinstance(data, dict) or data.get('success') is not True:
        raise ProtocolError('IP 检测服务未返回有效出口信息', 'exit_detection_failed')
    try:
        ip = ipaddress.ip_address(data.get('ip')) if isinstance(data.get('ip'), str) else None
    except ValueError:
        ip = None
    if ip is None or not ip.is_global or ip.is_multicast:
        raise ProtocolError('IP 检测服务未返回公网出口 IP', 'exit_detection_failed')
    if expected is not None and ip != expected:
        raise ProtocolError('实际代理出口与预期 IP 不一致，已停止登录', 'exit_ip_mismatch')
    country = data.get('country_code')
    if not isinstance(country, str) or not re.fullmatch('[A-Z]{2}', country):
        raise ProtocolError('出口国家信息缺失或无效，无法匹配指纹', 'exit_detection_failed')
    if country_code and country != country_code:
        raise ProtocolError('实际出口国家与配置的预期国家不一致', 'exit_country_mismatch')
    if country not in supported_country_codes():
        raise ProtocolError('当前指纹语言库尚未支持该出口国家，已停止登录', 'unsupported_exit_country')
    timezone_data = data.get('timezone')
    tz = timezone_data.get('id') if isinstance(timezone_data, dict) else None
    if not isinstance(tz, str) or not 1 <= len(tz) <= 100:
        raise ProtocolError('出口时区信息缺失，无法匹配指纹', 'exit_timezone_invalid')
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ProtocolError('出口时区无效或缺少 tzdata；请运行本地安装脚本', 'exit_timezone_invalid') from None
    return dict(exit_ip=str(ip), country_code=country, timezone=tz)


def make_session(proxy, country_code='', *, expected_exit_ip='', timeout=15, stop_event=None, ipv4_only=False):
    from login_vendor.fingerprint import generate_fingerprint
    from login_vendor.http_client_wreq import WreqSession, wreq
    if wreq is None or not hasattr(wreq.Emulation, 'Chrome152'):
        raise ProtocolError('本地协议引擎需要 wreq==0.13.0（Chrome152）')
    try:
        p = urlsplit(proxy)
        if (p.scheme not in ('http', 'https', 'socks5', 'socks5h') or not p.hostname or not p.port
                or p.query or p.fragment or p.path not in ('', '/')):
            raise ValueError()
    except (TypeError, ValueError):
        raise ProtocolError('必须配置完整的 HTTP/HTTPS/SOCKS5 登录代理，不能静默直连', 'proxy_required') from None
    bridge = None
    if ipv4_only:
        from oauth_proxy_transport import ProxyBridge
        bridge = ProxyBridge(dict(protocol='socks5' if p.scheme == 'socks5h' else p.scheme,
                                  host=p.hostname, port=p.port,
                                  username=unquote(p.username or ''), password=unquote(p.password or '')),
                             force_ipv4=True)
        bridge.__enter__()
        proxy = 'http://127.0.0.1:' + str(bridge.profile['port'])
    try:
        session = WreqSession(proxy=proxy, impersonate='Chrome152', platform='Windows', retries=0)
    except BaseException:
        if bridge:
            bridge.__exit__()
        raise
    if bridge:
        original_close = session.close
        closed = False
        def close():
            nonlocal closed
            if not closed:
                closed = True
                try:
                    original_close()
                finally:
                    bridge.__exit__()
        session.close = close
    try:
        location = detect_exit(session, expected_exit_ip, country_code, timeout, stop_event)
        fp = generate_fingerprint(country_code=location['country_code'], browser_family='chrome')
        # Use the detected city timezone rather than the vendor's weighted country default.
        fp.update(location)
        # Match UA/Client Hints with wreq's actual preset; do not mix custom TLS variants.
        fp.update(impersonate='chrome152', fallback_impersonates=[], tls_fp=None, akamai_fp=None)
        session.headers.update({'accept-language': fp['lang_full'], 'user-agent': fp['user_agent']})
        for key in ('sec_ch_ua', 'sec_ch_ua_platform', 'sec_ch_ua_mobile'):
            if fp.get(key):
                session.headers[key.replace('_', '-')] = fp[key]
        return session, fp
    except BaseException:
        session.close()
        raise


def network_details(fingerprint, phase):
    """Only non-credential fields are exposed to the workbench or relogin progress."""
    return dict(phase=phase, exit_ip=fingerprint['exit_ip'], country_code=fingerprint['country_code'],
                timezone=fingerprint['timezone'], language=fingerprint['lang_full'],
                user_agent=fingerprint['user_agent'], browser='Chrome152')


class LoginFlow:
    def __init__(self, entry, session, fingerprint, mailbox=None, timeout=600,
                 mail_timeout=180, stop_event=None, on_step=None, sentinel=None):
        self.entry, self.session, self.fp, self.mailbox = entry, session, fingerprint, mailbox
        self.stop = stop_event or threading.Event()
        self.deadline = time.monotonic() + timeout
        self.mail_timeout = mail_timeout
        self.on_step = on_step or (lambda stage: None)
        self.sentinel_provider = sentinel
        self.device_id = str(uuid.uuid4())
        self.navigation_id, self.invocation_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.state = secrets.token_urlsafe(24)
        self.verifier = secrets.token_urlsafe(48)
        self.last_url = AUTH + '/log-in'
        self.navigation_started = False
        self.auth_session = {}
        self.session.cookies.set('oai-did', self.device_id, domain='auth.openai.com', path='/')

    def remaining(self):
        if self.stop.is_set():
            raise BatchStopped('任务已停止')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError('本地协议登录超时')
        return remaining

    def event(self, stage):
        self.remaining()
        self.on_step(stage)

    def trusted(self, url):
        p = urlsplit(url)
        if (p.scheme != 'https' or p.hostname != 'auth.openai.com' or p.port not in (None, 443)
                or p.username or p.password or p.fragment):
            raise ProtocolError('登录流程返回了不支持的跳转地址；请使用浏览器核查')
        return url

    def request(self, method, url, **kwargs):
        self.trusted(url)
        try:
            response = self.session.request(method, url, timeout=min(30, self.remaining()),
                                            allow_redirects=False, **kwargs)
        except ApiError:
            raise
        except Exception:
            raise ProtocolError('认证请求网络失败；状态变更请求未自动重放', 'network') from None
        self.remaining()
        if response.status_code >= 400:
            code = ''
            try:
                error = response.json().get('error')
                if isinstance(error, dict):
                    code = str(error.get('code') or error.get('type') or '')
                elif isinstance(error, str):
                    code = error
            except (ValueError, AttributeError):
                pass
            # Only known machine codes are displayed, never raw response bodies.
            labels = {'invalid_password': '账号密码被拒绝', 'incorrect_password': '账号密码被拒绝',
                      'invalid_otp': '验证码被拒绝', 'invalid_code': '验证码被拒绝',
                      'otp_invalid': '验证码被拒绝', 'otp_expired': '验证码已过期',
                      'mfa_invalid_code': 'TOTP 验证码被拒绝', 'invalid_state': '登录会话状态失效'}
            message = labels.get(code, f'认证服务返回 HTTP {response.status_code}')
            if response.status_code == 429:
                message = '认证服务限流（429），已停止本次登录'
            elif response.status_code == 403:
                message = '认证服务拒绝请求（403），可能需要浏览器安全验证'
            raise ProtocolError(message, code, response.status_code)
        return response

    def sentinel_headers(self, flow):
        if self.sentinel_provider:
            return self.sentinel_provider(flow)
        from login_vendor.sentinel_quickjs import get_sentinel_token_via_quickjs, _resolve_node_binary
        if not shutil.which(_resolve_node_binary()):
            raise ProtocolError('本地协议登录需要 Node.js，请安装后重新启动工作台')
        kwargs = {k: self.fp.get(k, '') for k in
                  ('user_agent', 'screen', 'lang', 'lang_full', 'browser_type', 'hardware_concurrency',
                   'device_memory', 'max_touch_points', 'device_pixel_ratio', 'timezone')}
        kwargs.update(platform=self.fp.get('navigator_platform'), vendor=self.fp.get('navigator_vendor'))
        try:
            result = get_sentinel_token_via_quickjs(
                self.session, self.device_id, flow=flow, log=lambda message: None,
                timeout_ms=int(min(45, self.remaining()) * 1000), **kwargs)
        except ApiError:
            raise
        except Exception:
            raise ProtocolError('Sentinel 请求失败；未提交本步骤凭证', 'sentinel') from None
        self.remaining()
        if not result or not result[0]:
            status = getattr(self.session, '_sentinel_last_http_status', 0)
            if type(status) is int and status >= 400:
                phase = 'SDK' if getattr(self.session, '_sentinel_last_step', '') == 'sdk' else 'challenge'
                raise ProtocolError(f'Sentinel {phase} 请求返回 HTTP {status}；请核对登录代理出口',
                                    'sentinel_http', status)
            raise ProtocolError('Sentinel 运行失败，可能需要适配新的 SDK；未提交本步骤凭证', 'sentinel')
        token, observer = result
        return {'openai-sentinel-token': token, **({'openai-sentinel-so-token': observer} if observer else {})}

    def post(self, path, payload, flow=None):
        headers = {'accept': 'application/json', 'content-type': 'application/json',
                   'referer': self.last_url, 'sec-fetch-site': 'same-origin',
                   'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty',
                   'oai-device-id': self.device_id, 'oai-language': self.fp.get('lang', 'en-US'),
                   'x-openai-document-navigation-id': self.navigation_id,
                   'x-access-flow-invocation-id': self.invocation_id}
        if flow:
            headers.update(self.sentinel_headers(flow))
        response = self.request('POST', AUTH + path, json=payload, headers=headers)
        try:
            data = response.json()
        except ValueError:
            raise ProtocolError('认证服务返回了非 JSON 响应；可能需要安全验证') from None
        if not isinstance(data, dict):
            raise ProtocolError('认证服务响应结构不受支持')
        self.session_data(data)
        return data

    def session_data(self, data, fields=()):
        supplied = data.get('oai-client-auth-session')
        if isinstance(supplied, dict):
            self.auth_session = supplied
            if not fields or any(key in supplied for key in fields):
                return supplied
        for cookie in self.session.cookies:
            if getattr(cookie, 'name', '') != 'oai-client-auth-session':
                continue
            value = unquote(cookie.value)
            for segment in value.split('.')[:2]:
                decoded = decode_object(segment)
                if (isinstance(decoded, dict) and decoded
                        and (not fields or any(key in decoded for key in fields))):
                    return decoded
        if not fields or any(key in self.auth_session for key in fields):
            return self.auth_session
        return {}

    def totp_step(self, data):
        if not self.entry.mfa_secret:
            raise ProtocolError('账号要求 TOTP，但输入未提供 2FA 长期密钥', 'totp_secret_required')
        session = self.session_data(data, ('mfa_challenge_factors', 'mfa_factors'))
        factors = [f for key in ('mfa_challenge_factors', 'mfa_factors')
                   for f in (session.get(key) or []) if isinstance(f, dict)
                   and f.get('factor_type') == 'totp' and isinstance(f.get('id'), str) and f['id']]
        factors = {f['id']: f for f in factors}
        if len(factors) != 1:
            raise ProtocolError('TOTP factor 缺失或存在多个候选；需要明确绑定后再登录', 'factor_binding_required')
        factor_id = next(iter(factors))
        self.event('totp_challenge')
        self.post('/api/accounts/mfa/issue_challenge',
                  {'type': 'totp', 'id': factor_id, 'force_fresh_challenge': False})
        # Avoid issuing an OTP in the last few seconds of a time window.
        remaining_window = 30 - time.time() % 30
        if remaining_window < 4:
            self.stop.wait(min(remaining_window + 0.2, self.remaining()))
        self.remaining()
        return self.post('/api/accounts/mfa/verify',
                         {'type': 'totp', 'id': factor_id, 'code': totp(self.entry.mfa_secret)}, 'password_verify')

    def email_step(self, issued_after, needs_send=False):
        if self.mailbox is None:
            raise ProtocolError('登录要求邮箱验证码，请在账号行末提供邮箱 API 地址', 'mailbox_required')
        self.event('email_otp_waiting')
        if needs_send:
            self.post('/api/accounts/passwordless/send-otp', {})
        for attempt in range(2):
            code = self.mailbox.wait_code(
                issued_after, min(self.mail_timeout, self.remaining()),
                resend=lambda: self.post('/api/accounts/email-otp/resend', {}), on_wait=self.event)
            self.event('email_otp_received')
            try:
                return self.post('/api/accounts/email-otp/validate', {'code': code}, 'email_otp_validate')
            except ProtocolError as error:
                if (attempt or error.upstream_status not in (400, 401)
                        or error.code not in ('invalid_otp', 'invalid_code', 'otp_invalid', 'otp_expired')):
                    raise
                self.event('email_otp_rejected')
                issued_after = time.time()
                self.post('/api/accounts/email-otp/resend', {})
        raise ProtocolError('邮箱验证码验证失败')

    def navigate(self, url):
        initial = not self.navigation_started
        for _ in range(16):
            if urlsplit(url).hostname in ('localhost', '127.0.0.1'):
                callback_code(url, self.state)
                return {'callback': url}
            self.trusted(url)
            headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                       'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document',
                       'sec-fetch-site': 'none' if initial else 'same-origin',
                       'sec-fetch-user': '?1', 'upgrade-insecure-requests': '1'}
            if not initial:
                headers['referer'] = self.last_url
            response = self.request('GET', url, headers=headers)
            self.navigation_started = True
            self.last_url = url
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('location') or response.headers.get('Location')
                if not location:
                    raise ProtocolError('认证服务跳转缺少 Location')
                url = urljoin(url, location)
                continue
            if response.status_code != 200:
                raise ProtocolError('认证导航返回了不支持的响应')
            try:
                data = response.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and ('page' in data or 'continue_url' in data):
                self.session_data(data)
                return data
            text = response.text or ''
            if re.search(r'cf-chl-|Just a moment|Checking your browser|verify you are human', text, re.I):
                raise ProtocolError('需要浏览器安全验证，协议登录已停止', 'security_check')
            kind = state_from_url(url)
            if kind == 'choose_account':
                ids = set(re.findall(r'\bus_[A-Za-z0-9_-]+', text))
                if len(ids) != 1:
                    raise ProtocolError('授权页面缺少唯一账号会话；请通过浏览器核查')
                return self.post('/api/accounts/session/select', {'session_id': ids.pop()})
            return {'page': {'type': kind}, 'continue_url': url}
        raise ProtocolError('认证跳转次数超限')

    def run(self):
        self.event('authorize')
        if self.mailbox:
            self.mailbox.snapshot(min(12, self.remaining()))
        issued_after = time.time()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b'=').decode()
        params = dict(client_id=CLIENT_ID, response_type='code', redirect_uri=REDIRECT,
                      scope='openid email profile offline_access', state=self.state,
                      code_challenge=challenge, code_challenge_method='S256', prompt='login',
                      id_token_add_organizations='true', codex_cli_simplified_flow='true')
        data = self.navigate(AUTH + '/oauth/authorize?' + urlencode(params))
        counts = {}
        for _ in range(24):
            self.remaining()
            if data.get('callback'):
                return self.exchange(callback_code(data['callback'], self.state))
            target = data.get('continue_url') or data.get('redirect_url') or ''
            if target:
                target = urljoin(AUTH, target)
                if urlsplit(target).hostname in ('localhost', '127.0.0.1'):
                    return self.exchange(callback_code(target, self.state))
                self.trusted(target)
            page = data.get('page') or {}
            kind = str(page.get('type') or '') if isinstance(page, dict) else ''
            kind = kind or state_from_url(target)
            counts[kind] = counts.get(kind, 0) + 1
            if counts[kind] > 2:
                raise ProtocolError('登录状态重复，已停止以避免重复提交')
            if kind in ('add_phone', 'phone_verification') or state_from_url(target) in ('add_phone', 'phone_verification'):
                raise ProtocolError('账号还需要手机号验证；邮箱取码不能完成此步骤', 'phone_required')
            if kind in ('registration_required', 'create_account_password', 'profile_required', 'create_account'):
                raise ProtocolError('账号要求注册或补充资料，请先在浏览器完成', 'manual_required')
            if kind in ('login', 'login_email', 'email_input'):
                self.event('email_submitted')
                issued_after = time.time()
                data = self.post('/api/accounts/authorize/continue',
                                 {'username': {'kind': 'email', 'value': self.entry.email}, 'screen_hint': 'login'},
                                 'authorize_continue')
            elif kind in ('login_password', 'password'):
                self.last_url = target or AUTH + '/log-in/password'
                issued_after = time.time()
                if self.entry.password:
                    self.event('password_submitted')
                    data = self.post('/api/accounts/password/verify', {'password': self.entry.password}, 'password_verify')
                else:
                    data = self.email_step(issued_after, needs_send=True)
            elif kind in ('mfa_challenge', 'mfa') or state_from_url(target) == 'mfa_challenge':
                self.last_url = target or AUTH + '/mfa-challenge'
                issued_after = time.time()
                data = self.totp_step(data)
            elif kind in ('email_otp_verification', 'email_otp_send', 'passwordless_login', 'passwordless_signup'):
                if target and urlsplit(target).path == '/api/accounts/email-otp/send':
                    data = self.navigate(target)
                    continue
                self.last_url = AUTH + '/email-verification'
                data = self.email_step(issued_after)
            elif kind in ('consent', 'workspace', 'workspace_selection'):
                session = self.session_data(data, ('workspaces',))
                workspaces = [w for w in (session.get('workspaces') or []) if isinstance(w, dict) and w.get('id')]
                # Verification can return the consent URL before its GET populates
                # workspace cookies. Load it once through the same session.
                if not workspaces and target and target != self.last_url:
                    self.event('workspace_loading')
                    data = self.navigate(target)
                    continue
                if not workspaces:
                    raise ProtocolError('授权页面未返回工作区信息，请在浏览器核查', 'workspace_data_missing')
                personal = [w for w in workspaces if w.get('kind') in ('personal', 'individual')]
                choices = personal or workspaces
                if len(choices) != 1:
                    raise ProtocolError('授权页面存在多个可选工作区，请在浏览器选择', 'workspace_selection_required')
                self.last_url = target or AUTH + '/sign-in-with-chatgpt/codex/consent'
                self.event('workspace_selected')
                data = self.post('/api/accounts/workspace/select', {'workspace_id': choices[0]['id']})
            elif target:
                data = self.navigate(target)
            else:
                raise ProtocolError('遇到未支持的认证状态，请使用浏览器核查', 'unsupported_state')
        raise ProtocolError('登录步骤次数超限')

    def exchange(self, code):
        self.event('token_exchange')
        response = self.request('POST', AUTH + '/oauth/token', data={
            'grant_type': 'authorization_code', 'client_id': CLIENT_ID, 'code': code,
            'redirect_uri': REDIRECT, 'code_verifier': self.verifier},
            headers={'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json'})
        try:
            tokens = response.json()
        except ValueError:
            raise ProtocolError('OAuth token 响应无效') from None
        if not isinstance(tokens, dict) or not all(isinstance(tokens.get(k), str) and tokens[k]
                for k in ('access_token', 'refresh_token', 'id_token')):
            raise ProtocolError('OAuth 未返回完整的 access/refresh/id token')
        claims = decode_object(tokens['id_token'].split('.')[1] if tokens['id_token'].count('.') == 2 else '')
        if not isinstance(claims, dict) or claims.get('aud') not in (CLIENT_ID, [CLIENT_ID]):
            raise ProtocolError('OAuth id_token audience 不匹配')
        auth = claims.get('https://api.openai.com/auth') or {}
        if not isinstance(auth, dict) or not auth.get('chatgpt_account_id'):
            raise ProtocolError('OAuth token 缺少 ChatGPT account ID')
        credential = {k: tokens[k] for k in ('access_token', 'refresh_token', 'id_token')}
        credential.update(type='codex', email=self.entry.email, client_id=CLIENT_ID,
                          account_id=auth['chatgpt_account_id'], chatgpt_account_id=auth['chatgpt_account_id'])
        for claim, field in (('chatgpt_user_id', 'chatgpt_user_id'), ('user_id', 'user_id'),
                             ('chatgpt_plan_type', 'plan_type')):
            if isinstance(auth.get(claim), str) and auth[claim]:
                credential[field] = auth[claim]
        expires = tokens.get('expires_in')
        if type(expires) in (int, float) and 0 < expires < 366 * 86400:
            credential['expired'] = datetime.fromtimestamp(time.time() + expires, timezone.utc).isoformat()
            credential['expires_at'] = credential['expired']
            credential['expires_in'] = expires
        credential['last_refresh'] = datetime.now(timezone.utc).isoformat()
        verify_login_identity(credential, self.entry.email)
        self.event('identity_verified')
        return credential


def login(entry, proxy_url, country_code='', timeout=600, mail_timeout=180, stop_event=None,
          on_step=None, *, expected_exit_ip='', on_network=None, ipv4_only=False):
    session = mailbox = None
    deadline = time.monotonic() + timeout
    def remaining():
        if stop_event is not None and stop_event.is_set():
            raise BatchStopped('任务已停止')
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise ProtocolError('本地协议登录超时')
        return seconds
    def step(stage):
        remaining()
        if on_step:
            on_step(stage)
    try:
        step('network_checking')
        session, fingerprint = make_session(proxy_url, country_code, expected_exit_ip=expected_exit_ip,
                                            timeout=remaining(), stop_event=stop_event, ipv4_only=ipv4_only)
        remaining()
        if on_network:
            on_network(network_details(fingerprint, 'matched'))
        if entry.mail_url:
            mailbox = MailboxAPI(entry.mail_url, entry.email, stop_event=stop_event)
        credential = LoginFlow(entry, session, fingerprint, mailbox=mailbox, timeout=remaining(),
                               mail_timeout=mail_timeout, stop_event=stop_event, on_step=step).run()
        step('network_verifying')
        final = detect_exit(session, fingerprint['exit_ip'], fingerprint['country_code'], remaining(), stop_event)
        remaining()
        if final['timezone'] != fingerprint['timezone']:
            raise ProtocolError('登录后检测到出口时区变化，未返回凭证；请固定代理后重登', 'exit_timezone_changed')
        if on_network:
            on_network(network_details(fingerprint, 'verified'))
        step('login_verified')
        return credential
    except MailboxError as error:
        if stop_event is not None and stop_event.is_set():
            raise BatchStopped('任务已停止') from None
        raise ProtocolError(str(error), 'mailbox') from None
    except ImportError:
        raise ProtocolError('缺少本地协议依赖，请运行 install_local_login.cmd') from None
    except ApiError:
        raise
    except Exception:
        raise ProtocolError('本地协议运行失败，请核对依赖版本或使用浏览器核查') from None
    finally:
        if mailbox:
            mailbox.close()
        if session:
            session.close()
            cache = getattr(session, '_sentinel_sdk_dir', None)
            if cache:
                cache.cleanup()
