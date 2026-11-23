# SPDX-License-Identifier: AGPL-3.0-only
"""Read OTPs from an explicitly supplied mailbox API, isolated from OAuth cookies."""
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit


class MailboxError(Exception):
    pass


CODE_FIELDS = ('code', 'otp', 'verification_code', 'verificationcode', 'verify_code')
TIME_FIELDS = ('received_at', 'receivedat', 'created_at', 'timestamp', 'date', 'ts', 'time')
PENDING_MARKERS = frozenset(('no_code', 'nocode', 'no_otp', 'none', 'null', 'pending',
                             'waiting', 'not_ready', 'not_found', 'notfound', 'empty'))
ERROR_MARKERS = frozenset(('unauthorized', 'forbidden', 'invalid_token', 'token_expired',
                           'expired_token', 'invalid_api_key', 'mailbox_not_found', 'mailbox_expired'))


def normalized_fields(value):
    fields = {}
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        key = key.casefold()
        if key in fields and fields[key] != item:
            return None
        fields[key] = item
    return fields


def reply_state(value, depth=0):
    """Separate an explicit pending reply from a failed mailbox API response.

    Never use a provider's error message in diagnostics: it can contain the
    mailbox URL, API credential, recipient or a previous verification code.
    """
    if not isinstance(value, dict) or depth > 8:
        return 'ready'
    fields = normalized_fields(value)
    if fields is None:
        return 'error'
    error = fields.get('error')
    statuses = [fields.get(key) for key in ('code', 'status', 'error_code')]
    if isinstance(error, dict):
        statuses.extend(error.get(key) for key in ('code', 'type'))
    elif isinstance(error, str):
        statuses.append(error)
    markers = {item.strip().casefold().replace('-', '_').replace(' ', '_')
               for item in statuses if isinstance(item, str)}
    if markers & ERROR_MARKERS:
        return 'error'
    empty_code = ('code' in fields and (fields['code'] is None or
                  isinstance(fields['code'], str) and not fields['code'].strip()))
    if markers & PENDING_MARKERS or empty_code:
        return 'error' if fields.get('retryable') is False else 'pending'
    if fields.get('success') is False or fields.get('ok') is False or error:
        return 'pending' if fields.get('retryable') is True else 'error'
    for key in ('data', 'result'):
        state = reply_state(fields.get(key), depth + 1)
        if state != 'ready':
            return state
    return 'ready'


def validate_url(url, email=''):
    try:
        p = urlsplit(url)
        valid = (p.scheme == 'https' and p.hostname and not p.username
                 and not p.password and not p.fragment and (p.port is None or 1 <= p.port <= 65535))
        if not valid or any(c.isspace() for c in url):
            raise ValueError()
        for key in ('e', 'email', 'address'):
            recipients = parse_qs(p.query).get(key, [])
            if email and any('@' in r and r.split(':', 1)[0].casefold() != email.casefold() for r in recipients):
                raise ValueError()
    except ValueError:
        raise MailboxError('邮箱 API 必须是 HTTPS 地址，且 URL 中的邮箱须与账号一致') from None
    return url


class Text(HTMLParser):
    def __init__(self, depth=0):
        super().__init__(convert_charrefs=True)
        self.parts, self.hidden = [], 0
        self.depth = depth
        self.cf_tag = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        encoded = attributes.get('data-cfemail', '')
        if not self.hidden and not self.cf_tag and tag in ('a', 'span') and 4 <= len(encoded) <= 2048:
            try:
                raw = bytes.fromhex(encoded)
                address = bytes(value ^ raw[0] for value in raw[1:]).decode('utf-8')
                if re.fullmatch(r'[^\s<>@]+@[^\s<>@]+', address):
                    self.parts.append(address)
                    self.cf_tag = tag
            except (ValueError, UnicodeError):
                pass
        if tag == 'iframe' and self.depth < 5:
            source = attributes.get('srcdoc')
            if source:
                self.parts.extend(['\n', text_content(source, self.depth + 1), '\n'])
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag in ('br', 'p', 'div', 'tr', 'td', 'li', 'h1', 'h2', 'hr'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag == self.cf_tag:
            self.cf_tag = None
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag in ('p', 'div', 'tr', 'td', 'li'):
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden and not self.cf_tag:
            self.parts.append(data)


def text_content(value, depth=0):
    parser = Text(depth)
    parser.feed(str(value))
    return unescape(''.join(parser.parts))


def timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value / 1000 if value > 10**12 else value
    if not isinstance(value, str) or not value:
        return None
    try:
        if re.fullmatch(r'\d{10}(?:\d{3})?', value):
            return timestamp(int(value))
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        # A date without an offset cannot be compared to the login epoch safely.
        # The mailbox snapshot still excludes old codes when the timezone is unknown.
        if dt.tzinfo is None:
            return None
        return dt.timestamp()
    except (ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class Message:
    code: str = field(repr=False)
    received: float | None = None
    identity: str = ''

    @property
    def key(self):
        return hashlib.sha256(f'{self.identity}|{self.received}|{self.code}'.encode()).hexdigest()


def extract_codes(value):
    text = text_content(value)
    if re.fullmatch(r'\s*\d{6}\s*', text):
        return {text.strip()}
    codes = set(re.findall(
        r'(?:verification\s+code|one[- ]time\s+(?:code|password)|your\s+(?:OpenAI\s+)?code|'
        r'code\s+is|验证码|验证代码)\s*(?:is|为|是)?\s*[:：\-]?\s*(\d{6})(?!\d)', text, re.I))
    if re.search(r'verification|OpenAI|ChatGPT|验证码', text, re.I):
        codes.update(re.findall(r'(?m)^\s*(\d{6})\s*$', text))
    return codes


def parse_messages(source, email):
    """Common JSON envelopes and WDMail HTML; never scan arbitrary JSON for six digits."""
    result = []

    def visit(obj, depth=0, inherited=None):
        if depth > 8:
            return
        if isinstance(obj, list):
            for item in obj[:500]:
                visit(item, depth + 1, inherited)
            return
        if not isinstance(obj, dict):
            if depth == 0 and isinstance(obj, (str, int)):
                for code in extract_codes(obj):
                    result.append(Message(code))
            return
        obj = normalized_fields(obj)
        if obj is None or reply_state(obj) != 'ready':
            return
        meta = dict(inherited or {})
        for key in ('to', 'recipient', 'email', 'address', *TIME_FIELDS):
            if obj.get(key) is not None:
                meta[key] = obj[key]
        recipients = [str(meta[k]) for k in ('to', 'recipient', 'email', 'address') if meta.get(k)]
        addresses = {a.casefold() for v in recipients for a in re.findall(r'[^\s<>" ,;]+@[^\s<>" ,;]+', v)}
        if addresses and email.casefold() not in addresses:
            return
        sender = str(obj.get('from') or obj.get('sender') or '')
        if sender and not re.search(r'(?:@|\.)openai\.com\b|\bOpenAI\b|\bChatGPT\b', sender, re.I):
            return
        received = next((t for k in TIME_FIELDS
                         if (t := timestamp(meta.get(k))) is not None), None)
        codes = set()
        for key in CODE_FIELDS:
            v = obj.get(key)
            if isinstance(v, (str, int)) and re.fullmatch(r'\d{6}', str(v)):
                codes.add(str(v))
        bodies = [str(obj[k]) for k in ('subject', 'text', 'body', 'html', 'content', 'message')
                  if isinstance(obj.get(k), str)]
        if bodies:
            codes.update(extract_codes('\n'.join(bodies)))
        if len(codes) == 1:
            result.append(Message(codes.pop(), received, str(obj.get('id') or obj.get('message_id') or '')))
        for key in ('data', 'messages', 'mails', 'emails', 'items', 'results', 'result'):
            if isinstance(obj.get(key), (dict, list)):
                visit(obj[key], depth + 1, meta)

    if isinstance(source, (dict, list, int)):
        visit(source)
    else:
        try:
            visit(json.loads(source))
        except (ValueError, TypeError):
            text = text_content(source)
            if re.fullmatch(r'\s*\d{6}\s*', text):
                result.append(Message(text.strip()))
            else:
                chunks = re.split(r'(?=发件人\s*[:：]|From\s*:)', text, flags=re.I)
                for chunk in chunks:
                    recipient = re.search(r'(?:邮箱|收件人|To)\s*[:：]\s*([^\s<>]+@[^\s<>]+)', chunk, re.I)
                    if not recipient or recipient.group(1).rstrip(',;，；').casefold() != email.casefold():
                        continue
                    if not re.search(r'OpenAI|ChatGPT', chunk, re.I):
                        continue
                    date = re.search(r'(?:时间|Date)\s*[:：]\s*([\d-]{10}[ T][\d:.]+(?:Z|[+-]\d\d:\d\d)?)', chunk, re.I)
                    codes = extract_codes(chunk)
                    if len(codes) == 1:
                        result.append(Message(codes.pop(), timestamp(date.group(1)) if date else None))
    return list({m.key: m for m in result}.values())


class MailboxAPI:
    def __init__(self, url, email, stop_event=None, poll_interval=3, session=None):
        self.url = validate_url(url, email)
        self.email = email
        self.stop = stop_event or threading.Event()
        self.interval = poll_interval
        if session is None:
            import requests
            session = requests.Session()
        self.session = session
        self.session.trust_env = False
        self.baseline, self.used = set(), set()

    def close(self):
        self.session.close()

    def read(self, timeout=12):
        if self.stop.is_set():
            raise MailboxError('任务已停止')
        deadline = time.monotonic() + timeout
        for attempt in range(3):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MailboxError('邮箱 API 读取超时')
                # A read-only GET may recover from a dropped connection within its original budget.
                with self.session.get(self.url, timeout=remaining,
                                      allow_redirects=False, stream=True) as response:
                    if response.status_code != 200:
                        raise MailboxError(f'邮箱 API 返回 HTTP {response.status_code}')
                    body = bytearray()
                    for chunk in response.iter_content(16384):
                        if self.stop.is_set():
                            raise MailboxError('任务已停止')
                        if time.monotonic() >= deadline:
                            raise MailboxError('邮箱 API 读取超时')
                        body.extend(chunk)
                        if len(body) > 2 * 1024 * 1024:
                            raise MailboxError('邮箱 API 响应超过 2 MiB')
                break
            except MailboxError:
                raise
            except Exception:
                remaining = deadline-time.monotonic()
                if attempt == 2 or remaining <= 0:
                    raise MailboxError('邮箱 API 连接失败；请检查链接和网络') from None
                self.stop.wait(min(.5*(attempt+1), remaining))
                if self.stop.is_set():
                    raise MailboxError('任务已停止') from None
        payload = body.decode('utf-8-sig', errors='replace')
        state = 'ready'
        try:
            state = reply_state(json.loads(payload))
        except ValueError:
            pass
        if state == 'error':
            raise MailboxError('邮箱 API 返回失败状态；请检查授权和邮箱配置')
        return parse_messages(payload, self.email)

    def snapshot(self, timeout=12):
        self.baseline.update(m.key for m in self.read(timeout))

    def wait_code(self, issued_after, timeout=180, resend=None, on_wait=None):
        deadline = time.monotonic() + timeout
        resent = False
        start = time.monotonic()
        while time.monotonic() < deadline:
            if self.stop.is_set():
                raise MailboxError('任务已停止')
            messages = self.read(min(12, max(0.1, deadline - time.monotonic())))
            candidates = [m for m in messages if m.key not in self.baseline and m.code not in self.used
                          and (m.received is None or issued_after - 10 <= m.received <= time.time() + 120)]
            if candidates:
                latest = max(m.received or 0 for m in candidates)
                codes = {m.code for m in candidates if (m.received or 0) == latest}
                if len(codes) == 1:
                    code = codes.pop()
                    self.used.add(code)
                    self.baseline.update(m.key for m in messages)
                    return code
            if resend and not resent and time.monotonic() - start >= 60:
                resend()
                resent = True
                if on_wait:
                    on_wait('email_otp_resent')
            self.stop.wait(min(self.interval, max(0, deadline - time.monotonic())))
        raise MailboxError('等待新邮箱验证码超时；旧验证码不会被重复提交')
