#!/usr/bin/env python3
"""Local Codex protocol login with mailbox OTP, proxy selection and Sub2API import. Python 3.10+."""
import argparse
import base64
import csv
import getpass
import ipaddress
import json
import math
import os
import re
import sys
import time
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit, quote
from urllib.request import ProxyHandler, build_opener

from proxy_report import ApiError, Client, NoRedirect, SHANGHAI, now, safe_csv

LOGIN = '/api/v1/admin/account-ops/token-guard/two-fa-login'
IMPORT = '/api/v1/admin/accounts/import/codex-session'
OPS = '/api/v1/admin/account-ops/token-guard-v2'
DEFAULT_GROUPS = ['GPT X20', '\u5168\u6a21\u578b\u4e0d\u964d\u667a\u5206\u7ec4']
EMAIL_RE = re.compile(r'[^\s@()<>\[\],;]+@[^\s@()<>\[\],;]+\.[^\s@()<>\[\],;]+')
REPORT_FIELDS = ['time', 'email', 'status', 'account_id', 'proxy_id', 'proxy_name', 'exit_ip',
                 'latency_ms', 'relaxed_latency', 'group_ids', 'job_id', 'login_verified',
                 'existing_name', 'existing_emails', 'matched_by', 'message']


@dataclass
class Entry:
    email: str
    password: str = field(repr=False)
    mfa_secret: str = field(repr=False)
    mail_url: str = field(default='', repr=False)


class HaltBatch(ApiError):
    """Do not start more accounts while a side effect is uncertain."""


class NoProxyAvailable(ApiError):
    """Stop the batch when no unused IP satisfies the remaining constraints."""


class BatchStopped(ApiError):
    """Finish submitted requests without starting more login/import operations."""


class SafeClient(Client):
    def __init__(self, *args, secrets=(), direct=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.direct = direct
        if direct:
            self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.secrets = [s for s in secrets if s]

    def clean(self, message):
        text = str(message)
        for secret in [*self.secrets, self.password, self.token]:
            if secret:
                text = text.replace(secret, '[REDACTED]')
        return text[:600]

    def request(self, *args, **kwargs):
        try:
            return super().request(*args, **kwargs)
        except ApiError as exc:
            raise ApiError(self.clean(exc), exc.status) from None


def parse_entries(text):
    entries, seen = [], set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('----')
        if len(parts) not in (2, 3, 4):
            raise ApiError(f'Line {number}: expected email----password----2FA_SECRET[----mail_url], or email----mail_url')
        parts = [x.strip() for x in parts]
        if len(parts) == 2:
            email, mail_url = parts
            password, secret = '', ''
        else:
            email, password, secret = parts[:3]
            mail_url = parts[3] if len(parts) == 4 else ''
        email = email.lower()
        secret = re.sub(r'\s+', '', secret).upper()
        if not EMAIL_RE.fullmatch(email) or (not password and not mail_url) or (not secret and not mail_url):
            raise ApiError(f'Line {number}: missing or invalid login fields')
        if secret:
            try:
                decoded = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
            except (ValueError, base64.binascii.Error):
                raise ApiError(f'Line {number}: 2FA secret must be Base32, not a six-digit code') from None
            if len(decoded) < 10:
                raise ApiError(f'Line {number}: 2FA secret is too short')
        if mail_url:
            from mailbox_api import validate_url, MailboxError
            try:
                validate_url(mail_url, email)
            except MailboxError:
                raise ApiError(f'Line {number}: invalid mailbox API URL or recipient mismatch') from None
        if email in seen:
            raise ApiError(f'Line {number}: duplicate email in input')
        seen.add(email)
        entries.append(Entry(email, password, secret, mail_url))
    if not 1 <= len(entries) <= 100:
        raise ApiError('Supply 1..100 accounts per batch')
    return entries


def account_emails(account):
    found = set()
    for source in (account, account.get('credentials') or {}, account.get('extra') or {}):
        for key in ('email', 'email_address', 'login_email', 'name'):
            value = source.get(key)
            if isinstance(value, str):
                found.update(match.group(0).lower() for match in EMAIL_RE.finditer(value))
    return found


def list_accounts(client, search=None):
    accounts, seen, page, expected = [], set(), 1, None
    while True:
        params = dict(page=page, page_size=100, platform='openai', sort_by='id', sort_order='desc')
        if search:
            params['search'] = search
        query = urlencode(params)
        data = client.request('GET', '/api/v1/admin/accounts?' + query)
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            raise ApiError('Invalid accounts pagination response')
        total = data.get('total')
        if type(total) is not int or total < 0 or (expected is not None and expected != total):
            raise ApiError('Accounts changed during pagination; rerun')
        expected = total
        for account in data['items']:
            aid = account.get('id')
            if type(aid) is not int or aid in seen:
                raise ApiError('Invalid or duplicate account in pagination')
            seen.add(aid)
            accounts.append(account)
        if len(accounts) == total:
            return accounts
        if not data['items'] or len(accounts) > total:
            raise ApiError('Incomplete accounts pagination')
        page += 1


def existing_account(client, email):
    matches = [a for a in list_accounts(client, search=email) if email in account_emails(a)]
    return matches[0] if matches else None


def parse_group_ids(values):
    text = values if isinstance(values, str) else ' '.join(map(str, values))
    tokens = re.split(r'[\s,\uff0c]+', text.strip())
    if not tokens or any(not token.isascii() or not token.isdecimal() or int(token) < 1 for token in tokens):
        raise ApiError('Group IDs must be positive integers separated by spaces or commas')
    return sorted({int(token) for token in tokens})


def resolve_groups(client, names, group_ids=None):
    groups = client.request('GET', '/api/v1/admin/groups/all?platform=openai')
    if not isinstance(groups, list):
        raise ApiError('Invalid group list')
    if group_ids is not None:
        requested = parse_group_ids(group_ids)
        for gid in requested:
            matches = [g for g in groups if type(g.get('id')) is int and g['id'] == gid
                       and g.get('status') == 'active' and g.get('platform') == 'openai']
            if len(matches) != 1:
                raise ApiError(f'OpenAI group ID missing, inactive or ambiguous: {gid}')
        return requested
    ids = []
    for name in names:
        matches = [g for g in groups if g.get('name') == name and g.get('status') == 'active'
                   and g.get('platform') == 'openai']
        if len(matches) != 1 or type(matches[0].get('id')) is not int:
            raise ApiError(f'Group missing, inactive or ambiguous: {name}')
        ids.append(matches[0]['id'])
    return sorted(set(ids))


def selected_groups(client, args):
    ids = getattr(args, 'group_ids', None)
    if ids is not None:
        return resolve_groups(client, args.groups, group_ids=ids)
    return resolve_groups(client, args.groups)


def normalize_proxy_name(value):
    return ''.join(char for char in unicodedata.normalize('NFKC', value).casefold() if char.isalnum())


def proxy_name_matches(name, query):
    if not query:
        return True
    tokens = [normalize_proxy_name(token) for token in query.split()]
    tokens = [token for token in tokens if token]
    normalized = normalize_proxy_name(name or '')
    return bool(tokens) and all(token in normalized for token in tokens)


def count(value):
    return value if type(value) is int and value >= 0 else None


def latency(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def active(proxy):
    if proxy.get('status') != 'active' or count(proxy.get('account_count')) is None:
        return False
    expires = proxy.get('expires_at')
    if expires:
        try:
            expiry = datetime.fromisoformat(expires.replace('Z', '+00:00'))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                return False
        except (ValueError, TypeError):
            return False
    return True


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip())) if isinstance(value, str) else None
    except ValueError:
        return None


def occupancy(proxies, selected, exit_ip, virtual=None):
    # Account limits apply to a reported exit IP even if multiple proxy IDs use it.
    related = [p for p in proxies if normalize_ip(p.get('ip_address')) == exit_ip or p['id'] == selected['id']]
    counts = [count(p.get('account_count')) for p in related]
    if any(n is None for n in counts):
        return None
    return sum(counts) + (virtual or {}).get(exit_ip, 0)


class ProxyPicker:
    def __init__(self, client, max_per_ip, threshold, journal, virtual=None, name_filter=None):
        self.client, self.max_per_ip, self.threshold = client, max_per_ip, threshold
        self.journal, self.virtual = journal, virtual
        self.name_filter = (name_filter or '').strip()
        if self.name_filter and not normalize_proxy_name(self.name_filter):
            raise ApiError('Proxy name filter must contain letters, numbers or Chinese characters')
        self.proxy_owners = {}
        self.ip_owners = {}

    def available(self, proxy_id, exit_ip, owner):
        # Only the same account can revisit its own reserved proxy/IP during recheck.
        for key, owners in ((proxy_id, self.proxy_owners), (exit_ip, self.ip_owners)):
            if key in owners and (owner is None or owners[key] != owner):
                return False
        return True

    def reserve(self, chosen, owner):
        if owner is not None:
            if not self.available(chosen['proxy_id'], chosen['exit_ip'], owner):
                raise NoProxyAvailable('Proxy or exit IP was already reserved for another account')
            self.proxy_owners[chosen['proxy_id']] = owner
            self.ip_owners[chosen['exit_ip']] = owner
            self.journal('proxy_reserved', email=owner, **chosen)
        return chosen

    def choose(self, owner=None):
        proxies = self.client.list_proxies(100)
        candidates = [p for p in proxies if active(p) and p['account_count'] < self.max_per_ip
                      and proxy_name_matches(p.get('name'), self.name_filter)]
        def rank(p):
            ms = latency(p.get('latency_ms'))
            return (ms is None or ms >= self.threshold, p['account_count'], ms if ms is not None else math.inf, p['id'])
        candidates.sort(key=rank)
        fallback = []
        for candidate in candidates:
            ip = normalize_ip(candidate.get('ip_address'))
            if not self.available(candidate['id'], ip, owner):
                continue
            used = occupancy(proxies, candidate, ip, self.virtual) if ip else None
            if ip and (used is None or used >= self.max_per_ip):
                continue
            try:
                result = self.client.request('POST', f"/api/v1/admin/proxies/{candidate['id']}/test")
            except ApiError as exc:
                if exc.status in (401, 403):
                    raise
                self.journal('proxy_test_error', proxy_id=candidate['id'], message=self.client.clean(exc))
                continue
            if not isinstance(result, dict) or result.get('success') is not True:
                self.journal('proxy_failed', proxy_id=candidate['id'])
                continue
            ms = latency(result.get('latency_ms'))
            ip = normalize_ip(result.get('ip_address') or candidate.get('ip_address'))
            if ms is None or not ip:
                self.journal('proxy_invalid_test', proxy_id=candidate['id'])
                continue
            if not self.available(candidate['id'], ip, owner):
                self.journal('proxy_exit_already_reserved', proxy_id=candidate['id'], exit_ip=ip)
                continue
            candidate['ip_address'] = ip
            used = occupancy(proxies, candidate, ip, self.virtual)
            if used is None or used >= self.max_per_ip:
                continue
            chosen = dict(proxy_id=candidate['id'], proxy_name=candidate.get('name', ''), exit_ip=ip, latency_ms=ms,
                          relaxed_latency=ms >= self.threshold, occupancy_before=used)
            self.journal('proxy_test_ok', **chosen)
            if ms < self.threshold:
                return self.reserve(chosen, owner)
            fallback.append(chosen)
        if fallback:
            return self.reserve(min(fallback, key=lambda p: (p['latency_ms'], p['occupancy_before'], p['proxy_id'])), owner)
        suffix = f'; required proxy name: {self.name_filter}' if self.name_filter else ''
        raise NoProxyAvailable('No unused, reachable, active, unexpired exit IP with free capacity; IP uniqueness and account limit were NOT relaxed' + suffix)

    def recheck(self, chosen, owner=None):
        proxies = self.client.list_proxies(100)
        selected = next((p for p in proxies if p['id'] == chosen['proxy_id']), None)
        if selected is None or not active(selected):
            raise ApiError('Chosen proxy became unavailable before import')
        if not proxy_name_matches(selected.get('name'), self.name_filter):
            return self.choose(owner)
        result = self.client.request('POST', f"/api/v1/admin/proxies/{selected['id']}/test")
        if not isinstance(result, dict) or result.get('success') is not True:
            raise ApiError('Chosen proxy failed the pre-import connectivity test')
        ms = latency(result.get('latency_ms'))
        ip = normalize_ip(result.get('ip_address') or selected.get('ip_address'))
        if ms is None or not ip:
            raise ApiError('Invalid pre-import latency/IP result')
        if not self.available(selected['id'], ip, owner):
            return self.choose(owner)
        used = occupancy(proxies, selected, ip, self.virtual)
        if used is None or used >= self.max_per_ip:
            raise ApiError('Chosen IP filled while login was running')
        # Re-evaluate every candidate if a formerly fast proxy became slow.
        if ms >= self.threshold:
            return self.choose(owner)
        return self.reserve(dict(proxy_id=selected['id'], proxy_name=selected.get('name', ''), exit_ip=ip, latency_ms=ms,
                                 relaxed_latency=False, occupancy_before=used), owner)


def credential_identity(credential):
    """Read returned token claims for identity consistency; this is not signature verification."""
    if not isinstance(credential, dict):
        raise HaltBatch('Expected one credential object for one login')
    emails, account_ids, user_ids = set(), set(), set()
    for name in ('id_token', 'access_token'):
        token = credential.get(name)
        if not isinstance(token, str) or token.count('.') != 2:
            continue
        segment = token.split('.')[1]
        try:
            claims = json.loads(base64.urlsafe_b64decode(segment + '=' * ((-len(segment)) % 4)))
        except (ValueError, UnicodeError, base64.binascii.Error):
            raise HaltBatch('Login returned a malformed token; identity could not be checked') from None
        if not isinstance(claims, dict):
            raise HaltBatch('Login returned invalid token claims')
        profile = claims.get('https://api.openai.com/profile') or {}
        auth = claims.get('https://api.openai.com/auth') or {}
        for email in (claims.get('email'), profile.get('email') if isinstance(profile, dict) else None):
            if isinstance(email, str) and EMAIL_RE.fullmatch(email.strip()):
                emails.add(email.strip().lower())
        if isinstance(auth, dict):
            for key, target in (('chatgpt_account_id', account_ids), ('chatgpt_user_id', user_ids)):
                value = auth.get(key)
                if isinstance(value, str) and value:
                    target.add(value)
    for key in ('account_id', 'chatgpt_account_id'):
        value = credential.get(key)
        if isinstance(value, str) and value:
            account_ids.add(value)
    if len(account_ids) > 1 or len(user_ids) > 1:
        raise HaltBatch('Returned credential contains inconsistent upstream account/user IDs')
    return dict(token_emails=sorted(emails), account_ids=sorted(account_ids), user_ids=sorted(user_ids))


def verify_login_identity(credential, requested_email):
    identity = credential_identity(credential)
    if not identity['token_emails']:
        raise HaltBatch('Login task succeeded but the returned token email could not be verified')
    if set(identity['token_emails']) != {requested_email.lower()}:
        raise HaltBatch('Returned token email differs from requested email: ' + ', '.join(identity['token_emails']))
    metadata_email = credential.get('email')
    if isinstance(metadata_email, str) and metadata_email.strip().lower() != requested_email.lower():
        raise HaltBatch('Returned credential email differs from requested email')
    return identity


def login_credential(client, entry, wait_seconds, poll_seconds, journal):
    try:
        job = client.request('POST', LOGIN, dict(email=entry.email, password=entry.password,
                                               mfa_secret=entry.mfa_secret, credential_target='operations'))
    except ApiError as exc:
        if exc.status is None or (exc.status is not None and exc.status >= 500):
            raise HaltBatch('Login submission outcome unknown; inspect site jobs before rerunning') from None
        raise
    job_id = job.get('id') if isinstance(job, dict) else None
    if not isinstance(job_id, (str, int)) or isinstance(job_id, bool) or not str(job_id):
        raise HaltBatch('Login submission returned no job ID; inspect site jobs before rerunning')
    job_id = str(job_id)
    journal('login_submitted', email=entry.email, job_id=job_id)
    path = LOGIN + '/' + quote(job_id, safe='')
    deadline = time.monotonic() + wait_seconds
    try:
        while True:
            state = client.request('GET', path)
            if not isinstance(state, dict):
                raise HaltBatch('Invalid login task response; see job_id in journal')
            status = state.get('status')
            if status == 'succeeded':
                credential = state.get('credential')
                if not isinstance(credential, (dict, list)) or not credential:
                    raise ApiError('Login succeeded but returned no credential')
                identity = verify_login_identity(credential, entry.email)
                journal('login_verified', email=entry.email, job_id=job_id, identity=identity)
                return credential
            if status in ('failed', 'cancelled', 'canceled', 'expired'):
                detail = next((state.get(key) for key in
                               ('error_message', 'failure_reason', 'reason', 'message', 'detail', 'error')
                               if isinstance(state.get(key), str) and state.get(key)), '')
                nested = state.get('error')
                if not detail and isinstance(nested, dict):
                    detail = nested.get('message') if isinstance(nested.get('message'), str) else ''
                code = state.get('error_code')
                safe_detail = client.clean(detail)
                journal('login_failed', email=entry.email, job_id=job_id, status=status,
                        message=safe_detail, error_code=client.clean(code) if code is not None else '',
                        response_fields=sorted(state))
                suffix = ': ' + safe_detail if safe_detail else ''
                raise ApiError('Login task ended with status ' + status + suffix)
            if status not in ('running', 'pending', 'queued'):
                raise HaltBatch('Unknown login task status; see job_id in journal')
            if time.monotonic() >= deadline:
                raise HaltBatch('Login task timed out; cleanup was requested, see job_id in journal')
            time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))
    finally:
        # Matches the page: discard the temporary login task, never log its credential.
        try:
            client.request('DELETE', path)
        except ApiError:
            journal('login_cleanup_failed', email=entry.email, job_id=job_id)


def perform_login(client, entry, args, journal, chosen=None, stop_event=None):
    engine = getattr(args, 'login_engine', 'backend')
    if engine == 'local':
        from local_login_service import login_local
        return login_local(client, entry, chosen, args, journal, stop_event)
    if entry.mail_url or not entry.password or not entry.mfa_secret:
        raise ApiError('邮箱 API 自动取码需要选择本地协议登录')
    return login_credential(client, entry, args.job_timeout, args.poll_interval, journal)


def import_payload(credential, entry, chosen, group_ids, models=None):
    body = dict(initialize_openai_two_fa=bool(entry.mfa_secret), content=json.dumps(credential), name=entry.email,
                notes=None, proxy_id=chosen['proxy_id'], concurrency=10, priority=1,
                rate_multiplier=1, group_ids=group_ids, expires_at=None,
                auto_pause_on_expired=True, credential_extras={},
                extra={'cost_multiplier': 0.1, 'openai_request_timezone': chosen.get('timezone') or 'Asia/Singapore',
                       'openai_oauth_responses_websockets_v2_mode': 'off',
                       'openai_oauth_responses_websockets_v2_enabled': False},
                update_existing=False, skip_existing=True)
    if models:
        body['credential_extras']['model_mapping'] = {model: model for model in models}
    return body


def import_new(client, entry, credential, chosen, group_ids, models, journal):
    try:
        data = client.request('POST', IMPORT, import_payload(credential, entry, chosen, group_ids, models))
    except ApiError as exc:
        if exc.status is None or (exc.status is not None and exc.status >= 500):
            raise HaltBatch('Import outcome unknown; inspect accounts before rerunning; POST was not retried') from None
        raise
    if not isinstance(data, dict) or data.get('failed', 0) != 0:
        raise HaltBatch('Import failed or returned unexpected results; inspect accounts before rerunning')
    created = [r for r in data.get('items', []) if r.get('action') == 'created' and type(r.get('account_id')) is int]
    if data.get('created') == 0 and data.get('skipped', 0) > 0:
        skipped = [r['account_id'] for r in data.get('items', []) if r.get('action') == 'skipped' and type(r.get('account_id')) is int and r['account_id'] > 0]
        journal('import_skipped', email=entry.email, skipped=data.get('skipped'), account_ids=skipped)
        if data.get('skipped') != 1 or data.get('updated', 0) or len(skipped) != 1:
            raise HaltBatch('Import skipped without one verified existing account ID; this does not prove the account exists')
        account_id = skipped[0]
        existing = client.request('GET', f'/api/v1/admin/accounts/{account_id}')
        if not isinstance(existing, dict) or existing.get('id') != account_id or existing.get('platform') != 'openai':
            raise HaltBatch('Import skip did not resolve to a readable OpenAI account')
        incoming = credential_identity(credential)
        stored = existing.get('credentials') or {}
        stored_id = stored.get('chatgpt_account_id') or stored.get('account_id')
        stored_user = stored.get('chatgpt_user_id')
        if incoming['account_ids'] and stored_id:
            if stored_id not in incoming['account_ids']:
                raise HaltBatch('Import skip matched a different upstream account ID; existing account was not changed')
            if incoming['user_ids'] and stored_user and stored_user not in incoming['user_ids']:
                raise HaltBatch('Import skip matched a different upstream user ID; existing account was not changed')
            matched_by = 'upstream_account_and_user_id' if incoming['user_ids'] and stored_user else 'upstream_account_id'
        elif entry.email in account_emails(existing):
            matched_by = 'email'
        else:
            raise HaltBatch('Import skip account identity could not be verified; existing account was not changed')
        details = dict(account_id=account_id, existing_name=existing.get('name', ''),
                       existing_emails=sorted(account_emails(existing)), matched_by=matched_by)
        journal('existing_identity_match', email=entry.email, **details)
        return dict(status='skipped_existing_identity', **details,
                    message=f'Existing upstream identity matched account {account_id}: {details["existing_name"]}; existing name, email, proxy and groups were kept')
    if data.get('created') != 1 or len(created) != 1 or data.get('updated', 0):
        raise HaltBatch('Unexpected import counts; inspect accounts before rerunning')
    account_id = created[0]['account_id']
    journal('account_created', email=entry.email, account_id=account_id, **chosen)
    account = client.request('GET', f'/api/v1/admin/accounts/{account_id}')
    if account.get('proxy_id') != chosen['proxy_id'] or not set(group_ids).issubset(account.get('group_ids') or []):
        raise HaltBatch('Account was created but proxy/group readback did not match; see journal account_id')
    try:
        config = dict(account_id=account_id, login_email=entry.email,
                      credential_mode='password_totp' if entry.mfa_secret else 'email_otp_url',
                      proxy_source='account', password=entry.password,
                      totp_secret=entry.mfa_secret, enabled=True, auto_relogin_enabled=True)
        if entry.mail_url:
            config['otp_url'] = entry.mail_url
        client.request('POST', OPS + '/accounts', config)
    except ApiError:
        raise HaltBatch('Account was created but encrypted credential setup failed; see journal account_id; do not reimport') from None
    # Verify the IP occupancy after the account write as other admins can change it concurrently.
    proxies = client.list_proxies(100)
    selected = next((p for p in proxies if p['id'] == chosen['proxy_id']), None)
    used = occupancy(proxies, selected, chosen['exit_ip']) if selected else None
    journal('account_complete', email=entry.email, account_id=account_id, **chosen)
    return dict(status='created', account_id=account_id, occupancy_after=used,
                message='Imported and encrypted login credentials saved')


@contextmanager
def batch_lock(directory):
    path = directory / '.batch_login.lock'
    with path.open('a+b') as handle:
        if path.stat().st_size == 0:
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ApiError('Another batch is running in this script directory') from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def restore_reservations(picker, paths):
    for path in paths:
        for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
            event = json.loads(line)
            if event.get('event') == 'proxy_reserved':
                chosen = dict(proxy_id=event['proxy_id'], exit_ip=event['exit_ip'])
                picker.reserve(chosen, event['email'])


class LockedPicker:
    def __init__(self, picker):
        self.picker = picker
        self.lock = threading.RLock()

    def choose(self, owner=None):
        with self.lock:
            return self.picker.choose(owner)

    def recheck(self, chosen, owner=None):
        with self.lock:
            return self.picker.recheck(chosen, owner)


def run_batch_parallel(client, entries, args, journal, save_row, *, stop_event=None):
    client.request('GET', '/api/v1/settings/public?timezone=Asia%2FShanghai', authenticated=False)
    groups = selected_groups(client, args)
    print('Target group IDs: ' + ','.join(map(str, groups)), flush=True)
    io_lock = threading.RLock()
    stop = stop_event if stop_event is not None else threading.Event()
    def locked_journal(event, **data):
        with io_lock:
            journal(event, **data)
    def locked_save(row):
        with io_lock:
            save_row(row)
    picker = ProxyPicker(client, args.max_per_ip, args.max_latency, locked_journal,
                         name_filter=getattr(args, 'proxy_name', None))
    restore_reservations(picker, getattr(args, 'resume_journal', []))
    shared_picker = LockedPicker(picker)
    def worker(entry):
        local = SafeClient(client.base_url, client.email, client.password, client.token,
                           client.timeout, secrets=client.secrets, direct=client.direct)
        return run_batch(local, [entry], args, locked_journal, locked_save,
                         group_ids=groups, shared_picker=shared_picker,
                         stop_event=stop, progress=False)
    rows, iterator = [], iter(entries)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(worker, entry) for entry in
                   [next(iterator, None) for _ in range(min(args.workers, len(entries)))]
                   if entry is not None}
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                try:
                    completed = future.result()
                except BaseException:
                    stop.set()
                    raise
                rows.extend(completed)
                for row in completed:
                    print(f'[{len(rows)}/{len(entries)}] {row["email"]}: {row["status"]}', flush=True)
            if not stop.is_set():
                for _ in done:
                    entry = next(iterator, None)
                    if entry is not None:
                        pending.add(pool.submit(worker, entry))
    order = {entry.email: i for i, entry in enumerate(entries)}
    return sorted(rows, key=lambda row: order[row['email']])


def run_batch(client, entries, args, journal, save_row, *, group_ids=None,
              shared_picker=None, stop_event=None, progress=True):
    if group_ids is None:
        client.request('GET', '/api/v1/settings/public?timezone=Asia%2FShanghai', authenticated=False)
        group_ids = selected_groups(client, args)
        print('Target group IDs: ' + ','.join(map(str, group_ids)), flush=True)
    groups = group_ids
    virtual = {} if args.dry_run else None
    picker = shared_picker or ProxyPicker(client, args.max_per_ip, args.max_latency, journal, virtual,
                                         name_filter=getattr(args, 'proxy_name', None))
    if shared_picker is None:
        restore_reservations(picker, getattr(args, 'resume_journal', []))
    rows = []
    encryption_checked = False
    for index, entry in enumerate(entries, 1):
        if stop_event is not None and stop_event.is_set():
            break
        row = dict(time=now(), email=entry.email, group_ids=groups, login_verified=False)
        stage = 'precheck'
        try:
            if getattr(args, 'login_only', False):
                stage = 'login'
                chosen = None
                if getattr(args, 'login_engine', 'backend') == 'local':
                    chosen = picker.choose(entry.email)
                    row.update(chosen)
                credential = perform_login(client, entry, args, journal, chosen, stop_event)
                credential = None
                row['login_verified'] = True
                row.update(status='login_verified', message='Login succeeded; no account imported, updated, or rebound')
            else:
                existing = existing_account(client, entry.email)
                if existing:
                    row.update(status='skipped_existing', account_id=existing['id'],
                               message='Existing account left unchanged (including error/inactive accounts)')
                else:
                    if not encryption_checked:
                        enc = client.request('GET', OPS + '/encryption')
                        if not isinstance(enc, dict) or enc.get('configured') is not True:
                            raise HaltBatch('Configure credential encryption on the site before importing')
                        encryption_checked = True
                    chosen = picker.choose(entry.email)
                    row.update(chosen)
                    if args.dry_run:
                        virtual[chosen['exit_ip']] = virtual.get(chosen['exit_ip'], 0) + 1
                        row.update(status='planned', message='No login or account import was submitted')
                    else:
                        if stop_event is not None and stop_event.is_set():
                            raise BatchStopped('Batch stopped before login')
                        stage = 'login'
                        credential = perform_login(client, entry, args, journal, chosen, stop_event)
                        row['login_verified'] = True
                        stage = 'preimport'
                        if stop_event is not None and stop_event.is_set():
                            raise BatchStopped('Batch stopped before import')
                        existing = existing_account(client, entry.email)
                        if existing:
                            row.update(status='skipped_race', account_id=existing['id'],
                                       message='Account appeared during login; existing account left unchanged')
                        else:
                            login_route = (chosen['proxy_id'], chosen['exit_ip'])
                            chosen = picker.recheck(chosen, entry.email)
                            if (getattr(args, 'login_engine', 'backend') == 'local'
                                    and login_route != (chosen['proxy_id'], chosen['exit_ip'])):
                                raise ApiError('登录后的代理出口发生变化；本次凭证未导入，请重新登录')
                            row.update(chosen)
                            if stop_event is not None and stop_event.is_set():
                                raise BatchStopped('Batch stopped before import')
                            stage = 'import'
                            outcome = import_new(client, entry, credential, chosen, groups, args.models, journal)
                            row.update(outcome)
                            if outcome.get('occupancy_after') is None or outcome.get('occupancy_after', 0) > args.max_per_ip:
                                if outcome['status'] == 'created':
                                    raise HaltBatch('Created account, but IP occupancy could not be verified or exceeded cap; inspect concurrent changes')
                        credential = None
        except ApiError as exc:
            row.update(status='stopped' if isinstance(exc, BatchStopped) else
                       'needs_review' if isinstance(exc, HaltBatch) or stage == 'import' else 'failed',
                       message=client.clean(exc))
            if isinstance(exc, (HaltBatch, NoProxyAvailable, BatchStopped)) or stage == 'import' or exc.status in (401, 403):
                if stop_event is not None:
                    stop_event.set()
                rows.append(row)
                save_row(row)
                if progress:
                    print(f'[{index}/{len(entries)}] {entry.email}: {row["status"]}', flush=True)
                break
        rows.append(row)
        save_row(row)
        if progress:
            print(f'[{index}/{len(entries)}] {entry.email}: {row["status"]}', flush=True)
    return rows


def interactive_options(args, input_fn=None):
    input_fn = input_fn or input
    default_groups = ','.join(map(str, args.group_ids)) if args.group_ids else ' / '.join(args.groups)
    while True:
        value = input_fn(f'分组 ID（空格或逗号分隔，留空使用 {default_groups}）: ').strip()
        if not value:
            break
        try:
            args.group_ids = parse_group_ids(value)
            break
        except ApiError as exc:
            print(str(exc))
    while True:
        value = input_fn(f'代理名称关键词（可选，留空使用 {args.proxy_name or "全部可用代理"}）: ').strip()
        if not value:
            break
        if normalize_proxy_name(value):
            args.proxy_name = value
            break
        print('代理名称请至少输入一个中文、字母或数字。')
    while True:
        value = input_fn(f'并发数量（1–8，留空使用 {args.workers}）: ').strip()
        if not value:
            break
        if value.isascii() and value.isdecimal() and 1 <= int(value) <= 8:
            args.workers = int(value)
            break
        print('并发数量请输入 1–8 的整数。')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', type=Path, help='UTF-8: email----password----2FA_SECRET[----mail_url], or email----mail_url')
    parser.add_argument('--base-url', default='https://www.caeakrma.top')
    parser.add_argument('--email', default=os.getenv('SUB2API_EMAIL', 'admin@sub2api.local'))
    group_options = parser.add_mutually_exclusive_group()
    group_options.add_argument('--groups', nargs='+', default=DEFAULT_GROUPS, help='Group names; use --group-ids to select by ID instead')
    group_options.add_argument('--group-ids', nargs='+', help='Active OpenAI group IDs, separated by spaces or commas; replaces default groups')
    parser.add_argument('--proxy-name', help='Match proxy name keywords (case-insensitive, partial match); only bind matching usable proxies')
    parser.add_argument('--interactive', action='store_true', help='Prompt for group IDs, optional proxy name and worker count')
    parser.add_argument('--max-per-ip', type=int, default=4, help='Final max accounts per reported exit IP (default 4, strictly less than 5)')
    parser.add_argument('--max-latency', type=float, default=300, help='Prefer latency strictly below this; relax latency only if none qualify')
    parser.add_argument('--timeout', type=float, default=120, help='HTTP timeout seconds')
    parser.add_argument('--job-timeout', type=float, default=600)
    parser.add_argument('--poll-interval', type=float, default=2)
    parser.add_argument('--login-engine', choices=('local', 'backend'), default='local',
                        help='Local Codex protocol login (default), or legacy backend two-fa-login')
    parser.add_argument('--mail-timeout', type=float, default=180, help='Mailbox API OTP wait seconds')
    parser.add_argument('--gateway', help='Optional local HTTP CONNECT gateway, host:port')
    parser.add_argument('--login-only', action='store_true', help='Validate login credentials, including existing accounts; do not import or modify accounts')
    parser.add_argument('--workers', type=int, default=1, choices=range(1, 9), help='Concurrent account tasks; default 1, maximum 8; dry-run remains serial')
    parser.add_argument('--resume-journal', type=Path, action='append', default=[], help='Preserve proxy/IP reservations from a previous interrupted batch')
    parser.add_argument('--direct', action='store_true', help='Connect to the admin site without the local system HTTP proxy')
    parser.add_argument('--dry-run', action='store_true', help='Check duplicates/groups/proxies; do not submit login/import')
    parser.add_argument('--models', nargs='+', help='Optional explicit model whitelist; otherwise backend defaults')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent / 'batch_results')
    args = parser.parse_args(argv)
    if args.group_ids is not None:
        try:
            args.group_ids = parse_group_ids(args.group_ids)
        except ApiError as exc:
            parser.error(str(exc))
    args.proxy_name = (args.proxy_name or '').strip()
    if args.proxy_name and not normalize_proxy_name(args.proxy_name):
        parser.error('--proxy-name must contain letters, numbers or Chinese characters')
    if args.login_only and args.dry_run:
        parser.error('--login-only and --dry-run cannot be combined')
    url = urlsplit(args.base_url)
    if url.scheme != 'https' or not url.netloc or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
        parser.error('--base-url must be an HTTPS origin')
    if args.max_per_ip < 1 or any(not math.isfinite(n) or n <= 0 for n in
                                (args.max_latency, args.timeout, args.job_timeout, args.poll_interval, args.mail_timeout)):
        parser.error('Limits and timeouts must be positive finite numbers')
    if args.poll_interval > 30:
        parser.error('--poll-interval must be <= 30 seconds')
    if args.interactive:
        interactive_options(args)
    return args


def main():
    args = parse_args()
    if args.file:
        text = args.file.read_text(encoding='utf-8-sig')
    else:
        text = getpass.getpass('Account line (hidden; supports mailbox API): ')
    entries = parse_entries(text)
    text = None
    token = os.getenv('SUB2API_TOKEN')
    password = None if token else os.getenv('SUB2API_PASSWORD') or getpass.getpass('Admin password (hidden): ')
    client = SafeClient(args.base_url, args.email, password, token, args.timeout,
                        secrets=[secret for entry in entries for secret in (entry.password, entry.mfa_secret, entry.mail_url)], direct=args.direct)
    if not token:
        client.login()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = args.output_dir / datetime.now(SHANGHAI).strftime('batch_%Y%m%d_%H%M%S_%f')
    journal_path = stem.with_suffix('.jsonl')
    csv_path = stem.with_suffix('.csv')
    summary_path = stem.with_suffix('.json')
    with batch_lock(Path(__file__).resolve().parent):
        with journal_path.open('w', encoding='utf-8') as log, csv_path.open('w', encoding='utf-8-sig', newline='') as table:
            writer = csv.DictWriter(table, fieldnames=REPORT_FIELDS, extrasaction='ignore')
            writer.writeheader()
            table.flush()
            def journal(event, **data):
                log.write(json.dumps(dict(time=now(), event=event, **data), ensure_ascii=False) + '\n')
                log.flush()
            def save_row(row):
                journal('result', **{k:v for k,v in row.items() if k != 'time'})
                writer.writerow({k:safe_csv(json.dumps(v) if isinstance(v, list) else v) for k,v in row.items() if k in REPORT_FIELDS})
                table.flush()
            runner = run_batch_parallel if args.workers > 1 and not args.dry_run else run_batch
            rows = runner(client, entries, args, journal, save_row)
    summary = dict(finished_at=now(), input_count=len(entries), processed_count=len(rows),
                   workers=args.workers if not args.dry_run else 1, proxy_name_filter=args.proxy_name,
                   created=sum(r['status']=='created' for r in rows),
                   login_verified=sum(bool(r.get('login_verified')) for r in rows),
                   skipped=sum(r['status'] in ('skipped_existing', 'skipped_race', 'skipped_existing_identity') for r in rows),
                   planned=sum(r['status']=='planned' for r in rows),
                   failed=sum(r['status'] in ('failed', 'needs_review') for r in rows))
    summary_path.write_text(json.dumps(dict(summary=summary, items=rows), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    print('CSV: ' + str(csv_path.resolve()))
    print('JSON: ' + str(summary_path.resolve()))
    print('Journal: ' + str(journal_path.resolve()))
    return 2 if summary['failed'] or len(rows) < len(entries) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ApiError, OSError, EOFError, UnicodeError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nInterrupted. Check the journal for job/account IDs before rerunning.', file=sys.stderr)
        sys.exit(130)
