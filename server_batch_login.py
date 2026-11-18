"""Server-side concurrent login/import with a capacity shared by actual exit IP.

Account objects arrive only on stdin. Run as root to read the Docker admin login,
write the protected route config, then drop privileges before authentication.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
from itertools import zip_longest
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import quote

import batch_login as batch
from protocol_login import login, make_session, network_details, ProtocolError
from relogin_service import Config


def allocate_routes(emails, routes, maximum=5):
    available = {}
    selected = {}
    for route in routes:
        ip = route['exit_ip']
        if ip not in available:
            available[ip] = maximum - route['occupancy']
    for email in emails:
        route = next((r for r in routes if available[r['exit_ip']] > 0), None)
        if route is None:
            raise ValueError('Not enough verified IP capacity')
        selected[email] = route
        available[route['exit_ip']] -= 1
    return selected


def proxy_url(proxy):
    auth = ''
    if proxy.get('username') or proxy.get('password'):
        auth = quote(proxy.get('username') or '', safe='') + ':' + quote(proxy.get('password') or '', safe='') + '@'
    host = proxy['host']
    if ':' in host:
        host = '[' + host + ']'
    return f"{proxy['protocol']}://{auth}{host}:{proxy['port']}"


def configure_assignment(config, entry, route):
    # A password/TOTP login can succeed without an email challenge. An absent
    # mailbox must stay absent rather than becoming an invalid empty URL.
    if entry.mail_url:
        config.setdefault('mailboxes', {})[entry.email] = entry.mail_url
    config.setdefault('account_proxies', {})[entry.email] = dict(
        proxy_url=route['proxy_url'], expected_exit_ip=route['exit_ip'], country_code='US')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ports', nargs='+', type=int, required=True)
    parser.add_argument('--group-ids', nargs='+', type=int, required=True)
    parser.add_argument('--workers', type=int, default=4, choices=range(1, 5))
    args = parser.parse_args()
    print_lock = threading.Lock()
    events = []
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    result_path = Path('/var/lib/sub2api-login') / ('batch-' + stamp + '.json')

    def emit(kind, **values):
        with print_lock:
            value = dict(type=kind, at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **values)
            events.append(value)
            print(json.dumps(value, ensure_ascii=True), flush=True)
            fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(events, stream, indent=2)

    source = json.load(sys.stdin)
    assert isinstance(source, list) and 1 <= len(source) <= 100
    env = dict(x.split('=', 1) for x in json.loads(subprocess.check_output(
        ['docker', 'inspect', 'sub2api']))[0]['Config']['Env'] if '=' in x)
    client = batch.SafeClient('http://127.0.0.1:8080', env['ADMIN_EMAIL'], env['ADMIN_PASSWORD'], '', 30, direct=True)
    client.login()
    env = None
    client.password = None
    config_path = Path('/etc/sub2api-login/relogin.json')
    config = json.loads(config_path.read_text())
    recovery_path = config_path.with_name('portal-rebind-state.json')
    recovery = json.loads(recovery_path.read_text()) if recovery_path.exists() else {}
    entries = []
    for row in source:
        original_email = row['email']
        state = recovery.get(original_email, {})
        if (state.get('remote_outcome') == 'changed' and state.get('new_email')
                and state.get('current_email') == state.get('new_email') and state.get('mailbox_url')):
            row['email'] = state['current_email']
            row['mail_url'] = state['mailbox_url']
            # The new identity replaces this reservation; do not count both aliases.
            if original_email != row['email']:
                config.get('account_proxies', {}).pop(original_email, None)
            emit('email_rebound', email=row['email'], original_email=original_email,
                 portal_status=state.get('status'))
        mail_url = row.get('mail_url') or config['mailboxes'].get(row['email'], '')
        entry = batch.parse_entries('----'.join((row['email'], row['password'], row['mfa_secret'], mail_url)))[0]
        row.clear()
        existing = batch.existing_account(client, entry.email)
        if existing:
            emit('skipped_existing', email=entry.email, account_id=existing['id'], proxy_id=existing.get('proxy_id'))
            continue
        entries.append(entry)
    source = None
    assert len({e.email for e in entries}) == len(entries)
    if not entries:
        emit('batch_complete', outcomes=[], result_path=str(result_path))
        return
    assert client.request('GET', batch.OPS + '/encryption')['configured'] is True
    existing_emails = set().union(*(batch.account_emails(a) for a in batch.list_accounts(client)))
    incoming_emails = {e.email for e in entries}
    reserved_routes = [route for email, route in config.get('account_proxies', {}).items()
                       if email not in existing_emails and email not in incoming_emails]
    groups = client.request('GET', '/api/v1/admin/groups/all')
    assert all(any(g['id'] == gid and g.get('status') == 'active' and g.get('platform') == 'openai' for g in groups) for gid in args.group_ids)
    proxies = client.list_proxies(100)
    candidates = []
    for port in args.ports:
        matches = [p for p in proxies if p['host'] == '172.19.0.1' and p['port'] == port]
        assert len(matches) == 1
        candidates.extend(matches)
    candidates.extend(sorted([p for p in proxies if p not in candidates and p['status'] == 'active'
        and 'dasho' in p.get('name', '').lower() and '美国' in p.get('name', '')
        and p.get('account_count') == 0 and isinstance(p.get('latency_ms'), (int, float)) and p['latency_ms'] < 300],
        key=lambda p: (p['latency_ms'], p['id'])))
    routes, seen_ips = [], set()
    for proxy in candidates:
        if proxy['status'] != 'active':
            continue
        try:
            tested = client.request('POST', f"/api/v1/admin/proxies/{proxy['id']}/test")
            if tested.get('success') is not True:
                emit('proxy_failed', proxy_id=proxy['id'])
                continue
            url = proxy_url(proxy)
            session, fp = make_session(url, expected_exit_ip=tested.get('ip_address') or '', ipv4_only=True)
            session.close()
            if fp['country_code'] != 'US':
                emit('proxy_wrong_country', proxy_id=proxy['id'])
                continue
            confirm, second = make_session(url, expected_exit_ip=fp['exit_ip'], ipv4_only=True)
            confirm.close()
            if fp['exit_ip'] in seen_ips:
                continue
            proxies = client.list_proxies(100)
            used = batch.occupancy(proxies, proxy, fp['exit_ip'])
            if used is not None:
                used += sum(r.get('expected_exit_ip') == fp['exit_ip'] for r in reserved_routes)
            if used is None or used >= 5:
                continue
            route = dict(proxy_id=proxy['id'], proxy_name=proxy['name'], proxy_url=url,
                         exit_ip=fp['exit_ip'], occupancy=used, latency_ms=tested.get('latency_ms'),
                         timezone=fp['timezone'])
            routes.append(route)
            seen_ips.add(fp['exit_ip'])
            emit('verified_route', **{k: v for k, v in route.items() if k != 'proxy_url'})
            if sum(5-r['occupancy'] for r in routes) >= len(entries):
                break
        except (batch.ApiError, ProtocolError) as error:
            emit('proxy_failed', proxy_id=proxy['id'], code=getattr(error, 'code', None) or 'proxy_check_failed')
    assignments = allocate_routes([e.email for e in entries], routes)
    backup = config_path.with_name('relogin-before-batch-' + stamp + '.json')
    shutil.copy2(config_path, backup)
    for entry in entries:
        route = assignments[entry.email]
        configure_assignment(config, entry, route)
        emit('assigned', email=entry.email, proxy_id=route['proxy_id'], exit_ip=route['exit_ip'])
    Config(**config).validate()
    config['ipv4_only'] = True
    config_path.write_text(json.dumps(config, indent=2))
    os.chmod(config_path, 0o640)
    subprocess.run(['systemctl', 'restart', 'sub2api-login.service'], check=True)
    import pwd
    service_user = pwd.getpwnam('sub2api-login')
    if result_path.exists():
        os.chown(result_path, service_user.pw_uid, service_user.pw_gid)
    os.setgroups([])
    os.setgid(service_user.pw_gid)
    os.setuid(service_user.pw_uid)
    # Parallel authentication; serialize imports so IP totals are rechecked before every write.
    import_lock = threading.Lock()
    per_ip = {r['exit_ip']: threading.BoundedSemaphore(2) for r in routes}
    stop = threading.Event()

    def worker(entry):
        route = assignments[entry.email]
        started = time.monotonic()
        stage = 'starting'
        credential = None
        local_client = batch.SafeClient(client.base_url, '', '', client.token, 30,
            direct=True, secrets=(entry.password, entry.mfa_secret, entry.mail_url))
        def step(value):
            nonlocal stage
            stage = value
            emit('login_progress', email=entry.email, stage=value, elapsed_seconds=round(time.monotonic()-started,2))
        try:
            with per_ip[route['exit_ip']]:
                if stop.is_set():
                    raise batch.BatchStopped('Batch stopped')
                emit('login_start', email=entry.email, proxy_id=route['proxy_id'], exit_ip=route['exit_ip'])
                credential = login(entry, route['proxy_url'], expected_exit_ip=route['exit_ip'],
                    timeout=600, mail_timeout=180, stop_event=stop, on_step=step, ipv4_only=True,
                    on_network=lambda network: emit('network', email=entry.email, proxy_id=route['proxy_id'], **network))
            batch.verify_login_identity(credential, entry.email)
            with import_lock:
                latest = local_client.list_proxies(100)
                selected = next(p for p in latest if p['id'] == route['proxy_id'])
                used = batch.occupancy(latest, selected, route['exit_ip'])
                if used is None or used >= 5:
                    raise batch.HaltBatch('Actual exit IP capacity changed; credential was not imported')
                check, fp = make_session(route['proxy_url'], expected_exit_ip=route['exit_ip'], ipv4_only=True)
                check.close()
                # Match the two accounts already imported for this user.
                chosen = {key: route[key] for key in ('proxy_id', 'proxy_name', 'exit_ip', 'latency_ms', 'timezone')}
                outcome = batch.import_new(local_client, entry, credential, chosen, args.group_ids, None,
                    lambda action, **values: emit(action, **values))
                if outcome.get('status') == 'created' and outcome.get('occupancy_after', 6) > 5:
                    raise batch.HaltBatch('IP occupancy changed after import')
            outcome.update(email=entry.email, proxy_id=route['proxy_id'], exit_ip=route['exit_ip'],
                           login_verified=True, elapsed_seconds=round(time.monotonic()-started,2))
        except Exception as error:
            if isinstance(error, batch.HaltBatch) or getattr(error, 'upstream_status', None) == 429:
                stop.set()
            outcome = dict(email=entry.email, status='needs_review' if isinstance(error,batch.HaltBatch) else 'failed',
                proxy_id=route['proxy_id'], exit_ip=route['exit_ip'], stage=stage,
                code=getattr(error,'code', None) or type(error).__name__,
                message=local_client.clean(error) if isinstance(error,batch.ApiError) else type(error).__name__,
                elapsed_seconds=round(time.monotonic()-started,2))
        finally:
            if isinstance(credential, dict):
                credential.clear()
        emit('account_result', **outcome)
        return outcome

    outcomes = []
    queues = [[entry for entry in entries if assignments[entry.email]['exit_ip'] == route['exit_ip']]
              for route in routes]
    ordered = [entry for turn in zip_longest(*queues) for entry in turn if entry is not None]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(worker, entry) for entry in ordered]
        for future in as_completed(futures):
            outcomes.append(future.result())
    emit('batch_complete', outcomes=outcomes, result_path=str(result_path), max_per_ip=5, workers=args.workers)


if __name__ == '__main__':
    main()
