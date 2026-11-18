#!/usr/bin/env python3
"""Collect proxy account counts and server-measured latency (Python 3.9+)."""
import argparse
import csv
import getpass
from http.client import HTTPException
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

SHANGHAI = timezone(timedelta(hours=8))
FIELDS = [
    'tested_at', 'proxy_id', 'name', 'protocol', 'host', 'port', 'ip_address',
    'country', 'region', 'city', 'proxy_status', 'account_count',
    'previous_latency_ms', 'latency_ms', 'test_status', 'message',
]


class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base_url, email, password, token, timeout):
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.password = password
        self.token = token
        self.timeout = timeout
        self.opener = build_opener(NoRedirect())

    def request(self, method, path, body=None, authenticated=True, refresh=True):
        headers = {'Accept': 'application/json', 'X-Admin-UI-Request': '1'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.token
        payload = None
        if body is not None:
            payload = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        request = Request(self.base_url + path, data=payload, headers=headers, method=method)
        # Only GET requests are retried. A test POST may already have executed.
        for attempt in range(3 if method == 'GET' else 1):
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    envelope = json.load(response)
                break
            except HTTPError as exc:
                if exc.code == 401 and authenticated and refresh and self.password:
                    self.login()
                    return self.request(method, path, body, authenticated, refresh=False)
                if method == 'GET' and exc.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                messages = {401: 'Authentication expired or invalid', 403: 'Administrator access denied',
                            404: 'Endpoint or proxy no longer exists', 429: 'Rate limited'}
                raise ApiError(messages.get(exc.code, 'HTTP request failed') + f' (HTTP {exc.code})', exc.code) from None
            except (URLError, TimeoutError, OSError, HTTPException):
                if method == 'GET' and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise ApiError('Network error or timeout') from None
            except (ValueError, UnicodeError):
                raise ApiError('API did not return valid JSON') from None
        if not isinstance(envelope, dict):
            raise ApiError('Expected a JSON object')
        if envelope.get('code', 0) not in (0, 200):
            raise ApiError('API error: ' + str(envelope.get('message', 'unknown error')))
        return envelope.get('data', envelope)

    def login(self):
        data = self.request('POST', '/api/v1/auth/login',
                            {'email': self.email, 'password': self.password}, authenticated=False)
        if not isinstance(data, dict) or not data.get('access_token'):
            raise ApiError('Login did not return access_token; check whether 2FA is required. Use --token if needed.')
        self.token = data['access_token']

    def list_proxies(self, page_size):
        items = []
        seen = set()
        page = 1
        expected_total = None
        while True:
            query = urlencode({'page': page, 'page_size': page_size, 'sort_by': 'id',
                               'sort_order': 'desc', 'timezone': 'Asia/Shanghai'})
            data = self.request('GET', '/api/v1/admin/proxies?' + query)
            if not isinstance(data, dict) or not isinstance(data.get('items'), list):
                raise ApiError('Proxy response is missing data.items')
            batch = data['items']
            total = data.get('total')
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise ApiError('Proxy response has an invalid total')
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise ApiError('Proxy list changed during pagination; run again for a complete snapshot')
            for item in batch:
                if not isinstance(item, dict) or not isinstance(item.get('id'), int):
                    raise ApiError('Invalid proxy item')
                if item['id'] in seen:
                    raise ApiError('Duplicate proxy across pages; rerun after list changes stop')
                seen.add(item['id'])
                items.append(item)
            print(f'Fetched page {page}: {len(items)}/{total}', flush=True)
            if len(items) == total:
                return items
            if not batch or len(items) > total:
                raise ApiError('Pagination returned an incomplete or inconsistent proxy list')
            page += 1


def now():
    return datetime.now(SHANGHAI).isoformat(timespec='seconds')


def safe_csv(value):
    # Excel must treat names and server messages as text, including formula prefixes.
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def collect(client, items, csv_path, skip_test, interval):
    rows = []
    with csv_path.open('w', encoding='utf-8-sig', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        output.flush()
        for index, item in enumerate(items, 1):
            row = {key: item.get(key, '') for key in
                   ('name', 'protocol', 'host', 'port', 'ip_address', 'country', 'region', 'city', 'account_count')}
            row.update(tested_at='', proxy_id=item['id'], proxy_status=item.get('status', ''),
                       previous_latency_ms=item.get('latency_ms'), latency_ms=None,
                       test_status='skipped', message='Test skipped; previous_latency_ms is historical')
            if not skip_test:
                row['tested_at'] = now()
                try:
                    result = client.request('POST', f"/api/v1/admin/proxies/{item['id']}/test")
                    if not isinstance(result, dict) or not isinstance(result.get('success'), bool):
                        raise ApiError('Invalid test response: missing boolean success')
                    row['message'] = result.get('message', '')
                    row['test_status'] = 'success' if result['success'] else 'failed'
                    if result['success']:
                        latency = result.get('latency_ms')
                        if isinstance(latency, bool) or not isinstance(latency, (int, float)) or latency < 0:
                            raise ApiError('Successful test did not include a valid latency_ms')
                        row['latency_ms'] = latency
                    for key in ('ip_address', 'country', 'region', 'city'):
                        if result.get(key) is not None:
                            row[key] = result[key]
                except ApiError as exc:
                    row.update(latency_ms=None, test_status='error', message=str(exc))
                    if exc.status in (401, 403):
                        # Preserve the row and partial CSV before stopping on auth failure.
                        writer.writerow({k: safe_csv(v) for k, v in row.items()})
                        output.flush()
                        raise
            rows.append(row)
            writer.writerow({k: safe_csv(v) for k, v in row.items()})
            output.flush()
            print(f"[{index}/{len(items)}] id={item['id']} accounts={row['account_count']} "
                  f"status={row['test_status']} latency_ms={row['latency_ms']}", flush=True)
            if not skip_test and index < len(items) and interval:
                time.sleep(interval)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='https://www.caeakrma.top')
    parser.add_argument('--email', default=os.getenv('SUB2API_EMAIL', 'admin@sub2api.local'))
    parser.add_argument('--token', default=os.getenv('SUB2API_TOKEN'), help='Optional existing Bearer token')
    parser.add_argument('--page-size', type=int, default=20)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--interval', type=float, default=0.2, help='Seconds between tests')
    parser.add_argument('--ids', type=int, nargs='+', help='Only test/export these proxy IDs')
    parser.add_argument('--skip-test', action='store_true', help='Export counts and historical latency only')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent / 'results')
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme != 'https' or not url.netloc or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        parser.error('--base-url must be an HTTPS origin, e.g. https://www.caeakrma.top')
    if not 1 <= args.page_size <= 100 or args.timeout <= 0 or args.interval < 0:
        parser.error('page-size must be 1..100, timeout > 0, interval >= 0')
    password = None if args.token else (os.getenv('SUB2API_PASSWORD') or getpass.getpass('Admin password (hidden): '))
    client = Client(args.base_url, args.email, password, args.token, args.timeout)
    if not client.token:
        client.login()
    items = client.list_proxies(args.page_size)
    total = len(items)
    if args.ids:
        selected_ids = set(args.ids)
        missing = selected_ids.difference(item['id'] for item in items)
        if missing:
            raise ApiError('Proxy IDs not found: ' + ', '.join(map(str, sorted(missing))))
        items = [item for item in items if item['id'] in selected_ids]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(SHANGHAI).strftime('%Y%m%d_%H%M%S_%f')
    csv_path = args.output_dir / f'proxies_{stamp}.csv'
    print(f'CSV: {csv_path.resolve()}', flush=True)
    rows = collect(client, items, csv_path, args.skip_test, args.interval)
    counts = [row['account_count'] for row in rows]
    counts_complete = all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in counts)
    summary = {
        'finished_at': now(), 'base_url': client.base_url, 'total_proxies_on_site': total,
        'exported_proxies': len(rows), 'account_count_complete': counts_complete,
        'account_count_sum': sum(counts) if counts_complete else None,
        'successful_tests': sum(r['test_status'] == 'success' for r in rows),
        'failed_tests': sum(r['test_status'] == 'failed' for r in rows),
        'request_errors': sum(r['test_status'] == 'error' for r in rows),
        'skipped_tests': sum(r['test_status'] == 'skipped' for r in rows),
    }
    json_path = csv_path.with_suffix('.json')
    json_path.write_text(json.dumps({'summary': summary, 'items': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    print(f'JSON: {json_path.resolve()}')
    return 2 if summary['request_errors'] or summary['failed_tests'] or not counts_complete else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ApiError, OSError, EOFError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nInterrupted. Already written CSV rows are preserved.', file=sys.stderr)
        sys.exit(130)
