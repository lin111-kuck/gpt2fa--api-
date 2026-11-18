"""Desktop-facing API; all network and batch work can run outside the Tk thread."""
import csv
import json
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import batch_login as batch

ROOT = Path(__file__).resolve().parent
MODES = {'导入账号': 'import', '仅验证登录': 'login', '预检查': 'preview'}
ENGINES = {'本地协议（自动取码）': 'local', '后台登录任务': 'backend'}
STATUS_LABELS = {
    'waiting': '等待处理', 'working': '处理中', 'login_submitted': '正在登录',
    'login_verified': '登录成功', 'created': '已添加', 'planned': '预检查通过',
    'skipped_existing': '已存在，跳过', 'skipped_race': '已存在，跳过',
    'skipped_existing_identity': '已有相同账号', 'failed': '失败',
    'needs_review': '需要核查', 'stopped': '已停止', 'not_started': '未处理',
}


@dataclass
class Settings:
    group_ids: str
    proxy_name: str = ''
    workers: int = 3
    mode: str = 'import'
    max_per_ip: int = 4
    max_latency: float = 300
    resume_journal: str = ''
    login_engine: str = 'local'


def authenticate(base_url, email, password, direct=True):
    origin = base_url.strip().rstrip('/')
    url = urlsplit(origin)
    if (url.scheme != 'https' or not url.netloc or url.username or url.password
            or url.path or url.query or url.fragment):
        raise batch.ApiError('后台地址必须是 HTTPS 域名，例如 https://www.caeakrma.top')
    if not email.strip() or not password:
        raise batch.ApiError('请填写管理员邮箱和密码。')
    client = batch.SafeClient(origin, email.strip(), password, None, 30, direct=direct)
    client.login()
    groups = client.request('GET', '/api/v1/admin/groups/all?platform=openai')
    if not isinstance(groups, list):
        raise batch.ApiError('后台未返回有效分组列表。')
    groups = [g for g in groups if g.get('status') == 'active' and g.get('platform') == 'openai'
              and type(g.get('id')) is int]
    client.password = None
    return client, groups


def options(settings):
    if type(settings.workers) is not int or not 1 <= settings.workers <= 8:
        raise batch.ApiError('并发数量请输入 1–8 的整数。')
    if type(settings.max_per_ip) is not int or settings.max_per_ip < 1:
        raise batch.ApiError('每个 IP 的账号上限必须是正整数。')
    if settings.mode not in ('import', 'login', 'preview'):
        raise batch.ApiError('请选择有效的运行模式。')
    if settings.login_engine not in ('local', 'backend'):
        raise batch.ApiError('请选择有效的登录方式。')
    import math
    if not math.isfinite(settings.max_latency) or settings.max_latency <= 0:
        raise batch.ApiError('优先延迟必须是正数。')
    keyword = settings.proxy_name.strip()
    if keyword and not batch.normalize_proxy_name(keyword):
        raise batch.ApiError('代理关键词请至少填写一个中文、字母或数字。')
    return SimpleNamespace(
        groups=batch.DEFAULT_GROUPS, group_ids=batch.parse_group_ids(settings.group_ids),
        proxy_name=keyword, workers=settings.workers, max_per_ip=settings.max_per_ip,
        max_latency=settings.max_latency, dry_run=settings.mode == 'preview',
        login_only=settings.mode == 'login', job_timeout=600, poll_interval=2, models=None,
        login_engine=settings.login_engine, mail_timeout=180, gateway=None,
        resume_journal=[Path(settings.resume_journal)] if settings.resume_journal else [])


def proxy_candidates(client, keyword, max_per_ip=4):
    proxies = client.list_proxies(100)
    found = []
    for proxy in proxies:
        if not batch.active(proxy) or not batch.proxy_name_matches(proxy.get('name'), keyword):
            continue
        ip = batch.normalize_ip(proxy.get('ip_address'))
        used = batch.occupancy(proxies, proxy, ip) if ip else proxy['account_count']
        if used is None or used >= max_per_ip:
            continue
        found.append(dict(id=proxy['id'], name=proxy.get('name', ''), ip=ip or '待测试',
                          country=proxy.get('country', ''), account_count=used,
                          latency_ms=proxy.get('latency_ms')))
    return found


def execute_batch(client, text, settings, emit, stop_event=None, workspace=ROOT):
    args = options(settings)
    entries = batch.parse_entries(text)
    stop = stop_event if stop_event is not None else threading.Event()
    worker = batch.SafeClient(client.base_url, client.email, None, client.token, 45,
                             secrets=[s for e in entries for s in (e.password, e.mfa_secret, e.mail_url)],
                             direct=client.direct)
    workspace = Path(workspace)
    output = workspace / 'batch_results'
    output.mkdir(parents=True, exist_ok=True)
    stem = output / datetime.now(batch.SHANGHAI).strftime('gui_%Y%m%d_%H%M%S_%f')
    paths = {extension: str(stem.with_suffix('.' + extension)) for extension in ('csv', 'json', 'jsonl')}
    rows, error = [], ''
    emit('started', dict(emails=[e.email for e in entries], paths=paths))
    with batch.batch_lock(workspace):
        with open(paths['jsonl'], 'w', encoding='utf-8') as log, \
                open(paths['csv'], 'w', encoding='utf-8-sig', newline='') as table:
            writer = csv.DictWriter(table, fieldnames=batch.REPORT_FIELDS, extrasaction='ignore')
            writer.writeheader()
            table.flush()
            def journal(event, **data):
                log.write(json.dumps(dict(time=batch.now(), event=event, **data), ensure_ascii=False) + '\n')
                log.flush()
                emit('event', dict(event=event, **data))
            def save_row(row):
                rows.append(dict(row))
                journal('result', **{k: v for k, v in row.items() if k != 'time'})
                writer.writerow({k: batch.safe_csv(json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v)
                                 for k, v in row.items() if k in batch.REPORT_FIELDS})
                table.flush()
                emit('row', dict(row))
            try:
                journal('batch_options', group_ids=args.group_ids, proxy_name=args.proxy_name,
                        workers=1 if args.dry_run else args.workers, mode=settings.mode)
                runner = batch.run_batch_parallel if args.workers > 1 and not args.dry_run else batch.run_batch
                runner(worker, entries, args, journal, save_row, stop_event=stop)
            except Exception as exc:
                stop.set()
                error = worker.clean(str(exc) or type(exc).__name__)
                journal('batch_error', message=error)
    summary = dict(finished_at=batch.now(), input_count=len(entries), processed_count=len(rows),
                   created=sum(r['status'] == 'created' for r in rows),
                   login_verified=sum(bool(r.get('login_verified')) for r in rows),
                   skipped=sum(r['status'].startswith('skipped_') for r in rows),
                   planned=sum(r['status'] == 'planned' for r in rows),
                   failed=sum(r['status'] in ('failed', 'needs_review') for r in rows),
                   stopped=sum(r['status'] == 'stopped' for r in rows),
                   unprocessed=len(entries) - len(rows), mode=settings.mode,
                   workers=1 if args.dry_run else args.workers, proxy_name_filter=args.proxy_name)
    result = dict(summary=summary, items=rows, paths=paths, error=error)
    Path(paths['json']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result
