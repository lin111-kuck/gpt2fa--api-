# SPDX-License-Identifier: AGPL-3.0-only
"""Connect the local protocol flow to the importer's selected proxy and journal."""
import batch_login as batch
from oauth_proxy_transport import ProxyBridge, RouteError


def login_local(client, entry, chosen, args, journal, stop_event=None):
    if not chosen:
        raise batch.ApiError('本地协议登录需要先选择代理')
    proxy = next((p for p in client.list_proxies(100) if p.get('id') == chosen['proxy_id']), None)
    if not proxy:
        raise batch.ApiError('选中的代理已不存在')
    if str(proxy.get('protocol') or '').lower() not in ('http', 'https', 'socks5'):
        raise batch.ApiError('本地协议登录仅支持 HTTP、HTTPS 或 SOCKS5 代理')
    client.secrets.extend(str(proxy[k]) for k in ('username', 'password') if proxy.get(k))
    try:
        from protocol_login import login
        with ProxyBridge(proxy, gateway=getattr(args, 'gateway', None)) as bridge:
            def on_step(step):
                journal('login_step', email=entry.email, engine='local', step=step)
            def on_network(network):
                journal('login_network', email=entry.email, proxy_id=chosen['proxy_id'],
                        engine='local', **network)
            credential = login(entry, 'http://127.0.0.1:' + str(bridge.profile['port']),
                               expected_exit_ip=chosen['exit_ip'], on_network=on_network,
                               timeout=args.job_timeout, mail_timeout=getattr(args, 'mail_timeout', 180),
                               stop_event=stop_event, on_step=on_step, ipv4_only=True)
        identity = batch.verify_login_identity(credential, entry.email)
        journal('login_verified', email=entry.email, engine='local', identity=identity)
        return credential
    except RouteError:
        raise batch.ApiError('本地代理连接或出口核对失败；请检查选中的代理') from None
