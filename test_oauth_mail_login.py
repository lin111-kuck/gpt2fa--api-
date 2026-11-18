import html
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import batch_login as b
import oauth_mail_login as o
from test_batch_login import fake_credential

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
EMAIL = 'person@example.com'


def message(code='123456', email=EMAIL, when=None, css_number='999999'):
    when = when or datetime.now(b.SHANGHAI)
    inner = '<style>.x{color:#' + css_number + '}</style><h1>ChatGPT</h1><p>输入此临时验证码以继续：</p><div>' + code + '</div>'
    return ('<section><h2>你的 OpenAI 临时验证码</h2><div>发件人：OpenAI &lt;otp@example.com&gt;</div>'
            '<div>邮箱：' + email + '</div><div>时间：' + when.isoformat() + '</div>'
            '<iframe srcdoc="' + html.escape(inner, quote=True) + '"></iframe></section>')


class OAuthTests(unittest.TestCase):
    def test_original_four_fields_are_preserved_without_repr_secrets(self):
        text = EMAIL + '----secret-password----' + SECRET + '----https://api.wdmail.top/m?f=html&e=' + EMAIL + ':mail-secret'
        account = o.load_accounts(text)[0]
        self.assertEqual(account.mail_url, text.split('----')[3])
        self.assertNotIn('secret-password', repr(account))
        self.assertNotIn('mail-secret', repr(account))

    def test_mail_link_must_match_recipient_and_provider(self):
        for link in ('http://api.wdmail.top/m?e='+EMAIL+':x', 'https://evil.test/m?e='+EMAIL+':x',
                     'https://api.wdmail.top/m?e=other@example.com:x'):
            with self.subTest(link=link), self.assertRaises(b.ApiError):
                o.load_accounts(EMAIL+'----p----'+SECRET+'----'+link)

    def test_iframe_srcdoc_code_ignores_css_numbers(self):
        records = o.mailbox_codes(message(), EMAIL)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].code, '123456')
        self.assertNotIn('123456', repr(records[0]))

    def test_wrong_recipient_and_ambiguous_codes_are_rejected(self):
        self.assertEqual(o.mailbox_codes(message(email='other@example.com'), EMAIL), [])
        self.assertEqual(o.mailbox_codes(message(code='123456</div><div>654321'), EMAIL), [])

    def test_old_baseline_is_not_reused_and_newest_code_wins(self):
        now = datetime.now(timezone.utc)
        old = o.mailbox_codes(message('111111', when=now-timedelta(minutes=2)), EMAIL)[0]
        newer = o.mailbox_codes(message('222222', when=now-timedelta(seconds=2)), EMAIL)[0]
        self.assertIsNone(o.fresh_mail_code([old], {old.fingerprint}, now))
        self.assertEqual(o.fresh_mail_code([old,newer], {old.fingerprint}, now), '222222')
        self.assertIsNone(o.fresh_mail_code([old], set(), now))

    def test_future_and_same_time_ambiguous_codes_are_rejected(self):
        now = datetime.now(timezone.utc)
        one=o.mailbox_codes(message('111111', when=now), EMAIL)[0]
        two=o.mailbox_codes(message('222222', when=now), EMAIL)[0]
        future=o.mailbox_codes(message('333333', when=now+timedelta(hours=1)), EMAIL)[0]
        self.assertIsNone(o.fresh_mail_code([one,two],set(),now))
        self.assertIsNone(o.fresh_mail_code([future],set(),now))

    def test_network_failure_stops_with_code_without_auth_url_secrets(self):
        page=SimpleNamespace(goto=Mock(side_effect=RuntimeError('Page.goto: net::ERR_TIMED_OUT at https://auth.openai.com/?state=secret-state')))
        with self.assertRaises(o.BrowserNetworkError) as error:
            o.login_navigation(page,'https://auth.openai.com/?state=secret-state')
        self.assertIn('ERR_TIMED_OUT',str(error.exception))
        self.assertNotIn('secret-state',str(error.exception))

    def test_http_rejection_reports_reason_without_response_body_or_url(self):
        for body, headers, expected in (
            ('secret-token unsupported_country', {}, 'region is not supported'),
            ('secret-token invalid_request', {}, 'parameters rejected'),
        ):
            response = SimpleNamespace(status=403, headers=headers, text=lambda: body)
            page = SimpleNamespace(goto=Mock(return_value=response))
            with self.assertRaises(b.ApiError) as error:
                o.login_navigation(page, 'https://auth.openai.com/?state=secret-state')
            self.assertIn(expected, str(error.exception))
            self.assertNotIn('secret-token', str(error.exception))
            self.assertNotIn('secret-state', str(error.exception))

    def test_route_filter_keeps_private_proxy_occupancy_and_public_authenticated_socks(self):
        ps = [dict(id=1, host='172.19.0.1', port=1234, protocol='http', status='active', account_count=2),
              dict(id=2, host='8.8.8.8', port=1187, protocol='socks5', status='active', account_count=1, username='u', password='p')]
        client = o.RegionClient('https://example.com', 'admin', None, 'token', 1)
        with patch.object(b.SafeClient, 'list_proxies', return_value=ps):
            filtered = client.list_proxies(100)
        self.assertEqual(filtered[0]['status'], 'inactive')
        self.assertEqual(filtered[0]['account_count'], 2)
        self.assertEqual(filtered[1]['status'], 'active')
        self.assertEqual(client.catalog[1]['host'], '172.19.0.1')

    def test_observed_cloudflare_page_requires_human_verification(self):
        self.assertTrue(o.human_verification('正在进行安全验证 验证成功，正在等待 auth.openai.com 响应'))
        self.assertFalse(o.human_verification('请输入身份验证器中的验证码'))
        self.assertFalse(o.human_verification('Sign in to Codex'))
        with patch.object(o.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(o.ManualActionRequired):
                o.manual_pause('Cloudflare verification required')

    def test_page_diagnostic_redacts_secrets_and_excludes_query(self):
        client = o.RegionClient('https://example.com', 'admin', 'secret-password', 'secret-token', 1)
        result = o.clean_page_diagnostic(client, dict(path='/log-in?code=private', headings=['secret-password'], buttons=['secret-token']))
        self.assertEqual(result['path'], '/log-in')
        self.assertNotIn('secret-password', json.dumps(result))
        self.assertNotIn('secret-token', json.dumps(result))

    def test_security_response_is_allowed_to_complete_in_browser(self):
        response = SimpleNamespace(status=403, headers={'cf-mitigated':'challenge'}, text=lambda: 'Just a moment')
        self.assertIs(o.login_navigation(SimpleNamespace(goto=Mock(return_value=response)), 'https://auth.openai.com'), response)
        self.assertFalse(o.verification_requires_action('验证成功，正在等待 auth.openai.com 响应'))
        self.assertTrue(o.verification_requires_action('Verify you are human by completing the action below'))

    def test_security_wait_times_out_without_refresh_or_submission(self):
        page = SimpleNamespace(locator=lambda x: SimpleNamespace(inner_text=lambda **kw: '正在进行安全验证'),
                               wait_for_timeout=Mock(), is_closed=lambda: False)
        with patch.object(o.time, 'monotonic', side_effect=[0, 0, 0, 2]), patch.object(o, 'page_diagnostic', return_value={'path':'/check'}):
            with self.assertRaises(o.ManualActionRequired):
                o.wait_security_check(page, 1, Mock(), Mock())
        page.wait_for_timeout.assert_called_once_with(1000)

    def test_manual_callback_requires_exact_path_and_state(self):
        import threading
        import urllib.request
        import urllib.error
        session = dict(redirect_uri='http://127.0.0.1:0/auth/callback', state='test-state')
        server, captured = o.callback_server(session)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        origin = 'http://127.0.0.1:' + str(server.server_address[1])
        try:
            for path in ('/other?code=bad&state=test-state', '/auth/callback?code=bad&state=wrong'):
                with self.assertRaises(urllib.error.HTTPError):
                    opener.open(origin + path, timeout=3)
                self.assertNotIn('code', captured)
            with opener.open(origin + '/auth/callback?code=test-code&state=test-state', timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertEqual(captured['code'], 'test-code')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_manual_browser_cli_uses_visible_chrome(self):
        args = o.parse_args(['--manual-browser'])
        self.assertEqual(args.channel, 'chrome')
        self.assertFalse(args.headless)
        from contextlib import redirect_stderr
        from io import StringIO
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            o.parse_args(['--manual-browser', '--headless'])

    def test_form_submission_clicks_current_form_button(self):
        button = SimpleNamespace(is_visible=lambda: True, click=Mock())
        buttons = SimpleNamespace(count=lambda:1, nth=lambda i:button)
        form = SimpleNamespace(count=lambda:1, locator=lambda q:buttons)
        field = SimpleNamespace(locator=lambda q:form, press=Mock())
        self.assertEqual(o.submit_login_form(SimpleNamespace(), field), 'button')
        button.click.assert_called_once()
        field.press.assert_not_called()

    def test_missing_submit_button_does_not_send_enter(self):
        empty = SimpleNamespace(count=lambda: 0)
        page = SimpleNamespace(locator=lambda q: empty, get_by_role=lambda *a, **k: empty)
        field = SimpleNamespace(locator=lambda q: empty, press=Mock())
        with self.assertRaises(o.ManualActionRequired):
            o.submit_login_form(page, field)
        field.press.assert_not_called()

    def test_form_reset_during_initialization_is_not_submitted(self):
        page = SimpleNamespace(wait_for_load_state=Mock(), wait_for_timeout=Mock())
        field = SimpleNamespace(wait_for=Mock(), evaluate=Mock(return_value=True),
                                fill=Mock(), input_value=Mock(return_value=''))
        with self.assertRaisesRegex(o.ManualActionRequired, 'changed during initialization'):
            o.fill_login_field(page, field, 'private-password')
        field.fill.assert_called_once()

    def test_response_diagnostics_exclude_auth_query_and_headers(self):
        request = SimpleNamespace(method='GET', resource_type='document',
                                  redirected_from=SimpleNamespace(url='https://auth.openai.com/mfa?code=secret-code'))
        response = SimpleNamespace(url='https://auth.openai.com/api/accounts/email-otp/send?state=secret-state',
                                   status=307, request=request,
                                   header_value=lambda name: '/email-verification?token=secret-token' if name == 'location' else None)
        diagnostic = o.auth_response_diagnostic(response)
        self.assertEqual(diagnostic['redirect_from'], '/mfa')
        self.assertEqual(diagnostic['redirect_to'], '/email-verification')
        self.assertEqual(diagnostic['http_status'], 307)
        self.assertNotIn('secret-', json.dumps(diagnostic))
        response.status = 403
        response.header_value = lambda name: 'challenge' if name == 'cf-mitigated' else None
        self.assertTrue(o.auth_response_diagnostic(response)['cf_challenge'])
        response.url = 'https://mail.example.com/private'
        self.assertIsNone(o.auth_response_diagnostic(response))

    def test_failed_resource_diagnostics_only_keep_network_error_code(self):
        request = SimpleNamespace(url='https://auth.openai.com/assets/app.js?token=private',
                                  method='GET', resource_type='script',
                                  failure='net::ERR_CONNECTION_RESET at https://auth.openai.com/?code=private')
        diagnostic = o.auth_failure_diagnostic(request)
        self.assertEqual(diagnostic['error_code'], 'ERR_CONNECTION_RESET')
        self.assertNotIn('private', json.dumps(diagnostic))
        client = o.RegionClient('https://example.com', 'admin', None, 'token', 1)
        cleaned = o.clean_page_diagnostic(client, diagnostic)
        self.assertEqual(cleaned['resource_type'], 'script')
        self.assertEqual(cleaned['network_event'], 'request_failed')

    def test_callback_server_is_closed_when_browser_launch_fails(self):
        session = dict(redirect_uri='http://127.0.0.1:0/auth/callback', state='test-state')
        server, captured = o.callback_server(session)
        launcher = SimpleNamespace(chromium=SimpleNamespace(launch=Mock(side_effect=RuntimeError('launch failed'))))
        with patch.object(o, 'callback_server', return_value=(server, captured)):
            with self.assertRaisesRegex(RuntimeError, 'launch failed'):
                o.run_browser(launcher, o.Account(EMAIL, 'p', SECRET),
                              dict(protocol='http', host='unused.invalid', port=8080), session)
        self.assertEqual(server.fileno(), -1)
        self.assertEqual(launcher.chromium.launch.call_args.kwargs['proxy']['bypass'],
                         'localhost,127.0.0.1,[::1]')

    def test_email_verification_path_prevents_totp_footer_misclassification(self):
        self.assertEqual(o.verification_kind('/email-verification', 'Use your authenticator as an alternative'), 'email')
        self.assertEqual(o.verification_kind('/mfa-challenge', 'Check your email for help'), 'totp')
        self.assertEqual(o.verification_kind('/other', 'Check your inbox'), 'email')

    def test_verify_mode_cannot_import_or_require_manual_browser(self):
        self.assertTrue(o.parse_args(['--verify-only']).verify_only)
        from contextlib import redirect_stderr
        from io import StringIO
        for args in (['--verify-only','--import'], ['--verify-only','--manual-browser']):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                o.parse_args(args)

    def test_release_only_failed_accounts_temporary_reservations(self):
        picker = SimpleNamespace(proxy_owners={1:EMAIL,2:'other@example.com'}, ip_owners={'1.1.1.1':EMAIL,'8.8.8.8':'other@example.com'})
        o.release_unbound_failure(picker, EMAIL)
        self.assertEqual(picker.proxy_owners, {2:'other@example.com'})
        self.assertEqual(picker.ip_owners, {'8.8.8.8':'other@example.com'})

    def test_user_authorized_five_account_capacity(self):
        self.assertEqual(o.parse_args([]).max_per_ip, 5)
        self.assertEqual(o.parse_args(['--max-per-ip', '5']).max_per_ip, 5)
        ps = [dict(id=1,status='active',account_count=2,ip_address='192.0.2.1'),
              dict(id=2,status='active',account_count=2,ip_address='192.0.2.1')]
        c = SimpleNamespace(list_proxies=Mock(return_value=ps),request=Mock(return_value=dict(success=True,ip_address='192.0.2.1')))
        self.assertEqual(o.recheck_same_proxy(c,dict(proxy_id=1,exit_ip='192.0.2.1'),5),4)
        ps[1]['account_count']=3
        with self.assertRaises(b.ApiError):
            o.recheck_same_proxy(c,dict(proxy_id=1,exit_ip='192.0.2.1'),5)

    def test_totp_matches_rfc_vector(self):
        self.assertEqual(o.totp(SECRET,59), '287082')

    def test_callback_requires_exact_redirect_and_state(self):
        s=dict(redirect_uri='http://localhost:1455/auth/callback',state='random')
        self.assertEqual(o.callback_code(s['redirect_uri']+'?code=valid&state=random',s),'valid')
        self.assertIsNone(o.callback_code('https://evil.test/auth/callback?code=x&state=random',s))
        self.assertIsNone(o.callback_code('http://localhost:1455/other?code=x&state=random',s))
        with self.assertRaises(b.ApiError):o.callback_code(s['redirect_uri']+'?code=x&state=wrong',s)
        with self.assertRaises(b.ApiError):o.callback_code(s['redirect_uri']+'?error=denied&state=random',s)

    def test_region_policy_rejects_unknown_hk_tw_and_region_aliases(self):
        for location in ({},{'country':'TW'},{'country':'香港'},{'country':'China','region':'Hong Kong'},
                         {'country':'Taiwan'},{'country':'台灣'}):
            self.assertFalse(o.permitted_location(location))
        self.assertTrue(o.permitted_location({'country':'日本'}))

    def test_recheck_refuses_changed_ip_even_in_same_country(self):
        c=SimpleNamespace(list_proxies=Mock(return_value=[dict(id=1,status='active',account_count=1,ip_address='192.0.2.1')]),
                          request=Mock(return_value=dict(success=True,ip_address='192.0.2.2',country='日本')))
        with self.assertRaisesRegex(b.ApiError,'changed'):
            o.recheck_same_proxy(c,dict(proxy_id=1,exit_ip='192.0.2.1'),4)

    def test_recheck_combines_occupancy_across_duplicate_nodes(self):
        ps=[dict(id=1,status='active',account_count=2,ip_address='192.0.2.1'),
            dict(id=2,status='active',account_count=2,ip_address='192.0.2.1')]
        c=SimpleNamespace(list_proxies=Mock(return_value=ps),request=Mock(return_value=dict(success=True,ip_address='192.0.2.1')))
        with self.assertRaisesRegex(b.ApiError,'capacity'):
            o.recheck_same_proxy(c,dict(proxy_id=1,exit_ip='192.0.2.1'),4)

    def test_recheck_does_not_switch_slow_but_valid_proxy(self):
        c=SimpleNamespace(list_proxies=Mock(return_value=[dict(id=1,status='active',account_count=2,ip_address='192.0.2.1')]),
                          request=Mock(return_value=dict(success=True,ip_address='192.0.2.1',latency_ms=900)))
        self.assertEqual(o.recheck_same_proxy(c,dict(proxy_id=1,exit_ip='192.0.2.1'),4),2)

    def test_export_proxy_key_matches_supplied_format(self):
        p=dict(name='node',protocol='http',host='proxy.example',port=8080,username='u',password='p')
        record=o.proxy_record(p)
        self.assertEqual(record['proxy_key'],'http|proxy.example|8080|u|p')
        account=o.export_account(EMAIL,{'access_token':'token'},record['proxy_key'])
        self.assertEqual(account['type'],'oauth')
        self.assertNotIn('password',account['credentials'])
        self.assertEqual(account['proxy_key'],record['proxy_key'])

    def test_exchange_verifies_returned_email(self):
        session=dict(session_id='session',state='random')
        bad=dict(fake_credential('wrong@example.com'),refresh_token='refresh')
        client=SimpleNamespace(request=Mock(return_value=bad))
        with self.assertRaises(b.HaltBatch):o.exchange(client,session,'code',1,EMAIL)
        self.assertEqual(client.request.call_args.args[1],'/api/v1/admin/openai/exchange-code')
        self.assertEqual(client.request.call_args.args[2]['proxy_id'],1)

    def test_atomic_json_preserves_old_file_if_serialization_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'tokens.json'
            o.write_json(p,{'original':True})
            with self.assertRaises(TypeError):o.write_json(p,{'bad':object()})
            self.assertEqual(json.loads(p.read_text()),{'original':True})
            self.assertFalse(p.with_name(p.name+'.tmp').exists())

    def test_no_live_login_for_help_and_invalid_cli(self):
        self.assertEqual(o.parse_args([]).limit,1)
        self.assertFalse(o.parse_args([]).do_import)
        from contextlib import redirect_stderr
        from io import StringIO
        for args in (['--max-per-ip','6'],['--max-latency','nan']):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):o.parse_args(args)


@unittest.skipUnless(os.environ.get('OAUTH_BROWSER_SMOKE')=='1','opt-in offline browser flow')
class BrowserSmoke(unittest.TestCase):
    def test_email_mail_otp_totp_consent_callback_offline(self):
        self.run_fixture(False)

    def test_skip_security_page_stops_before_further_credentials(self):
        self.run_fixture(True)

    def test_form_initialization_completes_before_filling(self):
        self.run_fixture(delayed_form=True)

    def run_fixture(self, skip_security=False, delayed_form=False):
        from playwright.sync_api import sync_playwright
        observed=[]
        class Chromium:
            def __init__(self,p):self.p=p
            def launch(self,**kwargs):
                assert '--incognito' in kwargs['args']
                real=self.p.chromium.launch(channel=kwargs['channel'],headless=True,proxy=kwargs['proxy'])
                class Browser:
                    def new_context(self,**kwargs):
                        ctx=real.new_context(**kwargs)
                        # Fixture routing belongs to the test only. The object
                        # exposed to production deliberately has no route API.
                        def dispatch(route):
                            u=route.request.url
                            if u.startswith('https://auth.openai.com/fixture/') or u == 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent':
                                step='consent' if '/sign-in-with-chatgpt/' in u else u.split('/fixture/')[1]
                                observed.append(step)
                                pages={
                                  'email': '<form onsubmit="event.preventDefault();location.href=\'/fixture/password\'"><input type=email><button>Continue</button></form>',
                                  'password': '<form onsubmit="event.preventDefault();if(document.querySelector(\'input\').value===\'password\')location.href=\'/fixture/mail\'"><input type=password><button>Continue</button></form>',
                                  'mail': '<h1>Check your inbox</h1><form onsubmit="event.preventDefault();if(document.querySelector(\'input\').value===\'112233\')location.href=\'/fixture/checking\'"><input name=code><button>Continue</button></form>',
                                  'checking': '<h1>Checking your browser</h1><script>setTimeout(()=>location.href="/fixture/totp",1200)</script>',
                                  'totp': '<h1>Authenticator code</h1><form onsubmit="event.preventDefault();location.href=\'/sign-in-with-chatgpt/codex/consent\'"><input name=code><button>Continue</button></form>',
                                  'consent': '<p>Connect your account</p><button onclick="location.href=\'http://localhost:1455/auth/callback?code=offline-code&state=test-state\'">Continue</button>'}
                                if delayed_form and step == 'email':
                                    pages['email'] = """<form aria-busy="true" onsubmit="event.preventDefault();if(document.querySelector('input').value === 'person@example.com')location.href='/fixture/password'">
                                        <input type=email><button disabled>Continue</button></form>
                                        <script>setTimeout(() => {
                                            document.querySelector('input').value = '';
                                            document.querySelector('button').disabled = false;
                                            document.querySelector('form').removeAttribute('aria-busy');
                                        }, 700);</script>"""
                                route.fulfill(status=200,content_type='text/html; charset=utf-8',body=pages[step])
                            elif u.startswith('http://localhost:1455/auth/callback'):
                                route.continue_()
                            else:
                                route.abort()
                        ctx.route('**/*',dispatch)
                        return SimpleNamespace(new_page=ctx.new_page, close=ctx.close)
                    def close(self):real.close()
                return Browser()
        session=dict(auth_url='https://auth.openai.com/fixture/email',redirect_uri='http://localhost:1455/auth/callback',state='test-state')
        account=o.Account(EMAIL,'password',SECRET)
        with sync_playwright() as p,patch.object(o,'Mailbox') as mailbox,patch.object(o,'manual_pause',side_effect=AssertionError('unexpected handoff')):
            mailbox.return_value.wait_code.return_value='112233'
            if skip_security:
                with self.assertRaises(o.SecurityVerificationSkipped):
                    o.run_browser(SimpleNamespace(chromium=Chromium(p)), account,
                                  dict(protocol='http',host='unused.invalid',port=8080), session,
                                  timeout=30, headless=True, skip_security_verification=True)
                self.assertEqual(observed, ['email','password','mail','checking'])
                return
            result=o.run_browser(SimpleNamespace(chromium=Chromium(p)),account,
                                 dict(protocol='http',host='unused.invalid',port=8080),session,timeout=30,headless=True)
        self.assertEqual(result,'offline-code')
        self.assertEqual(observed,['email','password','mail','checking','totp','consent'])


if __name__=='__main__':unittest.main()
