"""Offline protocol and mailbox fixtures. These do not exercise a real account."""
import base64
import html
import json
import threading
import time
import unittest
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import batch_login as batch
import mailbox_api as mail
import protocol_login as protocol

EMAIL = 'person@example.com'
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
MAIL_URL = 'https://mail.example.test/otp?email=' + EMAIL + '&token=mail-private'


def jwt(claims):
    return 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode() + '.signature'


class Cookies(CookieJar):
    def set(self, name, value, domain='', path='/'):
        self.set_cookie(Cookie(0, name, value, None, False, domain, True, False,
                               path, True, True, None, True, None, None, {}))


class Response:
    def __init__(self, data=None, status=200, headers=None, text=''):
        self.data, self.status_code, self.headers = data, status, headers or {}
        self.text = text

    def json(self):
        if self.data is None:
            raise ValueError('fixture HTML')
        return self.data


class FakeSession:
    def __init__(self, action):
        self.cookies, self.headers, self.action, self.calls = Cookies(), {}, action, []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.action(method, urlsplit(url).path, kwargs)


def otp_message(code, stamp=None, **updates):
    return dict(code=code, to=EMAIL, sender='otp@tm.openai.com',
                received_at=time.time() if stamp is None else stamp, **updates)


class MailboxTests(unittest.TestCase):
    def test_supported_account_formats_preserve_api_and_hide_secrets(self):
        for source in (f'{EMAIL}----password-private----{SECRET}----{MAIL_URL}',
                       f'{EMAIL}----password-private--------{MAIL_URL}', f'{EMAIL}----{MAIL_URL}'):
            entry = batch.parse_entries(source)[0]
            self.assertEqual(entry.mail_url, MAIL_URL)
            self.assertNotIn('mail-private', repr(entry))
            self.assertNotIn('password-private', repr(entry))
        with self.assertRaises(batch.ApiError):
            batch.parse_entries(f'{EMAIL}----https://mail.example.test/?e=other@example.com')
        with self.assertRaises(batch.ApiError):
            batch.parse_entries(f'{EMAIL}----p----123456----{MAIL_URL}')

    def test_json_recipient_sender_time_and_ambiguous_codes(self):
        source = {'messages': [otp_message('123456', 1794840000),
                               dict(otp_message('222222'), to='other@example.com'),
                               dict(otp_message('333333'), sender='spam@example.net'),
                               {'subject': 'OpenAI verification code 444444 or verification code 555555'}]}
        records = mail.parse_messages(source, EMAIL)
        self.assertEqual([m.code for m in records], ['123456'])
        self.assertEqual(records[0].received, 1794840000)
        self.assertEqual(mail.parse_messages({'error': 'code 999999'}, EMAIL), [])
        self.assertEqual(mail.parse_messages({'success': False, 'code': '999999'}, EMAIL), [])

    def test_wdmail_iframe_srcdoc_and_css(self):
        inner = '<style>.x{color:#999999}</style><h1>ChatGPT</h1><p>临时验证码：</p><div>123456</div>'
        source = ('<div>发件人：OpenAI</div><div>邮箱：' + EMAIL + '</div>'
                  '<div>时间：2026-11-17 01:02:03+08:00</div><iframe srcdoc="' + html.escape(inner, quote=True) + '"></iframe>')
        messages = mail.parse_messages(source, EMAIL)
        self.assertEqual([m.code for m in messages], ['123456'])
        self.assertIsNotNone(messages[0].received)

    def test_cloudflare_protected_recipient_is_decoded_and_still_bound(self):
        def cf(address):
            return bytes([71, *(value ^ 71 for value in address.encode())]).hex()
        source = ('<div>发件人：OpenAI</div><div>邮箱：<a data-cfemail="' + cf(EMAIL)
                  + '">[email protected]</a></div><div>时间：2026-11-17 02:07:12</div>'
                  '<div>Your temporary OpenAI verification code</div><p>123456</p>')
        messages = mail.parse_messages(source, EMAIL)
        self.assertEqual([m.code for m in messages], ['123456'])
        self.assertIsNone(messages[0].received)
        self.assertEqual(mail.parse_messages(source.replace(cf(EMAIL), cf('other@example.com')), EMAIL), [])
        self.assertEqual(mail.parse_messages(source.replace(cf(EMAIL), 'invalid-encoding'), EMAIL), [])

    def test_naive_mail_dates_do_not_guess_the_mail_server_timezone(self):
        self.assertIsNone(mail.timestamp('2026-11-17 02:07:12'))
        self.assertEqual(mail.timestamp('2026-11-17T02:07:12Z'),
                         mail.timestamp('2026-11-17T10:07:12+08:00'))

    def test_protected_email_in_iframe_is_decoded_without_executing_scripts(self):
        value = bytes([12, *(b ^ 12 for b in EMAIL.encode())]).hex()
        body = ('<div>发件人：OpenAI</div><div>邮箱：<span data-cfemail="' + value
                + '">[email protected]</span></div><p>ChatGPT verification code: 654321</p>')
        source = '<script>verification code: 999999</script><iframe srcdoc="' + html.escape(body, quote=True) + '"></iframe>'
        self.assertEqual([m.code for m in mail.parse_messages(source, EMAIL)], ['654321'])

    def test_naive_html_dates_still_require_code_change_after_snapshot(self):
        def message(code):
            return mail.parse_messages('<div>发件人：OpenAI</div><div>邮箱：' + EMAIL
                + '</div><div>时间：2026-11-17 02:07:12</div><p>OpenAI verification code: '
                + code + '</p>', EMAIL)
        box = mail.MailboxAPI(MAIL_URL, EMAIL, session=Mock(), poll_interval=0)
        box.read = Mock(side_effect=[message('123456'), message('123456'), message('654321')])
        box.snapshot()
        self.assertEqual(box.wait_code(time.time(), timeout=.5), '654321')
        self.assertEqual(box.read.call_count, 3)

    def test_plain_code_change_is_required_when_no_timestamp(self):
        box = mail.MailboxAPI(MAIL_URL, EMAIL, session=Mock(), poll_interval=0)
        box.read = Mock(side_effect=[mail.parse_messages('123456', EMAIL),
                                    mail.parse_messages('123456', EMAIL), mail.parse_messages('654321', EMAIL)])
        box.snapshot()
        self.assertEqual(box.wait_code(time.time(), timeout=0.5), '654321')
        self.assertEqual(box.read.call_count, 3)

    def test_old_timestamp_and_same_time_ambiguity_are_ignored(self):
        box = mail.MailboxAPI(MAIL_URL, EMAIL, session=Mock(), poll_interval=0)
        stamp = time.time()
        ambiguous = mail.parse_messages([otp_message('123456', stamp), otp_message('654321', stamp)], EMAIL)
        old = mail.parse_messages([otp_message('111111', stamp - 600)], EMAIL)
        fresh = mail.parse_messages([otp_message('222222', stamp + 1)], EMAIL)
        box.read = Mock(side_effect=[old, ambiguous, fresh])
        self.assertEqual(box.wait_code(stamp, timeout=0.5), '222222')

    def test_api_redirect_or_auth_error_is_not_followed_or_retried(self):
        for status in (302, 401, 403, 429):
            session = MagicMock()
            response = session.get.return_value.__enter__.return_value
            response.status_code = status
            box = mail.MailboxAPI(MAIL_URL, EMAIL, session=session)
            with self.assertRaises(mail.MailboxError) as caught:
                box.wait_code(time.time(), 0.5)
            self.assertIn(str(status), str(caught.exception))
            self.assertNotIn('mail-private', str(caught.exception))
            session.get.assert_called_once()
            self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
            self.assertNotIn('headers', session.get.call_args.kwargs)
            self.assertFalse(session.trust_env)

    def test_mail_network_failure_redacts_exception_url(self):
        session = Mock()
        session.get.side_effect = RuntimeError(MAIL_URL)
        box = mail.MailboxAPI(MAIL_URL, EMAIL, session=session)
        with self.assertRaises(mail.MailboxError) as error:
            box.read()
        self.assertNotIn('mail-private', str(error.exception))

    def test_mailbox_read_recovers_from_one_dropped_get_within_original_budget(self):
        session = MagicMock()
        context = MagicMock()
        context.__enter__.return_value.status_code = 200
        context.__enter__.return_value.iter_content.return_value = [b'654321']
        session.get.side_effect = [ConnectionError(MAIL_URL), context]
        box = mail.MailboxAPI(MAIL_URL, EMAIL, session=session)
        self.assertEqual([m.code for m in box.read(timeout=3)], ['654321'])
        self.assertEqual(session.get.call_count, 2)
        self.assertLess(session.get.call_args.kwargs['timeout'], 3)

    def test_mailbox_stop_interrupts_connection_retry(self):
        session = Mock()
        stop = threading.Event()
        def interrupted(*args, **kwargs):
            stop.set()
            raise ConnectionError(MAIL_URL)
        session.get.side_effect = interrupted
        box = mail.MailboxAPI(MAIL_URL, EMAIL, stop_event=stop, session=session)
        with self.assertRaises(mail.MailboxError):
            box.read()
        session.get.assert_called_once()

    def test_stop_does_not_read_mail(self):
        stop = threading.Event()
        stop.set()
        box = mail.MailboxAPI(MAIL_URL, EMAIL, stop_event=stop, session=Mock())
        box.read = Mock()
        with self.assertRaises(mail.MailboxError):
            box.wait_code(time.time(), 0.5)
        box.read.assert_not_called()


class ProtocolTests(unittest.TestCase):
    def entry(self):
        return batch.Entry(EMAIL, 'password-private', SECRET, MAIL_URL)

    def setup_flow(self, password_result=None, mailbox=None, reject_otp=False):
        stages, sentinel_flows = [], []
        def action(method, path, options):
            if method == 'GET' and path == '/oauth/authorize':
                return Response(status=302, headers={'location': '/log-in'})
            if method == 'GET' and path == '/log-in':
                return Response(text='<html>Login</html>')
            if path == '/api/accounts/authorize/continue':
                return Response({'page': {'type': 'login_password'}, 'continue_url': '/log-in/password'})
            if path == '/api/accounts/password/verify':
                return password_result or Response({'page': {'type': 'mfa_challenge'},
                    'continue_url': '/mfa-challenge/factor-1', 'oai-client-auth-session': {
                    'mfa_challenge_factors': [{'factor_type': 'totp', 'id': 'factor-1'}]}})
            if path == '/api/accounts/mfa/issue_challenge':
                return Response({})
            if path == '/api/accounts/mfa/verify':
                return Response({'page': {'type': 'email_otp_verification'}, 'continue_url': '/email-verification'})
            if path == '/api/accounts/email-otp/validate':
                if reject_otp and options['json']['code'] == '123456':
                    return Response({'error': {'code': 'invalid_otp'}}, status=400)
                return Response({'continue_url': protocol.REDIRECT + '?code=code-private&state=' + flow.state})
            if path == '/api/accounts/email-otp/resend':
                return Response({})
            if path == '/oauth/token':
                return Response(dict(access_token=jwt({'email': EMAIL}), refresh_token='refresh-private',
                    id_token=jwt({'email': EMAIL, 'aud': protocol.CLIENT_ID,
                                  'https://api.openai.com/auth': {'chatgpt_account_id': 'account-test'}}), expires_in=3600))
            raise AssertionError('Unexpected fixture request ' + method + ' ' + path)
        session = FakeSession(action)
        def sentinel(name):
            sentinel_flows.append(name)
            return {'openai-sentinel-token': 'sentinel-private-' + name}
        flow = protocol.LoginFlow(self.entry(), session, {'lang': 'en-US'}, mailbox=mailbox,
                                 timeout=5, mail_timeout=0.5, on_step=stages.append, sentinel=sentinel)
        return flow, session, stages, sentinel_flows

    def test_password_totp_then_email_continues_to_pkce_exchange(self):
        mailbox = mail.MailboxAPI(MAIL_URL, EMAIL, session=Mock(), poll_interval=0)
        old = mail.parse_messages([otp_message('999999', time.time() - 3600)], EMAIL)
        fresh = mail.parse_messages([otp_message('123456')], EMAIL)
        mailbox.read = Mock(side_effect=[old, old, fresh])
        flow, session, stages, sentinel_flows = self.setup_flow(mailbox=mailbox)
        credential = flow.run()
        self.assertEqual(credential['email'], EMAIL)
        self.assertEqual(credential['account_id'], 'account-test')
        self.assertEqual(credential['chatgpt_account_id'], 'account-test')
        self.assertEqual(credential['client_id'], protocol.CLIENT_ID)
        self.assertEqual(credential['expires_at'], credential['expired'])
        self.assertEqual(stages[-1], 'identity_verified')
        self.assertLess(stages.index('totp_challenge'), stages.index('email_otp_waiting'))
        self.assertEqual(sentinel_flows, ['authorize_continue', 'password_verify', 'password_verify', 'email_otp_validate'])
        submitted = {urlsplit(url).path: opts for method, url, opts in session.calls if method == 'POST'}
        self.assertEqual(submitted['/api/accounts/mfa/verify']['json']['id'], 'factor-1')
        self.assertEqual(submitted['/api/accounts/email-otp/validate']['json'], {'code': '123456'})
        self.assertEqual(submitted['/oauth/token']['data']['code_verifier'], flow.verifier)
        self.assertTrue(all(urlsplit(url).hostname == 'auth.openai.com' for method, url, opts in session.calls))
        self.assertTrue(all(opts['allow_redirects'] is False for method, url, opts in session.calls))
        self.assertNotIn('password-private', json.dumps(stages))
        self.assertNotIn('123456', json.dumps(stages))

    def test_explicit_otp_rejection_only_consumes_a_new_code(self):
        mailbox = Mock()
        mailbox.wait_code.side_effect = ['123456', '654321']
        flow, session, _, sentinel = self.setup_flow(mailbox=mailbox, reject_otp=True)
        flow.run()
        self.assertEqual(mailbox.wait_code.call_count, 2)
        self.assertEqual(sentinel.count('email_otp_validate'), 2)
        self.assertEqual(sum(urlsplit(u).path.endswith('/resend') for _, u, _ in session.calls), 1)

    def workspace_flow(self, workspaces):
        mailbox = Mock()
        mailbox.wait_code.return_value = '654321'
        flow, session, stages, _ = self.setup_flow(mailbox=mailbox)
        original = session.action
        consent = '/sign-in-with-chatgpt/codex/consent'
        def action(method, path, options):
            if path == '/api/accounts/email-otp/validate':
                return Response({'page': {'type': 'consent'}, 'continue_url': consent})
            if method == 'GET' and path == consent:
                session.cookies.set('oai-client-auth-session', jwt({'workspaces': workspaces}),
                                    domain='auth.openai.com')
                return Response(text='<html>Consent</html>')
            if path == '/api/accounts/workspace/select':
                return Response({'continue_url': protocol.REDIRECT + '?code=code-private&state=' + flow.state})
            return original(method, path, options)
        session.action = action
        return flow, session, stages

    def test_consent_get_refreshes_workspace_before_selection(self):
        flow, session, stages = self.workspace_flow([{'id': 'personal-fixture', 'kind': 'personal'}])
        flow.run()
        paths = [urlsplit(url).path for _, url, _ in session.calls]
        self.assertLess(paths.index('/sign-in-with-chatgpt/codex/consent'),
                        paths.index('/api/accounts/workspace/select'))
        self.assertIn('workspace_loading', stages)
        self.assertIn('workspace_selected', stages)
        self.assertEqual(stages[-1], 'identity_verified')

    def test_workspace_jwt_skips_header_and_unrelated_supplied_data(self):
        flow, session, _, _ = self.setup_flow()
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode()
        payload = jwt({'workspaces': [{'id': 'personal-fixture'}]}).split('.')[1]
        session.cookies.set('oai-client-auth-session', header + '.' + payload + '.signature')
        result = flow.session_data({'oai-client-auth-session': {'other': True}}, ('workspaces',))
        self.assertEqual(result['workspaces'], [{'id': 'personal-fixture'}])

    def test_json_workspace_session_survives_html_redirect_without_legacy_cookie(self):
        mailbox = Mock()
        mailbox.wait_code.return_value = '654321'
        flow, session, _, _ = self.setup_flow(mailbox=mailbox)
        original = session.action
        consent = '/sign-in-with-chatgpt/codex/consent'
        def action(method, path, options):
            if path == '/api/accounts/email-otp/validate':
                return Response({'page': {'type': 'redirect'}, 'continue_url': consent,
                    'oai-client-auth-session': {'workspaces': [{'id': 'personal-fixture', 'kind': 'personal'}]}})
            if method == 'GET' and path == consent:
                return Response(text='<html>Consent</html>')
            if path == '/api/accounts/workspace/select':
                self.assertEqual(options['json'], {'workspace_id': 'personal-fixture'})
                return Response({'continue_url': protocol.REDIRECT + '?code=code-private&state=' + flow.state})
            return original(method, path, options)
        session.action = action
        flow.run()
        self.assertFalse(any(cookie.name == 'oai-client-auth-session' for cookie in session.cookies))
        self.assertTrue(any(urlsplit(url).path == '/oauth/token' for _, url, _ in session.calls))

    def test_current_json_session_replaces_previous_workspace_snapshot(self):
        flow, _, _, _ = self.setup_flow()
        flow.session_data({'oai-client-auth-session': {'workspaces': [{'id': 'stale'}]}})
        self.assertEqual(flow.session_data({'oai-client-auth-session': {'workspaces': []}}, ('workspaces',)),
                         {'workspaces': []})
        self.assertEqual(flow.session_data({}, ('workspaces',)), {'workspaces': []})

    def test_missing_or_ambiguous_workspaces_stop_without_guessing(self):
        for workspaces, code in (([], 'workspace_data_missing'),
                ([{'id': 'team-one'}, {'id': 'team-two'}], 'workspace_selection_required')):
            with self.subTest(code=code):
                flow, session, _ = self.workspace_flow(workspaces)
                with self.assertRaises(protocol.ProtocolError) as error:
                    flow.run()
                self.assertEqual(error.exception.code, code)
                paths = [urlsplit(url).path for _, url, _ in session.calls]
                self.assertEqual(paths.count('/sign-in-with-chatgpt/codex/consent'), 1)
                self.assertNotIn('/api/accounts/workspace/select', paths)
                self.assertNotIn('/oauth/token', paths)

    def test_unique_personal_workspace_is_selected_among_teams(self):
        flow, session, _ = self.workspace_flow([
            {'id': 'team-one', 'kind': 'team'}, {'id': 'personal-fixture', 'kind': 'personal'}])
        flow.run()
        submitted = next(opts['json'] for _, url, opts in session.calls
                         if urlsplit(url).path == '/api/accounts/workspace/select')
        self.assertEqual(submitted, {'workspace_id': 'personal-fixture'})

    def test_429_stops_before_totp_and_is_not_retried(self):
        flow, session, _, _ = self.setup_flow(password_result=Response({'error': {'code': 'rate_limit_exceeded'}}, 429))
        with self.assertRaises(protocol.ProtocolError) as error:
            flow.run()
        self.assertEqual(error.exception.upstream_status, 429)
        self.assertEqual(sum(urlsplit(u).path.endswith('/password/verify') for _, u, _ in session.calls), 1)
        self.assertFalse(any('/mfa/' in u for _, u, _ in session.calls))

    def test_missing_email_api_stops_without_token_exchange(self):
        flow, session, _, _ = self.setup_flow()
        with self.assertRaisesRegex(protocol.ProtocolError, '邮箱 API'):
            flow.run()
        self.assertFalse(any('/oauth/token' in u for _, u, _ in session.calls))

    def test_multiple_totp_factors_are_not_guessed(self):
        data = {'page': {'type': 'mfa_challenge'}, 'oai-client-auth-session': {
            'mfa_challenge_factors': [{'factor_type': 'totp', 'id': 'one'}, {'factor_type': 'totp', 'id': 'two'}]}}
        flow, session, _, _ = self.setup_flow(password_result=Response(data))
        with self.assertRaisesRegex(protocol.ProtocolError, '多个候选'):
            flow.run()
        self.assertFalse(any('/mfa/' in u for _, u, _ in session.calls))

    def test_phone_gate_is_reported_and_never_treated_as_email(self):
        flow, session, _, _ = self.setup_flow(password_result=Response({'page': {'type': 'add_phone'},
                                                                     'continue_url': '/add-phone'}))
        with self.assertRaisesRegex(protocol.ProtocolError, '手机号'):
            flow.run()
        self.assertFalse(any('/email-otp/' in u for _, u, _ in session.calls))

    def test_callback_is_exact_and_state_is_unique(self):
        good = protocol.REDIRECT + '?state=state-private&code=code-private'
        self.assertEqual(protocol.callback_code(good, 'state-private'), 'code-private')
        for bad in (good.replace(':1455', ':9999'), good.replace('/auth/callback', '/auth/callback/'),
                    good + '&state=state-private', good + '&code=extra',
                    good.replace('localhost', 'evil.test'), good + '#fragment'):
            with self.subTest(url=bad), self.assertRaises(protocol.ProtocolError) as error:
                protocol.callback_code(bad, 'state-private')
            self.assertNotIn('code-private', str(error.exception))

    def test_foreign_redirect_receives_no_request(self):
        flow, session, _, _ = self.setup_flow()
        with self.assertRaises(protocol.ProtocolError):
            flow.navigate('https://evil.test/collect')
        self.assertEqual(session.calls, [])

    def test_first_navigation_and_its_redirects_have_no_fabricated_referrer(self):
        flow, session, _, _ = self.setup_flow()
        flow.navigate(protocol.AUTH + '/oauth/authorize')
        self.assertEqual(len(session.calls), 2)
        for _, _, options in session.calls:
            self.assertEqual(options['headers']['sec-fetch-site'], 'none')
            self.assertEqual(options['headers']['sec-fetch-user'], '?1')
            self.assertNotIn('referer', options['headers'])
        flow.navigate(protocol.AUTH + '/log-in')
        self.assertEqual(session.calls[-1][2]['headers']['sec-fetch-site'], 'same-origin')
        self.assertEqual(session.calls[-1][2]['headers']['referer'], protocol.AUTH + '/log-in')

    def test_memoryview_location_is_decoded_before_oauth_navigation(self):
        from login_vendor.http_client_wreq import _Headers
        flow, session, _, _ = self.setup_flow()
        original = session.action
        def action(method, path, options):
            if path == '/oauth/authorize':
                result = Response(status=302)
                result.headers = _Headers({'location': memoryview(b'/log-in')})
                return result
            return original(method, path, options)
        session.action = action
        data = flow.navigate(protocol.AUTH + '/oauth/authorize')
        self.assertEqual(data['page']['type'], 'login')
        self.assertEqual([urlsplit(url).path for _, url, _ in session.calls], ['/oauth/authorize', '/log-in'])

    def test_native_header_iteration_and_values_decode_all_buffer_types(self):
        from login_vendor.http_client_wreq import _Headers
        class NativeHeaders:
            def get(self, key):
                return None
            def __iter__(self):
                return iter([(memoryview(b'Content-Type'), memoryview(b'text/html')),
                             (bytearray(b'Location'), bytearray(b'/log-in'))])
            def get_all(self, key):
                return [memoryview(b'one'), bytearray(b'two')]
        headers = _Headers(NativeHeaders())
        self.assertEqual(headers.get('content-type'), 'text/html')
        self.assertEqual(headers.get('location'), '/log-in')
        self.assertEqual(headers.get_list('fixture'), ['one', 'two'])

    def test_totp_matches_rfc_vector(self):
        self.assertEqual(protocol.totp(SECRET, 59), '287082')

    def test_real_transport_constructs_matching_profile_without_network(self):
        with patch.object(protocol, 'detect_exit', return_value=dict(
                exit_ip='8.8.8.8', country_code='US', timezone='America/Los_Angeles')):
            session, fp = protocol.make_session('http://127.0.0.1:9', 'US')
        try:
            self.assertIn(fp['impersonate'], {'chrome140', 'chrome145', 'chrome146', 'chrome149'})
            major = fp['user_agent'].split('Chrome/', 1)[1].split('.', 1)[0]
            self.assertEqual(fp['impersonate'], 'chrome' + major)
            self.assertIn('Chrome/152.', session.headers['user-agent'])
            self.assertIn('v="152"', session.headers['sec-ch-ua'])
            self.assertIn(session._impersonate, {'Chrome140', 'Chrome145', 'Chrome146', 'Chrome149'})
            self.assertEqual(session._platform, 'Windows')
            self.assertEqual(session._retries, 0)
            self.assertIsNone(fp['tls_fp'])
            self.assertIsNone(fp['akamai_fp'])
        finally:
            session.close()

    def test_local_dispatch_never_submits_backend_login(self):
        client, journal = Mock(), Mock()
        with patch('local_login_service.login_local', return_value={'access_token': 'private'}) as local:
            result = batch.perform_login(client, self.entry(), SimpleNamespace(login_engine='local'), journal, {'proxy_id': 1})
        client.request.assert_not_called()
        local.assert_called_once()
        self.assertEqual(result['access_token'], 'private')

    def test_passwordless_email_form_uses_mail_api(self):
        mailbox = Mock()
        mailbox.wait_code.return_value = '654321'
        flow, session, _, _ = self.setup_flow(mailbox=mailbox)
        flow.entry = batch.Entry(EMAIL, '', '', MAIL_URL)
        original = session.action
        def action(method, path, options):
            if path == '/api/accounts/passwordless/send-otp':
                return Response({})
            return original(method, path, options)
        session.action = action
        result = flow.run()
        self.assertEqual(result['email'], EMAIL)
        self.assertFalse(any('/password/verify' in url or '/mfa/' in url for _, url, _ in session.calls))
        self.assertTrue(any('/passwordless/send-otp' in url for _, url, _ in session.calls))

    def test_email_send_navigation_is_consumed_before_polling(self):
        mailbox = Mock()
        mailbox.wait_code.return_value = '654321'
        initial = Response({'page': {'type': 'email_otp_send'}, 'continue_url': '/api/accounts/email-otp/send'})
        flow, session, _, _ = self.setup_flow(password_result=initial, mailbox=mailbox)
        original = session.action
        def action(method, path, options):
            if path == '/api/accounts/email-otp/send':
                return Response(status=307, headers={'location': '/email-verification'})
            if path == '/email-verification':
                return Response(text='<html>Email verification</html>')
            return original(method, path, options)
        session.action = action
        flow.run()
        self.assertTrue(any(method == 'GET' and urlsplit(url).path == '/api/accounts/email-otp/send'
                            for method, url, options in session.calls))
        mailbox.wait_code.assert_called_once()

    def test_unknown_network_outcome_does_not_replay_password(self):
        flow, session, _, _ = self.setup_flow()
        original = session.action
        def action(method, path, options):
            if path == '/api/accounts/password/verify':
                raise TimeoutError('password-private ' + MAIL_URL)
            return original(method, path, options)
        session.action = action
        with self.assertRaises(protocol.ProtocolError) as error:
            flow.run()
        self.assertNotIn('password-private', str(error.exception))
        self.assertNotIn('mail-private', str(error.exception))
        self.assertEqual(sum(urlsplit(u).path.endswith('/password/verify') for _, u, _ in session.calls), 1)

    def test_initial_mail_snapshot_failure_sends_no_auth_request(self):
        mailbox = Mock()
        mailbox.snapshot.side_effect = mail.MailboxError('邮箱 API 返回 HTTP 401')
        flow, session, _, _ = self.setup_flow(mailbox=mailbox)
        with self.assertRaises(mail.MailboxError):
            flow.run()
        self.assertEqual(session.calls, [])

    def test_authorize_has_matching_pkce_and_token_exchange_has_no_password(self):
        mailbox = Mock()
        mailbox.wait_code.return_value = '654321'
        flow, session, _, _ = self.setup_flow(mailbox=mailbox)
        flow.run()
        params = parse_qs(urlsplit(session.calls[0][1]).query)
        expected = base64.urlsafe_b64encode(protocol.hashlib.sha256(flow.verifier.encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(params['code_challenge'], [expected])
        token_call = next(opts for _, url, opts in session.calls if urlsplit(url).path == '/oauth/token')
        self.assertEqual(set(token_call['data']), {'grant_type', 'client_id', 'code', 'redirect_uri', 'code_verifier'})

    def test_local_route_change_never_imports_new_credential(self):
        client = batch.SafeClient('https://site.example', EMAIL, None, 'admin-private', 2, direct=True)
        client.request = Mock(return_value={'configured': True})
        args = SimpleNamespace(login_engine='local', dry_run=False, max_per_ip=4, max_latency=300,
                               models=None, job_timeout=2, mail_timeout=0.5)
        chosen = dict(proxy_id=1, exit_ip='192.0.2.1')
        with patch.object(batch, 'existing_account', return_value=None), \
             patch.object(batch.ProxyPicker, 'choose', return_value=chosen), \
             patch.object(batch.ProxyPicker, 'recheck', return_value=dict(proxy_id=2, exit_ip='192.0.2.2')), \
             patch.object(batch, 'perform_login', return_value={'access_token': 'private'}), \
             patch.object(batch, 'import_new') as importer:
            rows = batch.run_batch(client, [self.entry()], args, Mock(), Mock(), group_ids=[6])
        importer.assert_not_called()
        self.assertEqual(rows[0]['status'], 'failed')
        self.assertIn('代理出口发生变化', rows[0]['message'])

    def test_legacy_backend_refuses_to_silently_drop_mailbox_url(self):
        client = Mock()
        with self.assertRaisesRegex(batch.ApiError, '本地协议'):
            batch.perform_login(client, self.entry(), SimpleNamespace(login_engine='backend'), Mock())
        client.request.assert_not_called()

    def test_sentinel_http_error_reports_stage_without_raw_response(self):
        flow, session, _, _ = self.setup_flow()
        flow.sentinel_provider = None
        session._sentinel_last_step, session._sentinel_last_http_status = 'sdk', 403
        with patch('login_vendor.sentinel_quickjs.get_sentinel_token_via_quickjs', return_value=None):
            with self.assertRaisesRegex(protocol.ProtocolError, 'Sentinel SDK.*403'):
                flow.sentinel_headers('password_verify')
        self.assertEqual(session.calls, [])


if __name__ == '__main__':
    unittest.main()
