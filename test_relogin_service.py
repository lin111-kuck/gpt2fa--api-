"""Real loopback HTTP with a fake login engine; no upstream account requests."""
import http.client
import json
import threading
import unittest
from unittest.mock import Mock

import relogin_service as service
import batch_login as batch
from test_protocol_login import EMAIL, SECRET, MAIL_URL, jwt

KEY = 'fixture-private-service-key-0123456789'


def credential(email=EMAIL):
    return {'access_token': jwt({'email': email}), 'refresh_token': 'refresh-private',
            'id_token': jwt({'email': email}), 'email': email}


def payload(**updates):
    return dict(action='start', auth_mode='password_2fa', email=EMAIL,
                password='password-private', mfa_secret=SECRET, **updates)


class ReloginServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock(return_value=credential())
        self.config = service.Config('http://127.0.0.1:9', country_code='US',
                                     mailboxes={EMAIL: MAIL_URL}, workers=1, heartbeat=0.02)
        self.server = service.make_server(('127.0.0.1', 0), self.config, KEY, login_fn=self.engine)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.connections = []

    def tearDown(self):
        for connection in self.connections:
            connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def request(self, body=None, key=KEY, path='/api/v1/relogin', method='POST', headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        self.connections.append(connection)
        hdrs = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key}
        hdrs.update(headers or {})
        connection.request(method, path, json.dumps(payload() if body is None else body), hdrs)
        return connection.getresponse()

    def events(self, response):
        return [json.loads(line) for line in response.read().splitlines()]

    def test_original_ranxi_request_gets_compatible_credential_envelope(self):
        response = self.request()
        self.assertEqual(response.status, 200)
        self.assertIn('application/x-ndjson', response.getheader('Content-Type'))
        event = self.events(response)[-1]
        self.assertEqual(event['type'], 'result')
        self.assertEqual(event['payload']['credential'], credential())
        self.assertEqual(event['payload']['status'], 'success')
        entry = self.engine.call_args.args[0]
        self.assertEqual(entry.mail_url, MAIL_URL)
        self.assertEqual(entry.password, 'password-private')
        self.assertEqual(self.engine.call_args.args[1], self.config.proxy_url)
        self.assertEqual(self.engine.call_args.kwargs['expected_exit_ip'], '')
        self.assertTrue(callable(self.engine.call_args.kwargs['on_network']))

    def test_account_route_controls_login_proxy_and_expected_exit(self):
        self.config.account_proxies[EMAIL] = {
            'proxy_url': 'http://127.0.0.1:20202', 'expected_exit_ip': '8.8.8.8', 'country_code': 'US'}
        response = self.request()
        self.assertEqual(self.events(response)[-1]['payload']['status'], 'success')
        self.assertEqual(self.engine.call_args.args[1], 'http://127.0.0.1:20202')
        self.assertEqual(self.engine.call_args.kwargs['expected_exit_ip'], '8.8.8.8')
        self.assertEqual(self.engine.call_args.kwargs['country_code'], 'US')

    def test_account_route_validation_rejects_invalid_routes_and_duplicates(self):
        for mapping in ({EMAIL: {'proxy_url': 'http://localhost'}},
                        {EMAIL: {'proxy_url': 'http://localhost:9', 'unexpected': True}},
                        {EMAIL: {'proxy_url': 'http://localhost:9', 'expected_exit_ip': 'invalid'}},
                        {EMAIL: {'proxy_url': 'http://localhost:9'}, EMAIL.upper(): {'proxy_url': 'http://localhost:10'}}):
            with self.assertRaises(ValueError):
                service.Config('http://localhost:9', account_proxies=mapping).validate()

    def test_account_route_names_are_normalized_without_exposing_secrets(self):
        config = service.Config('http://localhost:9', account_proxies={EMAIL.upper(): {
            'proxy_url': 'http://user:private-route-password@localhost:10'}}).validate()
        self.assertIn(EMAIL, config.account_proxies)
        self.assertNotIn('private-route-password', repr(config))

    def test_network_progress_reports_matching_without_exposing_other_fields(self):
        def progressing(*args, **kwargs):
            kwargs['on_network'](dict(phase='matched', exit_ip='8.8.8.8', country_code='US',
                                     timezone='America/Los_Angeles', browser='Chrome152',
                                     password='password-private', mail_url=MAIL_URL))
            kwargs['on_network'](dict(phase='unknown', exit_ip='8.8.8.8'))
            kwargs['on_network'](dict(phase='verified', exit_ip='8.8.8.8'))
            return credential()
        self.engine.side_effect = progressing
        events = self.events(self.request())
        self.assertEqual(events[0]['payload']['stage'], 'network_matched')
        self.assertEqual(events[0]['payload']['timezone'], 'America/Los_Angeles')
        self.assertEqual(events[1]['payload']['stage'], 'network_verified')
        self.assertEqual(events[-1]['payload']['status'], 'success')
        self.assertNotIn('password-private', json.dumps(events))
        self.assertNotIn('mail-private', json.dumps(events))

    def test_configured_ip_and_country_are_passed_as_expectations(self):
        self.config.country_code = 'JP'
        self.config.expected_exit_ip = '8.8.8.8'
        self.events(self.request())
        self.assertEqual(self.engine.call_args.kwargs['country_code'], 'JP')
        self.assertEqual(self.engine.call_args.kwargs['expected_exit_ip'], '8.8.8.8')

    def test_network_failure_returns_specific_code_without_credential(self):
        self.engine.side_effect = service.ProtocolError('fixture', 'exit_ip_mismatch')
        events = self.events(self.request())
        self.assertEqual(events[-1]['payload']['error']['code'], 'exit_ip_mismatch')
        self.assertNotIn('credential', events[-1]['payload'])

    def test_explicit_mailbox_url_overrides_mapping(self):
        other = 'https://mail.example.test/?e=' + EMAIL + '&token=override-private'
        response = self.request(payload(otp_url=other))
        self.events(response)
        self.assertEqual(self.engine.call_args.args[0].mail_url, other)

    def test_invalid_auth_does_not_start_login(self):
        response = self.request(key='wrong-private')
        self.assertEqual(response.status, 401)
        self.engine.assert_not_called()
        self.assertNotIn(KEY, response.read().decode())

    def test_recipient_mismatch_is_rejected_before_login(self):
        response = self.request(payload(otp_url='https://mail.example.test/?email=other@example.com'))
        self.assertEqual(response.status, 400)
        self.engine.assert_not_called()

    def test_unsupported_action_does_not_start_login(self):
        data = payload()
        data['action'] = 'delete'
        self.assertEqual(self.request(data).status, 400)
        self.engine.assert_not_called()

    def test_mismatched_returned_identity_is_not_exposed(self):
        self.engine.return_value = credential('other@example.com')
        events = self.events(self.request())
        self.assertNotIn('credential', events[-1]['payload'])
        self.assertEqual(events[-1]['payload']['status'], 'failed')
        self.assertNotIn('refresh-private', json.dumps(events))

    def test_runtime_exception_is_redacted(self):
        self.engine.side_effect = RuntimeError('password-private ' + MAIL_URL)
        events = self.events(self.request())
        self.assertEqual(events[-1]['payload']['error']['code'], 'relogin_failed')
        self.assertNotIn('password-private', json.dumps(events))
        self.assertNotIn('mail-private', json.dumps(events))

    def test_heartbeat_prevents_backend_idle_timeout_and_concurrency_is_bounded(self):
        release = threading.Event()
        def waiting(*args, **kwargs):
            release.wait(2)
            return credential()
        self.engine.side_effect = waiting
        first = self.request()
        try:
            heartbeat = json.loads(first.readline())
            self.assertEqual(heartbeat, {'type': 'heartbeat'})
            second = self.request()
            self.assertEqual(second.status, 429)
            self.assertEqual(json.loads(second.read())['error']['code'], 'busy')
        finally:
            release.set()
        self.assertEqual(self.events(first)[-1]['payload']['status'], 'success')

    def test_progress_has_no_credentials_and_ignores_unknown_stage(self):
        def progressing(*args, **kwargs):
            kwargs['on_step']('email_otp_waiting')
            kwargs['on_step'](MAIL_URL)
            return credential()
        self.engine.side_effect = progressing
        events = self.events(self.request())
        self.assertEqual(events[0], {'type': 'progress', 'payload': {'stage': 'email_otp_waiting'}})
        self.assertNotIn('mail-private', json.dumps(events))

    def test_health_request_does_not_call_login_engine(self):
        response = self.request(method='GET', path='/health')
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read()), {'status': 'ok'})
        self.engine.assert_not_called()

    def test_config_hides_proxy_and_mailbox_material(self):
        config = service.Config('http://user:proxy-private@127.0.0.1:9', mailboxes={EMAIL: MAIL_URL})
        self.assertNotIn('proxy-private', repr(config))
        self.assertNotIn('mail-private', repr(config))
        with self.assertRaises(ValueError):
            service.make_server(('127.0.0.1', 0), self.config, 'short')

    def test_service_credential_can_be_imported_and_read_back_in_sub2api(self):
        result = self.events(self.request())[-1]['payload']['credential']
        client = Mock()
        chosen = dict(proxy_id=9, exit_ip='192.0.2.9', proxy_name='fixture', latency_ms=10, relaxed_latency=False)
        def request(method, path, body=None):
            if method == 'POST' and path == batch.IMPORT:
                self.assertEqual(json.loads(body['content']), result)
                self.assertEqual(body['proxy_id'], 9)
                self.assertEqual(body['group_ids'], [6, 15])
                self.assertFalse(body['update_existing'])
                return dict(created=1, updated=0, skipped=0, failed=0, items=[dict(action='created', account_id=17)])
            if method == 'GET' and path == '/api/v1/admin/accounts/17':
                return dict(id=17, proxy_id=9, group_ids=[6, 15])
            if method == 'POST' and path == batch.OPS + '/accounts':
                self.assertEqual(body['account_id'], 17)
                self.assertEqual(body['login_email'], EMAIL)
                return {'account_id': 17}
            raise AssertionError('Unexpected backend fixture request')
        client.request.side_effect = request
        client.list_proxies.return_value = [dict(id=9, ip_address='192.0.2.9', account_count=1)]
        entry = service.parse_request(payload(), self.config)
        outcome = batch.import_new(client, entry, result, chosen, [6, 15], None, Mock())
        self.assertEqual(outcome['status'], 'created')
        self.assertEqual(outcome['account_id'], 17)


if __name__ == '__main__':
    unittest.main()
