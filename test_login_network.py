"""Offline exit/fingerprint checks. All IP lookup and account responses are fixtures."""
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import batch_login as batch
import local_login_service as local
import protocol_login as protocol
from test_protocol_login import EMAIL, FakeSession, Response

PROXY = 'http://proxy-user:proxy-private@127.0.0.1:8080'


def location(ip='8.8.8.8', country='US', tz='America/Los_Angeles'):
    return dict(success=True, ip=ip, country_code=country, timezone={'id': tz})


class NetworkTests(unittest.TestCase):
    def session(self, responses):
        pending = iter(responses)
        session = FakeSession(lambda *args: next(pending))
        session.close = Mock()
        return session

    def test_ipv4_transport_owns_bridge_lifetime_and_keeps_upstream_secret_out_of_url(self):
        session = self.session([Response(location())])
        original_close = session.close
        with patch('login_vendor.http_client_wreq.WreqSession', return_value=session) as transport:
            actual, _ = protocol.make_session(PROXY, ipv4_only=True)
        address = transport.call_args.kwargs['proxy']
        self.assertTrue(address.startswith('http://127.0.0.1:'))
        self.assertNotIn('proxy-private', address)
        actual.close()
        actual.close()
        original_close.assert_called_once()

    def test_profile_uses_detected_country_and_exact_city_timezone(self):
        for country, tz, language in [('US', 'America/Phoenix', 'en-US'),
                                      ('JP', 'Asia/Tokyo', 'ja-JP'),
                                      ('DE', 'Europe/Berlin', 'de-DE')]:
            with self.subTest(country=country):
                session = self.session([Response(location(country=country, tz=tz))])
                with patch('login_vendor.http_client_wreq.WreqSession', return_value=session) as transport:
                    actual, fp = protocol.make_session(PROXY)
                self.assertIs(actual, session)
                profile = transport.call_args.kwargs['impersonate']
                self.assertIn(profile, {'Chrome140', 'Chrome145', 'Chrome146', 'Chrome149'})
                transport.assert_called_once_with(proxy=PROXY, impersonate=profile,
                                                  platform='Windows', retries=0)
                self.assertEqual(fp['country_code'], country)
                self.assertEqual(fp['timezone'], tz)
                self.assertEqual(fp['lang'], language)
                self.assertEqual(fp['exit_ip'], '8.8.8.8')
                self.assertEqual(session.headers['accept-language'], fp['lang_full'])
                self.assertEqual(session.headers['user-agent'], fp['user_agent'])
                major = fp['user_agent'].split('Chrome/', 1)[1].split('.', 1)[0]
                self.assertEqual(profile, 'Chrome' + major)
                self.assertIn(f'v="{major}"', session.headers['sec-ch-ua'])
                self.assertIsNone(fp['tls_fp'])
                self.assertIsNone(fp['akamai_fp'])
                self.assertFalse(session.calls[0][2]['allow_redirects'])

    def test_invalid_exit_data_never_reaches_authentication(self):
        invalid = [Response(status=302), Response(status=429), Response(),
                   Response([]), Response({'success': False}),
                   Response(dict(location(), ip=None)), Response(dict(location(), ip='not-an-ip')),
                   Response(location(ip='127.0.0.1')), Response(location(ip='10.0.0.1')),
                   Response(location(ip='224.0.0.1')), Response(location(country='')),
                   Response(location(country='ZZ')), Response(location(tz='America/Not_A_City')),
                   Response(dict(location(), timezone=None)), Response(location(tz='../UTC'))]
        for response in invalid:
            with self.subTest(data=response.data, status=response.status_code):
                session = self.session([response])
                with patch('login_vendor.http_client_wreq.WreqSession', return_value=session), \
                     patch.object(protocol, 'LoginFlow') as flow:
                    with self.assertRaises(protocol.ProtocolError):
                        protocol.login(batch.Entry(EMAIL, 'fixture-private', ''), PROXY)
                flow.assert_not_called()
                session.close.assert_called_once()
                self.assertEqual([call[1] for call in session.calls], [protocol.EXIT_LOOKUP])

    def test_lookup_exception_is_redacted_and_does_not_fall_back_to_direct(self):
        session = self.session([])
        session.action = Mock(side_effect=RuntimeError(PROXY))
        with patch('login_vendor.http_client_wreq.WreqSession', return_value=session) as transport:
            with self.assertRaises(protocol.ProtocolError) as error:
                protocol.make_session(PROXY)
        self.assertEqual(error.exception.code, 'exit_detection_failed')
        self.assertNotIn('proxy-private', str(error.exception))
        transport.assert_called_once()
        self.assertEqual(len(session.calls), 1)
        session.close.assert_called_once()

    def test_missing_or_invalid_proxy_cannot_silently_use_direct_connection(self):
        for proxy in ('', None, 'http://proxy.test', 'ftp://proxy.test:21',
                      'http://proxy.test:8080/path', 'http://proxy.test:8080?password=private'):
            with self.subTest(proxy=proxy), patch('login_vendor.http_client_wreq.WreqSession') as transport:
                with self.assertRaises(protocol.ProtocolError) as error:
                    protocol.make_session(proxy)
                self.assertEqual(error.exception.code, 'proxy_required')
                transport.assert_not_called()

    def test_expected_ip_and_country_are_guards_not_profile_overrides(self):
        for options, code in [({'expected_exit_ip': '1.1.1.1'}, 'exit_ip_mismatch'),
                               ({'country_code': 'JP'}, 'exit_country_mismatch')]:
            with self.subTest(options=options):
                session = self.session([Response(location())])
                with patch('login_vendor.http_client_wreq.WreqSession', return_value=session), \
                     patch.object(protocol, 'LoginFlow') as flow:
                    with self.assertRaises(protocol.ProtocolError) as error:
                        protocol.login(batch.Entry(EMAIL, 'fixture-private', ''), PROXY, **options)
                self.assertEqual(error.exception.code, code)
                flow.assert_not_called()

    def test_same_session_is_used_for_matching_auth_and_final_check(self):
        session = self.session([Response(location()), Response(location())])
        steps, networks, calls = [], [], []
        credential = {'fixture': 'private-token'}
        def run_flow(entry, actual_session, fp, **kwargs):
            self.assertIs(actual_session, session)
            calls.append((actual_session, fp))
            self.assertEqual(fp['timezone'], 'America/Los_Angeles')
            self.assertNotIn('login_verified', steps)
            return SimpleNamespace(run=lambda: credential)
        with patch('login_vendor.http_client_wreq.WreqSession', return_value=session) as transport, \
             patch.object(protocol, 'LoginFlow', side_effect=run_flow):
            result = protocol.login(batch.Entry(EMAIL, '', ''), PROXY, timeout=30,
                                    on_step=steps.append, on_network=networks.append)
        self.assertIs(result, credential)
        transport.assert_called_once()
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(session.calls), 2)
        self.assertTrue(all(url == protocol.EXIT_LOOKUP for _, url, _ in session.calls))
        self.assertTrue(all(0 < opts['timeout'] <= 15 for _, _, opts in session.calls))
        self.assertEqual(steps, ['network_checking', 'network_verifying', 'login_verified'])
        self.assertEqual([item['phase'] for item in networks], ['matched', 'verified'])
        self.assertNotIn('private-token', str(networks))
        session.close.assert_called_once()

    def test_exit_changes_after_login_never_return_credentials_or_success(self):
        for final, code in [(location(ip='1.1.1.1'), 'exit_ip_mismatch'),
                            (location(country='JP', tz='Asia/Tokyo'), 'exit_country_mismatch'),
                            (location(tz='America/New_York'), 'exit_timezone_changed'),
                            ({'success': False}, 'exit_detection_failed')]:
            with self.subTest(final=final):
                session = self.session([Response(location()), Response(final)])
                steps, networks = [], []
                with patch('login_vendor.http_client_wreq.WreqSession', return_value=session), \
                     patch.object(protocol, 'LoginFlow') as flow:
                    flow.return_value.run.return_value = {'access_token': 'private-token'}
                    with self.assertRaises(protocol.ProtocolError) as error:
                        protocol.login(batch.Entry(EMAIL, '', ''), PROXY,
                                       on_step=steps.append, on_network=networks.append)
                self.assertEqual(error.exception.code, code)
                self.assertNotIn('login_verified', steps)
                self.assertEqual([item['phase'] for item in networks], ['matched'])
                session.close.assert_called_once()

    def test_stop_before_lookup_sends_no_network_request(self):
        stop = threading.Event()
        stop.set()
        with patch('login_vendor.http_client_wreq.WreqSession') as transport:
            with self.assertRaises(batch.BatchStopped):
                protocol.login(batch.Entry(EMAIL, '', ''), PROXY, stop_event=stop)
        transport.assert_not_called()

    def test_timeout_during_lookup_never_submits_account(self):
        session = self.session([Response(location())])
        with patch('login_vendor.http_client_wreq.WreqSession', return_value=session), \
             patch.object(protocol, 'LoginFlow') as flow, \
             patch.object(protocol.time, 'monotonic', side_effect=[0, 0, 0, 31]):
            with self.assertRaisesRegex(protocol.ProtocolError, '超时'):
                protocol.login(batch.Entry(EMAIL, '', ''), PROXY, timeout=30)
        flow.assert_not_called()
        session.close.assert_called_once()

    def test_ipv6_addresses_are_compared_canonically(self):
        session = self.session([Response(location(ip='2001:4860:4860::8888'))])
        result = protocol.detect_exit(session, '2001:4860:4860:0:0:0:0:8888')
        self.assertEqual(result['exit_ip'], '2001:4860:4860::8888')

    def test_sentinel_receives_the_same_timezone_language_and_ua_as_transport(self):
        session = self.session([Response(location(country='JP', tz='Asia/Tokyo'))])
        with patch('login_vendor.http_client_wreq.WreqSession', return_value=session):
            _, fp = protocol.make_session(PROXY)
        flow = protocol.LoginFlow(batch.Entry(EMAIL, '', ''), session, fp)
        with patch('login_vendor.sentinel_quickjs.get_sentinel_token_via_quickjs',
                   return_value=('fixture-token', None)) as sentinel:
            flow.sentinel_headers('password_verify')
        kwargs = sentinel.call_args.kwargs
        self.assertIs(sentinel.call_args.args[0], session)
        self.assertEqual(kwargs['timezone'], 'Asia/Tokyo')
        self.assertEqual(kwargs['lang'], 'ja-JP')
        self.assertEqual(kwargs['lang_full'], session.headers['accept-language'])
        self.assertEqual(kwargs['user_agent'], session.headers['user-agent'])

    def test_workbench_passes_selected_sub2api_ip_to_shared_login_engine(self):
        client, journal = Mock(), Mock()
        client.secrets = []
        client.list_proxies.return_value = [dict(id=9, protocol='http', host='proxy.test', port=80)]
        chosen = dict(proxy_id=9, exit_ip='8.8.8.8')
        args = SimpleNamespace(job_timeout=30, mail_timeout=10, gateway=None)
        bridge = Mock(profile={'port': 12345})
        with patch.object(local, 'ProxyBridge') as factory, patch.object(protocol, 'login') as engine:
            factory.return_value.__enter__.return_value = bridge
            engine.return_value = {'email': EMAIL}
            with patch.object(batch, 'verify_login_identity'):
                local.login_local(client, batch.Entry(EMAIL, '', ''), chosen, args, journal)
        self.assertEqual(engine.call_args.kwargs['expected_exit_ip'], '8.8.8.8')
        self.assertEqual(engine.call_args.args[1], 'http://127.0.0.1:12345')
        bridge.verify_exit.assert_not_called()  # No separate urllib transport for the new engine.
        engine.call_args.kwargs['on_network'](dict(phase='matched', exit_ip='8.8.8.8'))
        self.assertEqual(journal.call_args.args, ('login_network',))


if __name__ == '__main__':
    unittest.main()
