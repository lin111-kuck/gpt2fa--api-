"""Offline mailbox contract tests; no authentication or real mailbox requests."""
import json
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from mailbox_api import MailboxAPI, MailboxError, parse_messages

EMAIL = 'person@example.com'
URL = 'https://mail.example.test/otp?token=fixture-private'


def reply(payload):
    context = MagicMock()
    response = context.__enter__.return_value
    response.status_code = 200
    response.iter_content.return_value = [json.dumps(payload).encode()]
    return context


class MailboxContractTests(unittest.TestCase):
    def test_no_code_reply_never_exposes_an_old_code_in_body_or_nested_data(self):
        states = [{'code': marker} for marker in (
            'no_code', 'nocode', 'no-code', 'none', 'null', 'pending',
            'empty', 'waiting', 'not_found', 'notfound', None, '', '  ')]
        states.extend([{'status': 'pending'}, {'success': False, 'retryable': True},
                       {'ok': False, 'code': 'no_code', 'retryable': True}])
        for state in states:
            payload = {**state, 'body': 'Verification code: 123456',
                       'data': {'otp': '654321', 'email': EMAIL}}
            with self.subTest(state=state):
                self.assertEqual(parse_messages(payload, EMAIL), [])
                self.assertEqual(parse_messages({'result': payload}, EMAIL), [])

    def test_json_aliases_preserve_time_and_recipient_checks(self):
        for field in ('verificationCode', 'verify_code', 'VeRiFiCaTiOn_CoDe'):
            for date_field in ('receivedAt', 'ts', 'time'):
                payload = {'success': True, 'data': {field: '012345', date_field: 1794929150000,
                           'recipient': EMAIL, 'sender': 'otp@tm.openai.com'}}
                with self.subTest(field=field, date_field=date_field):
                    messages = parse_messages(payload, EMAIL)
                    self.assertEqual([message.code for message in messages], ['012345'])
                    self.assertEqual(messages[0].received, 1794929150)
                    self.assertEqual(parse_messages(payload, 'other@example.com'), [])

    def test_conflicting_aliases_are_not_arbitrarily_selected(self):
        self.assertEqual(parse_messages({'code': '123456', 'verify_code': '654321'}, EMAIL), [])
        self.assertEqual(parse_messages({'code': '123456', 'Code': '654321'}, EMAIL), [])

    def test_pending_http_200_continues_until_a_fresh_code_arrives(self):
        session = MagicMock()
        session.get.side_effect = [
            reply({'code': 'no_code', 'success': False, 'retryable': True,
                   'message': 'Verification code: 111111'}),
            reply({'ok': True, 'data': {'verificationCode': '654321', 'recipient': EMAIL,
                                      'receivedAt': time.time()}}),
        ]
        box = MailboxAPI(URL, EMAIL, poll_interval=0, session=session)
        self.assertEqual(box.wait_code(time.time(), timeout=1), '654321')
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(box.used, {'654321'})

    def test_api_errors_fail_immediately_without_echoing_provider_data(self):
        for failure in ({'success': False, 'retryable': False},
                        {'error': {'code': 'invalid_token'}},
                        {'code': 'unauthorized', 'retryable': True},
                        {'code': None, 'error': 'mailbox_not_found', 'retryable': True},
                        {'code': '123456', 'Code': '654321'},
                        {'result': {'ok': False, 'error': 'mailbox_expired'}}):
            context = reply({**failure, 'message': URL + ' Verification code: 123456'})
            session = MagicMock()
            session.get.return_value = context
            box = MailboxAPI(URL, EMAIL, poll_interval=0, session=session)
            with self.subTest(failure=failure), self.assertRaises(MailboxError) as error:
                box.snapshot()
            session.get.assert_called_once()
            context.__exit__.assert_called_once()
            self.assertEqual(box.baseline, set())
            for secret in (URL, 'fixture-private', '123456'):
                self.assertNotIn(secret, str(error.exception))

    def test_retryable_flag_does_not_hide_a_valid_code(self):
        session = MagicMock()
        session.get.return_value = reply({'code': '123456', 'retryable': True})
        box = MailboxAPI(URL, EMAIL, session=session)
        self.assertEqual([message.code for message in box.read()], ['123456'])

    def test_json_string_response_remains_supported(self):
        for payload in ('123456', 'Verification code: 123456'):
            session = MagicMock()
            session.get.return_value = reply(payload)
            box = MailboxAPI(URL, EMAIL, session=session)
            with self.subTest(payload=payload):
                self.assertEqual([message.code for message in box.read()], ['123456'])

    def test_used_and_stale_codes_remain_excluded_with_new_timestamp_aliases(self):
        now = time.time()
        session = MagicMock()
        session.get.side_effect = [
            reply({'verify_code': '111111', 'ts': now - 600}),
            reply({'verify_code': '222222', 'ts': now}),
            reply({'verify_code': '333333', 'ts': now}),
        ]
        box = MailboxAPI(URL, EMAIL, poll_interval=0, session=session)
        box.used.add('222222')
        self.assertEqual(box.wait_code(now, timeout=1), '333333')
        self.assertEqual(session.get.call_count, 3)

    def test_stop_during_streaming_discards_partial_code_and_closes_response(self):
        stop = threading.Event()
        context = reply({})

        def chunks():
            yield b'{"code":'
            stop.set()
            yield b'"123456"}'

        context.__enter__.return_value.iter_content.return_value = chunks()
        session = MagicMock()
        session.get.return_value = context
        box = MailboxAPI(URL, EMAIL, stop_event=stop, session=session)
        with self.assertRaisesRegex(MailboxError, '已停止'):
            box.read()
        session.get.assert_called_once()
        context.__exit__.assert_called_once()

    def test_expired_read_budget_does_not_issue_another_request(self):
        session = MagicMock()
        box = MailboxAPI(URL, EMAIL, session=session)
        with self.assertRaisesRegex(MailboxError, '超时'):
            box.read(timeout=0)
        session.get.assert_not_called()

    def test_streamed_response_is_discarded_after_read_budget_expires(self):
        session = MagicMock()
        context = reply({'code': '123456'})
        session.get.return_value = context
        box = MailboxAPI(URL, EMAIL, session=session)
        with patch('mailbox_api.time.monotonic', side_effect=[0, 0, 2]), \
             self.assertRaisesRegex(MailboxError, '超时'):
            box.read(timeout=1)
        session.get.assert_called_once()
        context.__exit__.assert_called_once()


if __name__ == '__main__':
    unittest.main()
