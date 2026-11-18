import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import batch_login as b
import batch_gui_service as service

SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
ACCOUNTS = 'person@example.com----account-private----' + SECRET
GROUPS = [dict(id=i, name=name, status='active', platform='openai')
          for i, name in zip([6, 15], b.DEFAULT_GROUPS)]


def client():
    return b.SafeClient('https://example.com', 'admin@example.com', None,
                        'admin-private-token', 2, direct=True)


class ServiceTests(unittest.TestCase):
    def test_authentication_loads_admin_groups_and_discards_password(self):
        fake = Mock()
        fake.request.return_value = GROUPS + [dict(id=99, status='inactive', platform='openai')]
        with patch.object(service.batch, 'SafeClient', return_value=fake):
            authenticated, groups = service.authenticate('https://example.com/', ' admin@example.com ', 'private')
        fake.login.assert_called_once()
        fake.request.assert_called_once_with('GET', '/api/v1/admin/groups/all?platform=openai')
        self.assertIs(authenticated, fake)
        self.assertIsNone(authenticated.password)
        self.assertEqual(groups, GROUPS)

    def test_authentication_rejects_unsafe_origin_before_network(self):
        for url in ['http://example.com', 'https://user:pass@example.com', 'https://example.com/path']:
            with self.subTest(url=url), patch.object(service.batch, 'SafeClient') as factory:
                with self.assertRaises(b.ApiError): service.authenticate(url, 'admin', 'private')
                factory.assert_not_called()

    def test_settings_require_explicit_valid_group_ids_and_limits(self):
        for settings in [service.Settings(''), service.Settings('6', workers=9),
                         service.Settings('6', proxy_name='---'), service.Settings('6', max_latency=float('nan'))]:
            with self.subTest(settings=settings), self.assertRaises(b.ApiError):
                service.options(settings)
        args = service.options(service.Settings('15,6', 'Dasho', 3))
        self.assertEqual(args.group_ids, [6, 15])
        self.assertEqual(args.proxy_name, 'Dasho')

    def test_reports_and_events_include_actual_results_without_credentials(self):
        def runner(c, entries, args, journal, save, **kwargs):
            self.assertEqual(args.group_ids, [6, 15])
            self.assertEqual(args.workers, 3)
            row = dict(time=b.now(), email=entries[0].email, status='created', account_id=42,
                       proxy_id=7, proxy_name='Dasho', exit_ip='192.0.2.7',
                       group_ids=args.group_ids, login_verified=True, message='Imported')
            save(row)
            return [row]
        emitted = []
        with tempfile.TemporaryDirectory() as directory, patch.object(b, 'run_batch_parallel', side_effect=runner):
            result = service.execute_batch(client(), ACCOUNTS, service.Settings('6,15'),
                                           lambda event, data: emitted.append((event, data)), workspace=directory)
            self.assertEqual(result['summary']['created'], 1)
            self.assertEqual(result['summary']['failed'], 0)
            reports = ''.join(Path(path).read_text(encoding='utf-8-sig') for path in result['paths'].values())
            self.assertIn('192.0.2.7', reports)
            for secret in ['account-private', SECRET, 'admin-private-token']:
                self.assertNotIn(secret, reports)
            self.assertEqual(json.loads(Path(result['paths']['json']).read_text(encoding='utf-8'))['items'][0]['account_id'], 42)
        self.assertEqual([event for event, data in emitted].count('row'), 1)

    def test_unexpected_failure_preserves_partial_results_and_redacts_error(self):
        def runner(c, entries, args, journal, save, **kwargs):
            save(dict(email=entries[0].email, status='failed', message='failed'))
            raise RuntimeError('account-private ' + SECRET + ' admin-private-token')
        with tempfile.TemporaryDirectory() as directory, patch.object(b, 'run_batch_parallel', side_effect=runner):
            result = service.execute_batch(client(), ACCOUNTS, service.Settings('6'), lambda *args: None, workspace=directory)
            self.assertEqual(result['summary']['processed_count'], 1)
            self.assertEqual(result['error'], '[REDACTED] [REDACTED] [REDACTED]')
            self.assertTrue(Path(result['paths']['json']).exists())

    def test_preview_stays_serial_and_shares_external_stop_event(self):
        stop = threading.Event()
        stop.set()
        with tempfile.TemporaryDirectory() as directory, patch.object(b, 'run_batch', return_value=[]) as serial, \
                patch.object(b, 'run_batch_parallel') as parallel:
            result = service.execute_batch(client(), ACCOUNTS, service.Settings('6', mode='preview'),
                                           lambda *args: None, stop, workspace=directory)
            self.assertIs(serial.call_args.kwargs['stop_event'], stop)
            parallel.assert_not_called()
            self.assertEqual(result['summary']['workers'], 1)
            self.assertEqual(result['summary']['unprocessed'], 1)

    def test_stop_after_login_never_imports_or_saves_credentials(self):
        c = client()
        c.request = Mock(return_value={'configured': True})
        args = service.options(service.Settings('6', workers=1, login_engine='backend'))
        stop = threading.Event()
        def login(*args):
            stop.set()
            return {'access_token': 'temporary'}
        with patch.object(b, 'selected_groups', return_value=[6]), \
             patch.object(b, 'existing_account', return_value=None), \
             patch.object(b.ProxyPicker, 'choose', return_value=dict(proxy_id=1, exit_ip='192.0.2.1')), \
             patch.object(b, 'login_credential', side_effect=login), \
             patch.object(b, 'import_new') as importer:
            rows = b.run_batch(c, b.parse_entries(ACCOUNTS), args, Mock(), Mock(), stop_event=stop)
        importer.assert_not_called()
        self.assertEqual(rows[0]['status'], 'stopped')
        self.assertTrue(rows[0]['login_verified'])

    def test_proxy_preview_checks_capacity_across_unmatched_aliases(self):
        c = client()
        c.list_proxies = Mock(return_value=[
            dict(id=1, name='Dasho A', status='active', account_count=3, ip_address='192.0.2.1'),
            dict(id=2, name='Other', status='active', account_count=1, ip_address='192.0.2.1'),
            dict(id=3, name='Dasho B', status='active', account_count=0, ip_address='192.0.2.3'),
        ])
        found = service.proxy_candidates(c, 'Dasho')
        self.assertEqual([row['id'] for row in found], [3])


class DesktopTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        import batch_login_gui
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        self.app = batch_login_gui.ImportApp(self.root)

    def tearDown(self):
        if hasattr(self, 'app') and not self.app.closed:
            self.app.closed = True
            self.root.destroy()

    def settle(self):
        deadline = time.monotonic() + 3
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.01)
        self.assertFalse(self.app.busy, 'UI did not consume its background result')

    def test_login_button_connects_loads_groups_and_clears_password(self):
        self.app.password.set('private')
        with patch.object(service, 'authenticate', return_value=(client(), GROUPS)) as login:
            self.app.login_button.invoke()
            self.settle()
        login.assert_called_once()
        self.assertEqual(self.app.group_ids.get(), '6,15')
        self.assertEqual(self.app.password.get(), '')
        self.assertEqual(str(self.app.start_button['state']), 'normal')
        self.app.logout()
        self.assertIsNone(self.app.client)
        self.assertEqual(str(self.app.start_button['state']), 'disabled')

    def test_failed_login_stays_logged_out_and_can_retry(self):
        self.app.password.set('wrong')
        with patch.object(service, 'authenticate', side_effect=b.ApiError('Authentication expired or invalid')):
            self.app.login_button.invoke()
            self.settle()
        self.assertIsNone(self.app.client)
        self.assertEqual(self.app.password.get(), '')
        self.assertEqual(str(self.app.login_button['state']), 'normal')
        self.assertEqual(str(self.app.start_button['state']), 'disabled')

    def test_start_button_passes_form_and_renders_background_progress(self):
        self.app._handle('authenticated', (client(), GROUPS))
        self.app.proxy_name.set('Dasho')
        self.app.workers.set('2')
        self.app.accounts.insert('1.0', ACCOUNTS)
        def execute(c, text, settings, emit, stop):
            self.assertEqual(settings.proxy_name, 'Dasho')
            self.assertEqual(settings.workers, 2)
            self.assertEqual(settings.group_ids, '6,15')
            emit('started', dict(emails=['person@example.com'], paths={}))
            row = dict(email='person@example.com', status='created', account_id=42, proxy_id=7,
                       exit_ip='192.0.2.7', proxy_name='Dasho', login_verified=True, message='Imported')
            emit('row', row)
            return dict(summary=dict(processed_count=1, input_count=1, created=1, login_verified=1,
                                    skipped=0, failed=0, planned=0, stopped=0, unprocessed=0),
                        items=[row], paths={'json': 'result.json'}, error='')
        with patch.object(service, 'execute_batch', side_effect=execute):
            self.app.start_button.invoke()
            self.settle()
        values = self.app.table.item(self.app.row_ids['person@example.com'], 'values')
        self.assertEqual(values[1], '已添加')
        self.assertEqual(values[2], '42')
        self.assertEqual(float(self.app.progress['value']), 100)
        self.assertEqual(str(self.app.report_button['state']), 'normal')

    def test_mode_label_and_stop_controls(self):
        self.app._handle('authenticated', (client(), GROUPS))
        self.app.mode.set('仅验证登录')
        self.app._refresh_controls()
        self.assertEqual(self.app.start_button['text'], '开始验证')
        self.app.busy = True
        self.app.total = 2
        self.app._refresh_controls()
        self.app.stop_button.invoke()
        self.assertTrue(self.app.stop_event.is_set())
        self.assertEqual(str(self.app.start_button['state']), 'disabled')


if __name__ == '__main__':
    unittest.main()
