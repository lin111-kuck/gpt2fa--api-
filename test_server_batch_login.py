import unittest
from server_batch_login import allocate_routes, configure_assignment
from relogin_service import Config
from batch_login import parse_entries


class CapacityTests(unittest.TestCase):
    def test_password_totp_without_mailbox_keeps_service_configuration_valid(self):
        email = 'person@example.com'
        secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        entry = parse_entries(f'{email}----fixture-password----{secret}')[0]
        config = dict(proxy_url='http://127.0.0.1:20202', mailboxes={})
        route = dict(proxy_url=config['proxy_url'], exit_ip='192.0.2.1')
        configure_assignment(config, entry, route)
        Config(**config).validate()
        self.assertNotIn(email, config['mailboxes'])
        self.assertEqual(config['account_proxies'][email]['expected_exit_ip'], route['exit_ip'])
        existing = 'https://mail.example.test/otp?email=' + email
        config['mailboxes'][email] = existing
        configure_assignment(config, entry, route)
        self.assertEqual(config['mailboxes'][email], existing)
        Config(**config).validate()

    def test_counts_existing_accounts_across_shared_exit_and_reserves_before_parallel_login(self):
        routes = [{'proxy_id': 1, 'exit_ip': '192.0.2.1', 'occupancy': 1},
                  {'proxy_id': 2, 'exit_ip': '192.0.2.1', 'occupancy': 1},
                  {'proxy_id': 3, 'exit_ip': '192.0.2.2', 'occupancy': 2}]
        planned = allocate_routes(list('abcdefg'), routes)
        self.assertEqual([r['proxy_id'] for r in planned.values()], [1, 1, 1, 1, 3, 3, 3])
        with self.assertRaises(ValueError):
            allocate_routes(list('abcdefgh'), routes)

    def test_full_ip_is_skipped_and_additional_ip_takes_remainder(self):
        routes = [{'proxy_id': 1, 'exit_ip': '192.0.2.1', 'occupancy': 5},
                  {'proxy_id': 2, 'exit_ip': '192.0.2.2', 'occupancy': 4},
                  {'proxy_id': 3, 'exit_ip': '192.0.2.3', 'occupancy': 0}]
        self.assertEqual([r['proxy_id'] for r in allocate_routes(['a', 'b'], routes).values()], [2, 3])


if __name__ == '__main__':
    unittest.main()
