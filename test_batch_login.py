import unittest
import base64
import json
import threading
from http.client import IncompleteRead
from io import BytesIO
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import batch_login as b
from proxy_report import ApiError

SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


def fake_credential(email='a@example.com', account_id='external-1', user_id='user-1'):
    claims={'email':email,'https://api.openai.com/auth':{'chatgpt_account_id':account_id,'chatgpt_user_id':user_id}}
    segment=base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return {'access_token':'temporary','id_token':'header.'+segment+'.test-signature','email':email,'account_id':account_id}


def proxy(pid=1, accounts=0, ip='192.0.2.1', ms=50, **kwargs):
    return dict(id=pid, account_count=accounts, ip_address=ip, latency_ms=ms, status='active', **kwargs)


def client_for(proxies, results):
    return SimpleNamespace(list_proxies=Mock(return_value=proxies), request=Mock(side_effect=results), clean=str)


def options(**updates):
    return SimpleNamespace(groups=b.DEFAULT_GROUPS, max_per_ip=4, max_latency=300,
                           dry_run=updates.get('dry_run', False), job_timeout=2,
                           poll_interval=0, models=None)


class BatchLoginTests(unittest.TestCase):
    def setUp(self):
        settings = patch.dict('os.environ', {'SUB2API_BASE_URL': 'https://sub2api.example.com',
                                             'SUB2API_EMAIL': 'admin@example.com'})
        settings.start()
        self.addCleanup(settings.stop)

    def test_input_and_secret_repr(self):
        entries=b.parse_entries(f'A@example.com----pass----{SECRET}\nb@example.com----pass2----{SECRET}')
        self.assertEqual([e.email for e in entries], ['a@example.com','b@example.com'])
        self.assertNotIn('pass',repr(entries[0]))
        self.assertNotIn(SECRET,repr(entries[0]))
        for text in [f'a@example.com----p----{SECRET}\nA@example.com----p----{SECRET}',
                     'a@example.com----p----123456', '', 'bad----p----'+SECRET]:
            with self.assertRaises(ApiError): b.parse_entries(text)

    def test_optional_mailbox_url_is_preserved_without_repr_and_password_is_preserved(self):
        text=f'a@example.com----p!$&^*----{SECRET}----https://mail.example/m?token=private'
        entry=b.parse_entries(text)[0]
        self.assertEqual(entry.password,'p!$&^*')
        self.assertEqual(entry.mfa_secret,SECRET)
        self.assertEqual(set(vars(entry)),{'email','password','mfa_secret','mail_url'})
        self.assertEqual(entry.mail_url, text.split('----')[3])
        self.assertNotIn('private',repr(entry))
        with self.assertRaises(ApiError):
            b.parse_entries(text+'----extra')

    def test_strict_threshold_and_zero_latency(self):
        c=client_for([proxy(1),proxy(2)], [{'success':True,'latency_ms':300,'ip_address':'192.0.2.1'},
                                             {'success':True,'latency_ms':0,'ip_address':'192.0.2.1'}])
        chosen=b.ProxyPicker(c,4,300,Mock()).choose()
        self.assertEqual(chosen['proxy_id'],2)
        self.assertEqual(chosen['latency_ms'],0)
        self.assertFalse(chosen['relaxed_latency'])

    def test_same_exit_ip_combines_counts(self):
        c=client_for([proxy(1,2),proxy(2,2),proxy(3,0,'192.0.2.3')],
                     [{'success':True,'latency_ms':30,'ip_address':'192.0.2.3'}])
        chosen=b.ProxyPicker(c,4,300,Mock()).choose()
        self.assertEqual(chosen['proxy_id'],3)
        self.assertEqual(c.request.call_count,1)

    def test_fallback_tests_every_eligible_candidate(self):
        c=client_for([proxy(1,0,ms=30),proxy(2,0,'192.0.2.2',ms=40)],
                     [{'success':True,'latency_ms':700,'ip_address':'192.0.2.1'},
                      {'success':True,'latency_ms':310,'ip_address':'192.0.2.2'}])
        chosen=b.ProxyPicker(c,4,300,Mock()).choose()
        self.assertEqual(chosen['proxy_id'],2)
        self.assertTrue(chosen['relaxed_latency'])
        self.assertEqual(c.request.call_count,2)

    def test_capacity_is_never_relaxed(self):
        c=client_for([proxy(1,4)],[])
        with self.assertRaises(ApiError): b.ProxyPicker(c,4,300,Mock()).choose()
        c.request.assert_not_called()

    def test_failure_and_expiry_are_excluded(self):
        expired=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        c=client_for([proxy(1,expires_at=expired),proxy(2),proxy(3,ip='192.0.2.3')],
                     [{'success':False,'latency_ms':10}, {'success':True,'latency_ms':50,'ip_address':'192.0.2.3'}])
        self.assertEqual(b.ProxyPicker(c,4,300,Mock()).choose()['proxy_id'],3)
        self.assertEqual(c.request.call_count,2)

    def test_unknown_count_excludes_shared_ip(self):
        c=client_for([proxy(1,0),proxy(2,None)],[])
        with self.assertRaises(ApiError): b.ProxyPicker(c,4,300,Mock()).choose()
        c.request.assert_not_called()

    def test_preimport_capacity_recheck(self):
        c=client_for([proxy(1,4)],[{'success':True,'latency_ms':50,'ip_address':'192.0.2.1'}])
        with self.assertRaises(ApiError):
            b.ProxyPicker(c,4,300,Mock()).recheck(dict(proxy_id=1))

    def test_login_polling_and_cleanup(self):
        e=b.Entry('a@example.com','pass',SECRET)
        j=Mock()
        c=client_for([], [{'id':'job-1'},{'status':'queued'},{'status':'running'},
                          {'status':'succeeded','credential':fake_credential()},None])
        result=b.login_credential(c,e,5,0,j)
        self.assertEqual(result,fake_credential())
        self.assertEqual(c.request.call_args_list[-1].args,('DELETE',b.LOGIN+'/job-1'))
        self.assertEqual(c.request.call_args_list[0].args[2]['credential_target'],'operations')
        self.assertNotIn(SECRET,str(j.call_args_list))
        self.assertNotIn('temporary',str(j.call_args_list))

    def test_login_failure_includes_backend_error_message(self):
        c=client_for([], [{'id':'job-1'},{'status':'failed','error_message':'Worker rejected login','error_code':'LOGIN_REJECTED'},None])
        journal=Mock()
        with self.assertRaisesRegex(ApiError,'Worker rejected login'):
            b.login_credential(c,b.Entry('a@example.com','pass',SECRET),5,0,journal)
        event=next(call for call in journal.call_args_list if call.args[0]=='login_failed')
        self.assertEqual(event.kwargs['error_code'],'LOGIN_REJECTED')

    def test_login_failure_cleans_job(self):
        c=client_for([], [{'id':'job-1'},{'status':'failed'},None])
        with self.assertRaises(ApiError): b.login_credential(c,b.Entry('a@example.com','pass',SECRET),5,0,Mock())
        self.assertEqual(c.request.call_args_list[-1].args[0],'DELETE')

    def test_uncertain_submission_stops_batch(self):
        c=client_for([], [ApiError('Network error')])
        with self.assertRaises(b.HaltBatch): b.login_credential(c,b.Entry('a@example.com','pass',SECRET),5,0,Mock())
        self.assertEqual(c.request.call_count,1)

    def test_input_payload_never_updates_existing(self):
        body=b.import_payload({'token':'temporary'},b.Entry('a@example.com','pass',SECRET),
                              {'proxy_id':9},[6,15],['model-a'])
        self.assertFalse(body['update_existing'])
        self.assertTrue(body['skip_existing'])
        self.assertEqual(body['group_ids'],[6,15])
        self.assertEqual(body['credential_extras']['model_mapping'],{'model-a':'model-a'})

    def test_existing_error_account_is_untouched(self):
        c=SimpleNamespace(clean=str)
        def request(method,path,*args,**kwargs):
            self.assertEqual(method,'GET')
            if path.startswith('/api/v1/settings/'):return {}
            if path.startswith('/api/v1/admin/groups/'):return [dict(id=i,name=n,status='active',platform='openai') for i,n in zip([6,15],b.DEFAULT_GROUPS)]
            if path.startswith('/api/v1/admin/accounts?'):return dict(total=1,items=[dict(id=337,name='old (a@example.com)',status='error')])
            self.fail('Unexpected request '+path)
        c.request=Mock(side_effect=request)
        rows=b.run_batch(c,[b.Entry('a@example.com','pass',SECRET)],options(),Mock(),Mock())
        self.assertEqual(rows[0]['status'],'skipped_existing')
        self.assertEqual(rows[0]['account_id'],337)

    def test_new_account_complete_flow(self):
        state={'created':False,'ops':False}
        calls=[]
        journal=Mock()
        e=b.Entry('a@example.com','pass',SECRET)
        c=SimpleNamespace(clean=str)
        c.list_proxies=Mock(side_effect=lambda size:[proxy(9,1 if state['created'] else 0)])
        def request(method,path,body=None,**kwargs):
            calls.append((method,path))
            if path.startswith('/api/v1/settings/'):return {}
            if path.startswith('/api/v1/admin/groups/'):return [dict(id=i,name=n,status='active',platform='openai') for i,n in zip([6,15],b.DEFAULT_GROUPS)]
            if path.startswith('/api/v1/admin/accounts?'):return dict(total=0,items=[])
            if path==b.OPS+'/encryption':return {'configured':True}
            if path=='/api/v1/admin/proxies/9/test':return dict(success=True,latency_ms=60,ip_address='192.0.2.1')
            if path==b.LOGIN:return {'id':'job-1'}
            if path==b.LOGIN+'/job-1':return {} if method=='DELETE' else dict(status='succeeded',credential=fake_credential())
            if path==b.IMPORT:
                self.assertTrue(body['skip_existing']);self.assertFalse(body['update_existing'])
                self.assertEqual(body['proxy_id'],9);self.assertEqual(body['group_ids'],[6,15])
                state['created']=True
                return dict(created=1,updated=0,skipped=0,failed=0,items=[dict(action='created',account_id=17)])
            if path=='/api/v1/admin/accounts/17':return dict(id=17,proxy_id=9,group_ids=[6,15])
            if path==b.OPS+'/accounts':
                self.assertEqual(body['totp_secret'],SECRET);self.assertEqual(body['password'],'pass')
                self.assertTrue(body['enabled']);self.assertTrue(body['auto_relogin_enabled']);state['ops']=True
                return {'account_id':17}
            self.fail('Unexpected request '+method+' '+path)
        c.request=Mock(side_effect=request)
        rows=b.run_batch(c,[e],options(),journal,Mock())
        self.assertEqual(rows[0]['status'],'created')
        self.assertEqual(rows[0]['account_id'],17)
        self.assertTrue(state['ops'])
        self.assertEqual(rows[0]['occupancy_after'],1)
        self.assertNotIn(SECRET,str(journal.call_args_list))
        self.assertNotIn('temporary',str(journal.call_args_list))

    def test_dry_run_reserves_capacity_without_login(self):
        c=SimpleNamespace(clean=str)
        c.list_proxies=Mock(return_value=[proxy(9,3)])
        def request(method,path,*args,**kwargs):
            if path.startswith('/api/v1/settings/'):return {}
            if path.startswith('/api/v1/admin/groups/'):return [dict(id=i,name=n,status='active',platform='openai') for i,n in zip([6,15],b.DEFAULT_GROUPS)]
            if path.startswith('/api/v1/admin/accounts?'):return dict(total=0,items=[])
            if path==b.OPS+'/encryption':return {'configured':True}
            if path=='/api/v1/admin/proxies/9/test':return dict(success=True,latency_ms=60,ip_address='192.0.2.1')
            self.fail('Dry run submitted an unexpected request '+method+' '+path)
        c.request=Mock(side_effect=request)
        entries=[b.Entry('a@example.com','pass',SECRET),b.Entry('b@example.com','pass',SECRET)]
        rows=b.run_batch(c,entries,options(dry_run=True),Mock(),Mock())
        self.assertEqual([r['status'] for r in rows],['planned','failed'])
        tests=[call for call in c.request.call_args_list if call.args[0]=='POST']
        self.assertEqual(len(tests),1)
        self.assertTrue(tests[0].args[1].endswith('/test'))

    def test_unknown_import_outcome_is_not_retried(self):
        c=client_for([], [ApiError('timeout')])
        with self.assertRaises(b.HaltBatch):
            b.import_new(c,b.Entry('a@example.com','pass',SECRET),{'token':'temp'},
                         dict(proxy_id=1),[6,15],None,Mock())
        self.assertEqual(c.request.call_count,1)

    def test_batch_assigns_distinct_ips_and_stops_when_exhausted(self):
        c=SimpleNamespace(clean=str)
        proxies=[proxy(1,0),proxy(2,0),proxy(3,0,'192.0.2.3')]
        c.list_proxies=Mock(return_value=proxies)
        def request(method,path,*args,**kwargs):
            if path.startswith('/api/v1/admin/proxies/'):
                pid=int(path.split('/')[-2])
                return dict(success=True,latency_ms=50,ip_address=proxies[pid-1]['ip_address'])
            return {'configured':True}
        c.request=Mock(side_effect=request)
        entries=[b.Entry(f'user{i}@example.com','pass',SECRET) for i in range(4)]
        with patch.object(b,'resolve_groups',return_value=[6,15]), patch.object(b,'existing_account',return_value=None):
            rows=b.run_batch(c,entries,options(dry_run=True),Mock(),Mock())
        self.assertEqual([r['status'] for r in rows],['planned','planned','failed'])
        self.assertEqual([r['proxy_id'] for r in rows[:2]],[1,3])
        self.assertEqual(len({r['exit_ip'] for r in rows[:2]}),2)
        self.assertEqual(len([call for call in c.request.call_args_list if call.args[0]=='POST']),2)

    def test_latency_fallback_never_reuses_reserved_ip(self):
        proxies=[proxy(1,0),proxy(2,0,'192.0.2.2')]
        c=client_for(proxies,[dict(success=True,latency_ms=500,ip_address='192.0.2.1'),
                              dict(success=True,latency_ms=550,ip_address='192.0.2.2'),
                              dict(success=True,latency_ms=550,ip_address='192.0.2.2')])
        picker=b.ProxyPicker(c,4,300,Mock())
        first=picker.choose('first@example.com')
        second=picker.choose('second@example.com')
        self.assertEqual([first['proxy_id'],second['proxy_id']],[1,2])
        self.assertTrue(first['relaxed_latency'] and second['relaxed_latency'])
        with self.assertRaises(b.NoProxyAvailable): picker.choose('third@example.com')
        self.assertEqual(c.request.call_count,3)

    def test_test_result_cannot_reuse_another_accounts_exit(self):
        proxies=[proxy(1,0),proxy(2,0,'192.0.2.2'),proxy(3,0,'192.0.2.3')]
        c=client_for(proxies,[dict(success=True,latency_ms=50,ip_address='192.0.2.1'),
                              dict(success=True,latency_ms=50,ip_address='192.0.2.1'),
                              dict(success=True,latency_ms=50,ip_address='192.0.2.3')])
        picker=b.ProxyPicker(c,4,300,Mock())
        picker.choose('first@example.com')
        second=picker.choose('second@example.com')
        self.assertEqual(second['proxy_id'],3)
        self.assertEqual(second['exit_ip'],'192.0.2.3')

    def test_recheck_reselects_on_exit_collision_and_allows_own_reservation(self):
        proxies=[proxy(1,0),proxy(2,0,'192.0.2.2'),proxy(3,0,'192.0.2.3')]
        c=client_for(proxies,[dict(success=True,latency_ms=50,ip_address=ip) for ip in
                             ['192.0.2.1','192.0.2.2','192.0.2.2','192.0.2.2','192.0.2.3']])
        picker=b.ProxyPicker(c,4,300,Mock())
        first=picker.choose('first@example.com')
        picker.choose('second@example.com')
        changed=picker.recheck(first,'first@example.com')
        self.assertEqual(changed['proxy_id'],3)
        self.assertEqual(changed['exit_ip'],'192.0.2.3')
        self.assertFalse(picker.available(1,'192.0.2.1','third@example.com'))
        self.assertTrue(picker.available(3,'192.0.2.3','first@example.com'))

    def test_login_failure_keeps_ip_reserved_for_rest_of_batch(self):
        c=SimpleNamespace(clean=str)
        c.list_proxies=Mock(return_value=[proxy(1,0),proxy(2,0,'192.0.2.2')])
        def request(method,path,*args,**kwargs):
            if path.startswith('/api/v1/admin/proxies/'):
                pid=int(path.split('/')[-2])
                return dict(success=True,latency_ms=50,ip_address=f'192.0.2.{pid}')
            return {'configured':True}
        c.request=Mock(side_effect=request)
        entries=[b.Entry(f'user{i}@example.com','pass',SECRET) for i in range(2)]
        outcome=dict(status='created',account_id=17,occupancy_after=1)
        with patch.object(b,'resolve_groups',return_value=[6,15]), patch.object(b,'existing_account',return_value=None), \
             patch.object(b,'login_credential',side_effect=[ApiError('Login failed'),{'token':'temp'}]), \
             patch.object(b,'import_new',return_value=outcome) as importer:
            rows=b.run_batch(c,entries,options(),Mock(),Mock())
        self.assertEqual([r['status'] for r in rows],['failed','created'])
        self.assertEqual([r['proxy_id'] for r in rows],[1,2])
        self.assertEqual(importer.call_args.args[3]['proxy_id'],2)

    def test_ipv6_spelling_does_not_bypass_unique_ip(self):
        proxies=[proxy(1,0,'2001:db8::1'),proxy(2,0,'2001:0db8:0:0:0:0:0:1')]
        c=client_for(proxies,[dict(success=True,latency_ms=50,ip_address='2001:db8::1')])
        picker=b.ProxyPicker(c,4,300,Mock())
        picker.choose('first@example.com')
        with self.assertRaises(b.NoProxyAvailable): picker.choose('second@example.com')
        self.assertEqual(c.request.call_count,1)

    def test_login_only_does_not_import_or_rebind_existing_accounts(self):
        c=SimpleNamespace(clean=str,request=Mock(return_value={}))
        args=options()
        args.login_only=True
        entries=[b.Entry('a@example.com','pass',SECRET),b.Entry('b@example.com','pass',SECRET)]
        with patch.object(b,'resolve_groups',return_value=[6,15]), \
             patch.object(b,'existing_account',side_effect=AssertionError('Login-only must not fetch or skip existing accounts')), \
             patch.object(b,'login_credential',return_value={'access_token':'temporary'}) as login, \
             patch.object(b,'import_new',side_effect=AssertionError('Login-only imported an account')):
            rows=b.run_batch(c,entries,args,Mock(),Mock())
        self.assertEqual([r['status'] for r in rows],['login_verified','login_verified'])
        self.assertEqual(login.call_count,2)
        self.assertTrue(all('proxy_id' not in r for r in rows))
        self.assertNotIn('temporary',str(rows))
        self.assertTrue(all(call.args[0]=='GET' for call in c.request.call_args_list))

    def test_login_identity_rejects_token_for_another_email(self):
        c=client_for([], [{'id':'job-1'},{'status':'succeeded','credential':fake_credential('other@example.com')},None])
        with self.assertRaisesRegex(b.HaltBatch,'differs from requested email'):
            b.login_credential(c,b.Entry('a@example.com','pass',SECRET),5,0,Mock())
        self.assertEqual(c.request.call_args_list[-1].args[0],'DELETE')

    def test_skip_without_existing_id_is_not_reported_as_existing(self):
        c=client_for([], [dict(created=0,updated=0,skipped=1,failed=0,items=[dict(action='skipped',message='unsupported input')])])
        with self.assertRaisesRegex(b.HaltBatch,'does not prove the account exists'):
            b.import_new(c,b.Entry('a@example.com','pass',SECRET),fake_credential(),{'proxy_id':1},[6,15],None,Mock())
        self.assertEqual(c.request.call_count,1)

    def test_skip_by_upstream_identity_reports_old_display_name_and_id(self):
        existing=dict(id=281,name='old@example.com (old@example.com)',platform='openai',
                      credentials=dict(email='old@example.com',chatgpt_account_id='external-1',chatgpt_user_id='user-1'))
        c=client_for([], [dict(created=0,updated=0,skipped=1,failed=0,items=[dict(action='skipped',account_id=281)]),existing])
        result=b.import_new(c,b.Entry('a@example.com','pass',SECRET),fake_credential(),{'proxy_id':1},[6,15],None,Mock())
        self.assertEqual(result['status'],'skipped_existing_identity')
        self.assertEqual(result['account_id'],281)
        self.assertEqual(result['existing_name'],existing['name'])
        self.assertEqual(result['existing_emails'],['old@example.com'])
        self.assertEqual(result['matched_by'],'upstream_account_and_user_id')
        self.assertEqual(c.request.call_count,2)
        self.assertEqual(c.request.call_args_list[1].args,('GET','/api/v1/admin/accounts/281'))

    def test_skip_with_different_upstream_user_is_not_accepted(self):
        existing=dict(id=281,platform='openai',credentials=dict(chatgpt_account_id='external-1',chatgpt_user_id='wrong-user'))
        c=client_for([], [dict(created=0,updated=0,skipped=1,failed=0,items=[dict(action='skipped',account_id=281)]),existing])
        with self.assertRaisesRegex(b.HaltBatch,'different upstream user ID'):
            b.import_new(c,b.Entry('a@example.com','pass',SECRET),fake_credential(),{'proxy_id':1},[6,15],None,Mock())

    def test_safe_client_redacts_password_and_secret(self):
        c=b.SafeClient('https://example.com','admin','admin-pass','token-value',60,secrets=['account-pass',SECRET])
        output=c.clean('admin-pass token-value account-pass '+SECRET)
        self.assertEqual(output,'[REDACTED] [REDACTED] [REDACTED] [REDACTED]')

    def test_parallel_logins_overlap_and_reserve_distinct_exit_ips(self):
        c=b.SafeClient('https://example.com','admin',None,'token',2,direct=True)
        proxies=[proxy(1),proxy(2),proxy(3,ip='192.0.2.3'),proxy(4,ip='192.0.2.4')]
        c.list_proxies=Mock(return_value=proxies)
        def request(method,path,*args,**kwargs):
            if path.startswith('/api/v1/admin/proxies/'):
                pid=int(path.split('/')[-2])
                return dict(success=True,latency_ms=50,ip_address=proxies[pid-1]['ip_address'])
            return {'configured':True}
        c.request=Mock(side_effect=request)
        barrier=threading.Barrier(3,timeout=3)
        def login(*args):
            barrier.wait()
            return {'token':'temporary'}
        args=options();args.workers=3;args.resume_journal=[]
        entries=[b.Entry(f'user{i}@example.com','pass',SECRET) for i in range(3)]
        def imported(client,entry,credential,chosen,*rest):
            return dict(status='created',account_id=chosen['proxy_id'],occupancy_after=1)
        with patch.object(b,'SafeClient',return_value=c), patch.object(b,'resolve_groups',return_value=[6,15]), \
             patch.object(b,'existing_account',return_value=None), patch.object(b,'login_credential',side_effect=login), \
             patch.object(b,'import_new',side_effect=imported):
            rows=b.run_batch_parallel(c,entries,args,Mock(),Mock())
        self.assertEqual(len(rows),3)
        self.assertTrue(all(row['status']=='created' for row in rows))
        self.assertEqual(len({row['exit_ip'] for row in rows}),3)
        self.assertEqual([row['email'] for row in rows],[entry.email for entry in entries])

    def test_parallel_scheduler_stops_after_unknown_import_outcome(self):
        c=b.SafeClient('https://example.com','admin',None,'token',2,direct=True)
        c.request=Mock(return_value={'configured':True})
        args=options();args.workers=1;args.resume_journal=[]
        entries=[b.Entry(f'user{i}@example.com','pass',SECRET) for i in range(4)]
        chosen=dict(proxy_id=1,exit_ip='192.0.2.1')
        with patch.object(b,'SafeClient',return_value=c), patch.object(b,'resolve_groups',return_value=[6,15]), \
             patch.object(b,'existing_account',return_value=None), \
             patch.object(b.ProxyPicker,'choose',return_value=chosen), \
             patch.object(b.ProxyPicker,'recheck',return_value=chosen), \
             patch.object(b,'login_credential',return_value={'token':'temporary'}) as login, \
             patch.object(b,'import_new',side_effect=b.HaltBatch('Unknown import outcome')) as importer:
            rows=b.run_batch_parallel(c,entries,args,Mock(),Mock())
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'needs_review')
        self.assertEqual(login.call_count,1)
        self.assertEqual(importer.call_count,1)

    def test_restored_reservations_exclude_previous_exit_ips(self):
        c=client_for([proxy(1),proxy(2,ip='192.0.2.2')],
                     [dict(success=True,latency_ms=50,ip_address='192.0.2.2')])
        picker=b.ProxyPicker(c,4,300,Mock())
        old=json.dumps(dict(event='proxy_reserved',email='old@example.com',proxy_id=1,exit_ip='192.0.2.1'))
        with patch.object(b.Path,'read_text',return_value=old):
            b.restore_reservations(picker,['previous.jsonl'])
        self.assertEqual(picker.choose('new@example.com')['proxy_id'],2)
        self.assertEqual(c.request.call_count,1)

    def test_interrupted_response_retries_get_but_never_post(self):
        for method,calls in [('GET',2),('POST',1)]:
            c=b.SafeClient('https://example.com','admin',None,'token',2,direct=True)
            c.opener=Mock()
            response=BytesIO(b'{"data":{"ok":true}}')
            c.opener.open.side_effect=[IncompleteRead(b'partial'),response]
            with patch('proxy_report.time.sleep'):
                if method=='GET':
                    self.assertEqual(c.request(method,'/example'),{'ok':True})
                else:
                    with self.assertRaises(ApiError): c.request(method,'/example',{})
            self.assertEqual(c.opener.open.call_count,calls)

    def test_group_ids_select_only_requested_active_openai_groups(self):
        groups=[dict(id=gid,name=name,status='active',platform='openai')
                for gid,name in [(6,'renamed first'),(15,'renamed second'),(23,'other')]]
        c=client_for([], [groups])
        self.assertEqual(b.resolve_groups(c,b.DEFAULT_GROUPS,group_ids=[23,23]),[23])

    def test_group_ids_reject_missing_inactive_and_other_platform(self):
        groups=[dict(id=6,name='active',status='active',platform='openai'),
                dict(id=15,name='inactive',status='inactive',platform='openai'),
                dict(id=23,name='other platform',status='active',platform='anthropic')]
        for gid in [0,15,23,99]:
            with self.subTest(gid=gid),self.assertRaises(ApiError):
                b.resolve_groups(client_for([], [groups]),[],group_ids=[gid])

    def test_cli_accepts_group_ids_proxy_name_and_worker_count(self):
        args=b.parse_args(['--group-ids','15,6','23','--proxy-name','Dasho 美国','--workers','3'])
        self.assertEqual(args.group_ids,[6,15,23])
        self.assertEqual(args.proxy_name,'Dasho 美国')
        self.assertEqual(args.workers,3)
        self.assertIsNone(b.parse_args([]).group_ids)

    def test_cli_rejects_invalid_options_before_any_login(self):
        for argv in [['--group-ids','0'],['--group-ids','6,bad'],['--workers','0'],
                     ['--workers','9'],['--proxy-name','---'],
                     ['--groups','name','--group-ids','6']]:
            with self.subTest(argv=argv),redirect_stderr(StringIO()),self.assertRaises(SystemExit) as error:
                b.parse_args(argv)
            self.assertEqual(error.exception.code,2)

    def test_interactive_options_support_comma_ids_filter_and_workers(self):
        args=b.parse_args([])
        with redirect_stdout(StringIO()):
            b.interactive_options(args,Mock(side_effect=['6，15,23','Dasho 美国','3']))
        self.assertEqual(args.group_ids,[6,15,23])
        self.assertEqual(args.proxy_name,'Dasho 美国')
        self.assertEqual(args.workers,3)

    def test_interactive_blanks_keep_options_and_invalid_values_are_reprompted(self):
        args=b.parse_args(['--group-ids','23','--proxy-name','Dasho','--workers','3'])
        b.interactive_options(args,Mock(side_effect=['','','']))
        self.assertEqual((args.group_ids,args.proxy_name,args.workers),([23],'Dasho',3))
        with redirect_stdout(StringIO()):
            b.interactive_options(args,Mock(side_effect=['0','15','---','香港','9','2']))
        self.assertEqual((args.group_ids,args.proxy_name,args.workers),([15],'香港',2))

    def test_proxy_name_matching_handles_case_punctuation_and_chinese(self):
        self.assertTrue(b.proxy_name_matches('Dasho 1030 · 美国04-0.1倍','DASHO 美国04'))
        self.assertTrue(b.proxy_name_matches('Dasho 1113 1','dasho-1113'))
        self.assertTrue(b.proxy_name_matches('香港-A（通用）','香港a'))
        self.assertFalse(b.proxy_name_matches('Dasho 日本03','Dasho 美国'))
        self.assertFalse(b.proxy_name_matches(None,'Dasho'))

    def test_filtered_picker_ignores_faster_unmatched_proxies(self):
        proxies=[proxy(1,ms=1,name='Other US'),proxy(2,ip='192.0.2.2',name='Dasho 美国04')]
        c=client_for(proxies,[dict(success=True,latency_ms=60,ip_address='192.0.2.2')])
        chosen=b.ProxyPicker(c,4,300,Mock(),name_filter='dasho 美国').choose('a@example.com')
        self.assertEqual(chosen['proxy_id'],2)
        self.assertEqual(chosen['proxy_name'],'Dasho 美国04')
        self.assertEqual(c.request.call_count,1)

    def test_filtered_picker_never_falls_back_to_unmatched_name(self):
        c=client_for([proxy(1,name='Other'),proxy(2,ip='192.0.2.2',name='Dasho')],
                     [dict(success=False)])
        with self.assertRaises(b.NoProxyAvailable):
            b.ProxyPicker(c,4,300,Mock(),name_filter='Dasho').choose()
        self.assertEqual(c.request.call_count,1)

    def test_filtered_picker_counts_same_ip_on_unmatched_nodes(self):
        c=client_for([proxy(1,3,name='Dasho'),proxy(2,1,name='Other')],[])
        with self.assertRaises(b.NoProxyAvailable):
            b.ProxyPicker(c,4,300,Mock(),name_filter='Dasho').choose()
        self.assertEqual(c.request.call_count,0)

    def test_recheck_reselects_if_proxy_name_no_longer_matches(self):
        c=client_for([proxy(1,name='renamed'),proxy(2,ip='192.0.2.2',name='Dasho')],
                     [dict(success=True,latency_ms=60,ip_address='192.0.2.2')])
        picker=b.ProxyPicker(c,4,300,Mock(),name_filter='Dasho')
        chosen=picker.recheck(dict(proxy_id=1),'a@example.com')
        self.assertEqual(chosen['proxy_id'],2)

    def test_both_runners_use_custom_groups_and_proxy_name(self):
        for parallel in (False,True):
            with self.subTest(parallel=parallel):
                c=b.SafeClient('https://example.com','admin',None,'token',2,direct=True)
                c.request=Mock(return_value={'configured':True})
                args=options();args.group_ids=[23];args.proxy_name='Dasho';args.workers=2
                entry=b.Entry('a@example.com','pass',SECRET)
                with patch.object(b,'SafeClient',return_value=c), \
                     patch.object(b,'resolve_groups',return_value=[23]) as groups, \
                     patch.object(b,'existing_account',return_value={'id':17}), \
                     patch.object(b,'ProxyPicker',wraps=b.ProxyPicker) as picker:
                    runner=b.run_batch_parallel if parallel else b.run_batch
                    rows=runner(c,[entry],args,Mock(),Mock())
                self.assertEqual(rows[0]['group_ids'],[23])
                groups.assert_called_once_with(c,b.DEFAULT_GROUPS,group_ids=[23])
                self.assertEqual(picker.call_args.kwargs['name_filter'],'Dasho')


if __name__=='__main__':
    unittest.main()
