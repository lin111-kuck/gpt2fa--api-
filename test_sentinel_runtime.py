"""Exercise the real Node adapter with an offline SDK fixture, including process exit."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class SentinelRuntimeTests(unittest.TestCase):
    def invoke(self, action, init='async function(){}'):
        sdk = '''function O(){}
O.prototype.getRequirementsToken=async function(){return 'fixture-proof'};
var E=new O;
function Rn(){} function D(){} async function je(){return 'fixture-token'}
var SentinelSDK=function(t){return t.init=INIT,t.sessionObserverToken=async function(){return 'fixture-observer'},t.token=je,t}({});'''.replace('INIT', init)
        script = Path(__file__).parent / 'login_vendor/openai_sentinel_quickjs.js'
        with tempfile.TemporaryDirectory() as folder:
            sdk_path = Path(folder) / 'sdk.js'
            sdk_path.write_text(sdk, encoding='utf-8')
            started = time.monotonic()
            result = subprocess.run(['node', str(script)],
                input=json.dumps({'action': action}), text=True, encoding='utf-8', capture_output=True,
                env={**os.environ, 'OPENAI_SENTINEL_SDK_FILE': str(sdk_path)}, timeout=13)
            elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout), elapsed

    def test_requirements_exits_without_waiting_for_unused_eight_second_timer(self):
        result, elapsed = self.invoke('requirements')
        self.assertEqual(result, {'request_p': 'fixture-proof'})
        self.assertLess(elapsed, 3)

    def test_solve_preserves_collection_and_token_output_without_lingering_timers(self):
        result, elapsed = self.invoke('solve')
        self.assertEqual(result, {'token': 'fixture-token', 'so_token': 'fixture-observer'})
        self.assertGreaterEqual(elapsed, 4.1)
        self.assertLess(elapsed, 7)

    def test_unresolved_init_still_times_out_and_uses_requirements_fallback(self):
        result, elapsed = self.invoke('requirements', 'function(){return new Promise(function(){})}')
        self.assertEqual(result, {'request_p': 'fixture-proof'})
        self.assertGreaterEqual(elapsed, 7.9)
        self.assertLess(elapsed, 11)


if __name__ == '__main__':
    unittest.main()
