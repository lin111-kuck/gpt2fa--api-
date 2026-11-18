# Retained protocol helpers

Source: https://github.com/wangshen233/turb-register-public/tree/1a1d86a34695738213cdfd23bb1c4db049de8377/vendor/gpt-register-tool/%E5%8D%8F%E8%AE%AE

The selected files are `fingerprint.py`, `tls_fingerprint.py`, `http_client.py`,
`http_client_wreq.py`, `sentinel_quickjs.py`, and `openai_sentinel_quickjs.js`.
The bundled protocol directory retains the GNU AGPL version 3 license in `LICENSE`;
the containing Turb repository's MIT notice is retained in `TURB_LICENSE`.
Preserve both notices and comply with the retained licenses when redistributing
this derivative login tool. The containing repository's MIT license does not
replace the protocol subdirectory's AGPL license.

The newly added `protocol_login.py`, `mailbox_api.py`, `relogin_service.py` and `local_login_service.py`
are provided under AGPL-3.0-only; the full license is retained in `login_vendor/LICENSE`.

Local changes on 2026-11-17: package-relative imports, per-session SDK cache with
cleanup, language headers from the session profile, disabled SDK/challenge
redirects, and removed proxy credentials from the session debug message.

The new login state machine calls `WreqSession` directly with retries disabled.
It does not call `install()`, `_turb_bridge.py`, registration flows or Turb's
database, account pool and mail-provider adapters. Chrome152 is selected in wreq;
the fingerprint UA and Client Hints use the same version. The optional custom
TLS/HTTP2 variations produced by the original generator are not used here.

OpenAI's SDK is fetched at runtime from sentinel.openai.com into a temporary
directory for each login. It is not included in this source directory. The
retained SDK adaptation is version-dependent and may require future maintenance.

Additional transport change on 2026-11-17: optional explicit emulation platform.
The local login engine selects Windows together with Chrome152 on every host,
matching the generated UA/Client Hints rather than using wreq's default platform.
Native header buffers are decoded from memoryview as well as bytes/bytearray;
this is required for real Location responses on the Linux wreq build.
