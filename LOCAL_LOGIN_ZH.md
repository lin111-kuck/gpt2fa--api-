# 本地协议登录与邮箱 API 取码

首次源码快照为 2026-11-17；邮箱接口与配置更新见 [2026-11-23 上游评估](UPSTREAM_REVIEW_20261123.md)。

## 使用

1. 双击 `start_gui.cmd`，登录 Sub2API 管理后台，选择分组和代理。
2. 登录方式保持“本地协议（自动取码）”。先用“仅验证登录”检查单个账号，再使用“导入账号”。
3. 粘贴账号行。遇到邮箱验证码时，程序自动轮询对应 API，取得新码后继续 OAuth。

支持三种格式，每行一个账号：

```text
# 密码、TOTP，邮箱二验时自动取码
person@example.com----PASSWORD----BASE32_TOTP_SECRET----https://mail.example/otp?email=person@example.com&token=TOKEN

# 密码和邮箱验证码，没有 TOTP 密钥时保留空的第三段
person@example.com----PASSWORD--------https://mail.example/otp?email=person@example.com&token=TOKEN

# 邮箱验证码登录；账号如果仍要求 TOTP，会提示缺少密钥
person@example.com----https://mail.example/otp?email=person@example.com&token=TOKEN
```

原来的三字段 `邮箱----密码----TOTP密钥` 仍然支持；如果上游追加邮箱二验，会提示补充邮箱 API。这里的密钥是 Base32 长期密钥，不是六位动态码。URL 中的 `e=email:mail_password` 也支持，会校验邮箱与账号是否一致。

本地协议需要 Python 3.11+、Node.js、wreq 0.13.0、requests 2.32.5 和 tzdata。Windows 上运行 `install_local_login.cmd`，并安装 Node.js；运行环境以安装脚本的实际检查结果为准。GUI 优先使用本目录 `.venv`。旧浏览器脚本需要单独安装 requirements 中的 Playwright；它仍是原来的浏览器实现。

后台地址与管理员邮箱须由使用者填写。GUI 和两个命令行入口使用相同的 `SUB2API_BASE_URL`、`SUB2API_EMAIL` 环境变量；命令行可用 `--base-url`、`--email` 覆盖。未配置后台地址时，命令行在读取账号或密码前退出并提示配置。

命令行示例：

```powershell
Set-Location 'C:\path\to\gpt2fa-api'
$env:SUB2API_BASE_URL = 'https://sub2api.example.com'
$env:SUB2API_EMAIL = 'admin@example.com'
.\.venv\Scripts\python.exe -B batch_login.py --file .\my-accounts.txt --group-ids 6 15 --login-engine local --login-only
```

去掉 `--login-only` 才会导入。管理员密码由隐藏提示读取；也可使用原有的环境变量配置。`--mail-timeout 180` 设置取码超时；`--gateway 127.0.0.1:PORT` 可指定连接远端代理时使用的本地 CONNECT 网关。默认并发为 1；GUI 默认仍为 3。

## 邮箱 API 返回格式

邮箱 API 是用户输入的 HTTPS GET 地址，可带自己的 token 查询参数。新模块使用独立 requests 会话，直连邮件服务，不共享 OpenAI Cookie、Bearer token 或浏览器请求头，不跟随 API 重定向。

支持纯六位文本，以及以下常见 JSON 形式：

```json
{"code":"123456"}
{"data":{"otp":"123456","email":"person@example.com","received_at":"2026-11-17T00:01:02+08:00"}}
{"messages":[{"id":"message-1","from":"otp@tm.openai.com","to":"person@example.com","subject":"Your OpenAI verification code","text":"Verification code: 123456","received_at":1794840000}]}
```

还支持 WDMail 的“发件人 / 邮箱 / 时间 / 正文”HTML，包括 iframe srcdoc，忽略 script/style 中的数字。结构不同的 API 需要补充解析适配，当前不会猜测任意 JSON 数字为验证码。

补充支持 `verificationCode` / `verify_code` 验证码字段，以及 `receivedAt` / `ts` / `time` 时间戳字段；秒和毫秒时间戳均可。字段名不区分大小写；冲突的验证码或字段不会被任意选用。

HTTP 200 的 JSON 也会区分状态：`{"success":false,"code":"no_code","retryable":true}` 表示继续等待；`code` 为 `null`、空字符串或 `not_found` 等占位值时同样等待，响应正文和嵌套数据里的旧码均不会被提交。`invalid_token`、`unauthorized`、`mailbox_expired` 等明确错误，或不可重试失败，立即返回通用的邮箱配置错误；错误不回显服务端正文、取码 URL 或 token。读取响应期间收到停止信号或检测到预算过期时，会丢弃本次响应。

登录前读取一次邮箱快照；仅接收快照之外的新邮件，并校验可用的收件人和时间。没有时间戳的纯验证码接口要求返回码相对于快照发生变化。带时区时间按其偏移解析；未标时区的日期不猜测时区，依靠快照和新码变化排除旧码。支持解码 WDMail 页面中 Cloudflare 的 `data-cfemail` 邮箱保护格式，解码后仍严格核对收件人，不执行页面脚本。多个同时间候选码会继续等待，避免错投。单次邮箱等待 60 秒后最多请求一次重发；仅在明确收到验证码错误时允许再取一个新码，429、403、网络不确定错误不重放认证 POST。邮箱 API 连接失败会直接报告，初始快照失败时不会继续提交账号密码。

## 让 Sub2API 网页调用自建 relogin 服务

已新增 `relogin_service.py`，实现兼容 ranxi 的 `POST /api/v1/relogin` 服务端接口。公开源码提供的是 Sub2API 的调用协议，不是 session.ameng2027.xyz 的内部实现；这里的服务使用本项目协议引擎完成认证，不转发至该域名。

配置步骤：

1. 将 `relogin.example.json` 复制为自己的 `relogin.local.json`，填真实登录代理 URL 和邮箱 API 映射。`country_code` 和 `expected_exit_ip` 默认留空，国家、时区自动检测；填值后仅用于核对预期国家/IP，不会覆盖检测结果。邮箱二验时，按账号邮箱查对应 URL。
2. 在启动服务的终端设置 `RELOGIN_API_KEY`，使用自己生成的随机密钥，至少 24 个非空白字符。
3. 运行 `.\.venv\Scripts\python.exe -B relogin_service.py --config relogin.local.json`。默认监听 `127.0.0.1:8766`。
4. 将该服务通过自己的 HTTPS 反向代理提供给 Sub2API 后端，在凭证守护设置中把 `relogin_endpoint` 改为自己的 `https://YOUR_DOMAIN/api/v1/relogin`，并在 `relogin_headers` 中加入 `Authorization: Bearer YOUR_SERVICE_KEY`。
5. 通过 Sub2API 原有的账号添加/2FA 登录入口登录。后台任务取得 credential 后，由原页面继续调用账号导入接口，最后在账号列表核对分组、代理和账号 ID。

接口接受 ranxi 原请求：

```json
{"action":"start","email":"person@example.com","auth_mode":"password_2fa","password":"PASSWORD","mfa_secret":"BASE32_TOTP_SECRET"}
```

服务端使用配置的邮箱映射补充取码地址；调用方也可以扩展传入 `mail_url` 或 `otp_url`。原 ranxi 首次 2FA 接口不转发这些扩展字段，也不转发登录代理，所以直接接原网页时应使用服务端配置。单靠替换 endpoint 不会让旧网页自动出现邮箱 API 输入框；若希望网页当场填写，需要另外修改其前后端请求字段。工作台已经支持填写邮箱 API。

服务每 15 秒输出 NDJSON 心跳，适配 ranxi 的 60 秒空闲读取限制。成功事件格式：

```json
{"type":"result","payload":{"status":"success","credential":{"access_token":"...","refresh_token":"...","id_token":"...","client_id":"...","email":"person@example.com"}}}
```

失败返回结构化错误码，不回显账号输入；全程不记录请求内容或响应凭证。并发默认 3，满载返回 429；断开连接后发送取消信号。`/health` 仅返回服务状态。

登录进度中增加 `network_checking`、`network_matched`、`network_verifying`、`network_verified`。匹配/复核事件仅输出出口 IP、国家、时区、语言、UA 和浏览器版本；不含代理密码、邮箱 API 或 OAuth 凭证。只有出口复核通过才会输出登录成功结果。检测失败或不一致时会返回 `exit_detection_failed`、`exit_ip_mismatch`、`exit_country_mismatch`、`exit_timezone_invalid`、`exit_timezone_changed` 或 `unsupported_exit_country`。

Windows 下可在当前 PowerShell 中生成密钥，保留在环境变量里：

```powershell
$reloginKeyBytes = New-Object byte[] 32
$reloginRng = [Security.Cryptography.RandomNumberGenerator]::Create()
$reloginRng.GetBytes($reloginKeyBytes)
$env:RELOGIN_API_KEY = [Convert]::ToBase64String($reloginKeyBytes)
$reloginRng.Dispose()
.\.venv\Scripts\python.exe -B relogin_service.py --config relogin.local.json
```

密钥也须配置到 Sub2API 的 Authorization 请求头。示例命令在前台运行，服务器常驻部署可由 systemd 管理；接入状态与内部 endpoint 以实际部署记录为准。真实账号登录仍需在选定代理下验证。

## 协议与指纹

主流程为本地生成 OAuth state / PKCE → OpenAI authorize → 密码 → 按需 TOTP → 按需邮箱验证码 → 工作区选择 → 严格校验回调 → 在同一会话交换 token。TOTP 后再要求邮箱验证码的情况会继续处理。

支持从认证响应 JSON 保留本次会话信息，页面跳转后仍可读取工作区，不依赖旧版完整会话 cookie。必要时先加载授权页刷新工作区；仅有唯一候选或唯一个人工作区时自动选择，多个可选工作区则停止并提示人工选择。

OpenAI 和 Sentinel 请求复用同一 wreq 会话及同一代理。每次登录从 sentinel-rs 对齐的 Chrome140/145/146/149 档位中选择一档；该档位同时决定 UA major、低熵 Client Hints 和 TLS/HTTP2 emulation，禁止出现 UA 版本与握手档位不一致。每次登录还固定语言、时区、屏幕、硬件和 device ID，Sentinel JS 使用同一套画像。此实现没有运行真实浏览器；设置画像并不能证明服务端会接受它，也不能保证避开安全验证。Turb 自定义 JA3/HTTP2 变体未用于当前传输。

登录前通过同一 wreq 会话请求 `https://ipwho.is/`，取得公网出口 IP、国家和 IANA 时区：国家用于选择语言，时区采用检测站返回的具体时区，不再从国家池随机选择。UA、Client Hints、TLS/HTTP2 始终来自同一 Chrome 档位；wreq 平台明确指定 Windows，与画像的 Windows UA、平台和硬件配套，运行在 Linux 上也保持此画像。未覆盖的国家、检测失败、缺少或无效时区均停止登录，不静默套用美国/UTC，也不切换直连。

登录后再次通过同一会话检测，IP、国家、时区必须与登录前一致，之后才返回凭证。检测请求不含账号密码、验证码、代理凭据或 OAuth token。检测站看到的是对它发请求的出口；按域名分流或每请求轮换的代理仍可能让 OpenAI 看到另一 IP。应使用固定出口代理，让 OpenAI、Sentinel 和检测站走同一路由；前后检测不能证明每条中间请求的 IP 都相同。

工作台读取 Sub2API 代理列表，经过容量筛选，再通过本地 CONNECT 桥和实际登录的 wreq 会话核对后台选定的出口 IP；登录后复核出口。导入前如果代理被重新分配或出口发生变化，会丢弃本次凭证并要求重登。OAuth 回调只接受本次约定的完整地址与唯一 state/code；不实际请求 localhost 回调，不把密码、TOTP、邮箱 API 发给后台 `two-fa-login`。后台仍负责管理、代理查询与最终导入。

## Linux 运行与复用 Sub2API 代理

Linux 使用 CLI 或 HTTP 服务，不依赖 Tk、Playwright 或桌面。Python 至少 3.11，需 Node.js；[wreq 0.13.0 官方发行页](https://pypi.org/project/wreq/0.13.0/#files)提供 Linux 发行包。复制源码时排除 Windows 的 `.venv`、账号文件、运行日志，重新创建环境：

```bash
cd /opt/sub2api-login
bash install_local_login.sh
.venv/bin/python -B batch_login.py --help
```

CLI 复用后台代理示例（账号和管理员密码从隐藏提示读取）：

```bash
.venv/bin/python -B batch_login.py \
  --base-url https://YOUR_SUB2API_DOMAIN \
  --email YOUR_ADMIN_EMAIL \
  --group-ids 6 15 --proxy-name Dasho --login-engine local --login-only
```

CLI 获取后台代理配置、选择代理，用该代理登录并匹配指纹；去掉 `--login-only` 才导入。Linux 必须能连接代理的 host/port。后台中的 `127.0.0.1`、容器名和私有地址可能仅在原网络可达；把程序放到同一服务器的可达网络较方便。`--direct` 仅控制访问管理后台，不会让协议登录绕过选定代理。

自建 relogin 服务不从原版 2FA 请求收到 proxy_id；`relogin.local.json` 的 `proxy_url` 应填写与后台对应代理相同的连接地址和认证信息。不要把网站 URL 或仅有的出口 IP 当作代理地址。单服务当前使用一条固定代理；按账号动态复用绑定代理仍需扩展调用字段和服务端选路。

只检测出口及指纹，不提交账号、不启动监听服务：

```bash
.venv/bin/python -B relogin_service.py --config relogin.local.json --check-network
```

输出包含 `exit_ip`、`country_code`、`timezone`、`language`、`user_agent`、`browser`。正常服务仍使用 `RELOGIN_API_KEY`；Sub2API 在容器中时，服务应监听容器可访问的宿主机网桥地址，用相应内部 URL 配置 endpoint。

旧“后台登录任务”模式可手动选择，只支持原来的密码和 TOTP 输入。该模式仍调用后台 `two-fa-login`，不支持本地邮箱 API 自动取码。

导入后保留原有凭证运营登记：有 TOTP 时登记 password_totp；只有邮箱 API 时登记 email_otp_url。当前后端这两个模式分别保存凭证，password_totp 模式不会持久保存邮箱 API。后台后续自动重登由后台的引擎/Worker 配置决定；使用本程序的 relogin 服务时，应在该服务的 mailboxes 中保存邮箱 API 映射，并配置后台的 relogin endpoint 和鉴权头。首次导入与后续自动重登需分别验证。

## 换绑与限制

本次实现的是自动取码。Turb 的换绑流程是登录后的 `change_email/begin` → 新邮箱验证码 → `change_email/verify`，需要有效的 ChatGPT 登录凭证。遇到 reauth_required 还要先完成原邮箱重认证，所以它不能用来跳过登录前的原邮箱验证。程序不会在登录失败时更改账号邮箱。

要求手机号、补资料、浏览器安全验证、缺失或多个 TOTP factor、不明确的工作区和未知页面时会停止并给出原因。暂未提供多 TOTP factor 的人工绑定输入。账号登录和线上导入的实测结果以部署记录为准；不能承诺当前上游协议接受全部步骤，也不能据离线测试认定触发安全验证的概率下降。

此前 Windows 本机直连公共 Sentinel SDK 返回 HTTP 403；Ubuntu 部署时通过选定代理获取该 SDK 返回 HTTP 200。不同网络的结果不能互相代替；如果代理下被拒绝，程序会显示具体的 Sentinel 阶段和 HTTP 状态，停止继续提交凭证。

## 验证和来源

离线测试：

```powershell
.\.venv\Scripts\python.exe -B -m unittest test_login_network test_relogin_service test_protocol_login test_batch_login test_batch_gui test_oauth_mail_login test_oauth_proxy_transport
node --check login_vendor/openai_sentinel_quickjs.js
```

协议组件固定来源为 [Turb 1a1d86a](https://github.com/wangshen233/turb-register-public/tree/1a1d86a34695738213cdfd23bb1c4db049de8377)，TOTP factor 交互亦核对了 [toSub2](https://github.com/poxiao33/toSub2/blob/8548397e89bf80e508eda64a87e0d556d43abc84/src/protocol-login.mjs)。授权提示和许可见 `login_vendor/SOURCE.md`、`LICENSE`、`TURB_LICENSE`。原根文件备份保存在当前 Codex 任务工作目录的 `work/login-system-original`。

Sub2API 兼容接口核对的固定源码：[ranxi 调用与 NDJSON 读取](https://github.com/ranxi2001/sub2api/blob/41778efe6f7cb28dd2c70a4b70c6c8b6f04a352c/backend/internal/service/account_token_guard.go)、[2FA 异步任务](https://github.com/ranxi2001/sub2api/blob/41778efe6f7cb28dd2c70a4b70c6c8b6f04a352c/backend/internal/service/openai_two_fa_login.go)、[Codex 凭证导入](https://github.com/ranxi2001/sub2api/blob/41778efe6f7cb28dd2c70a4b70c6c8b6f04a352c/backend/internal/handler/admin/account_codex_import.go)。
