# sentinel-rs 更新评估与本项目适配

评估日期：2026-11-23。时间为北京时间。检查的上游为 [wangshen233/sentinel-rs](https://github.com/wangshen233/sentinel-rs)，最新提交为 `f222371c7960be490baf4ab1a2873da900506f2a`；本项目修改基线为 `c99a37ce8454cac957d9dcc731420927613e20d3`。

## 最近更新

| 时间 | 提交 | 内容 |
| --- | --- | --- |
| 2026-11-18 22:43 | [f222371](https://github.com/wangshen233/sentinel-rs/commit/f222371c7960be490baf4ab1a2873da900506f2a) | 清理个人路径、真实邮箱端点和供应商示例；本地 WebUI 配置移出版本控制；补充运行产物的忽略规则。 |
| 2026-11-18 22:02 | [3a8f3b2](https://github.com/wangshen233/sentinel-rs/commit/3a8f3b229648b2c32ef5c01311232cb5ce0c9aaa) | 大幅更新设备画像、TLS/HTTP2 档位与请求头同源约束；增加静态邮箱池、代理轮换、运行期出口探测、JSON `no_code` 待机语义和 WebUI。 |
| 2026-11-18 21:35 | [2c1b60f](https://github.com/wangshen233/sentinel-rs/commit/2c1b60f) | 增加设备指纹生成器基础实现。 |

查询时没有比 11 月 18 日更新的提交。上次记录只覆盖了邮箱接口，因此遗漏了 `3a8f3b2` 中的指纹、传输和协议链路变更。本次补充核对了 `src/fingerprint.rs`、`src/flow/http.rs`、`src/flow/auth.rs`、`src/flow/mod.rs`、`src/flow/otp.rs` 和 `src/token.rs`。

### 指纹与协议更新的实际内容

- 指纹由多个浏览器版本档位、Windows 屏幕、DPR、硬件并发数、设备内存、国家/时区/语言画像组合生成，并要求 UA、低熵 Client Hints、token profile 与 TLS/HTTP2 档位同源。
- 上游把 Chrome 140/145/146/149 作为成套档位；目标项目当前的 `Chrome152` UA/Client Hints 与 `Chrome152` wreq 选择仍是另一套实现，且目标环境的 wreq 版本约束并不等于上游 Rust 的 wreq-util。
- 上游增加了代理文件轮换和运行期出口国家探测；目标项目已经有显式代理、出口 IP/国家/时区校验与 IPv4 bridge，但接口、生命周期和错误码不同。
- 上游注册流程中的跳过冗余 token 交换、邮箱池和 WebUI，不属于目标项目当前的本地登录/导入契约，直接复制会改变登录状态机和凭证边界。

上游是 Rust 项目，使用 Cargo 的 `wreq=0.16.1`、`wreq-util=0.2.0`；本项目是 Python 服务，依赖 Python `wreq==0.13.0`、Node Sentinel 适配器和既有 Sub2API 导入流程。Rust 模块不能作为 Python 文件直接替换。涉及自动化注册、浏览器指纹伪装或规避第三方风控的改动未直接移植；目标仓库保留其现有的画像一致性校验、显式代理约束和协议错误处理。

## 实际修改

1. 邮箱接口待机响应优先于验证码正文。原实现会跳过 `code=no_code` 字段，却仍从附带正文中抽取旧的六位数字；现在待机响应整体进入等待状态，包括 `code=null`、空字符串和上游定义的暂无验证码占位值，以及嵌套的 `data` / `result`。
2. 补充上游使用的验证码、时间戳字段别名，保留收件人、发件人、新鲜度、快照和已使用验证码检查。字段大小写不同但值冲突时拒绝选码。
3. 区分 HTTP 200 内的邮箱 API 失败与正常待机。明确的授权失效、邮箱过期或不可重试失败会立即结束本次邮箱读取，不再持续等到取码超时。诊断只返回固定说明，不回显邮箱 API 正文或链接。
4. 读取响应时检查停止信号与剩余预算；预算已耗尽时不再发起 GET，检测到过期或取消时不使用部分响应。该检查发生在响应块交付时；requests 的底层读取仍受其 socket timeout 约束。
5. GUI 与两个命令行入口去掉预填的个人站点和管理员邮箱，改由 `SUB2API_BASE_URL` / `SUB2API_EMAIL` 或显式参数提供。批处理 JSON 导出目录、`.used` 和 `.bak` 加入忽略规则。

没有复制上游注册流程的通用 POST 重试策略；本项目原有的认证请求处理及登录结果校验保持现有实现。

## 兼容示例

待机：

```json
{"success":false,"code":"no_code","retryable":true}
```

收到新邮件：

```json
{"ok":true,"data":{"verificationCode":"123456","receivedAt":1794929150000,"recipient":"person@example.com"}}
```

`retryable=true` 不会屏蔽明确的 `invalid_token` 等授权错误；未知的普通 JSON 状态页没有可用码时仍继续等待。原有六位文本、常见 JSON 和 WDMail HTML 返回形式继续支持。

## 验证

新增离线邮箱契约测试覆盖待机响应夹带旧码、字段别名、授权错误脱敏、快照失败、过期与已用验证码、响应中断和读取超时。验证仅使用模拟响应与本地测试服务；未登录真实账号、调用真实邮箱或部署服务器。

在 Windows 的 Python 环境中运行 `python -B -m unittest discover -q`：共 193 项，190 项通过，3 项按原有 opt-in 开关跳过（旧版浏览器流程的离线冒烟测试），无失败。GUI 测试与 Node 离线运行时测试包含在本次回归中。该结果不代表 Linux 实机或真实账号登录已验证。源码 SHA-256 清单同步更新。
