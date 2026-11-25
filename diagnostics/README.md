# Grape 404 分诊约定（diagnostics）

运营报障“Grape API 返回 404”时，外部看到的可能只是同一个 `404 Not Found`，内部却停在大不相同的阶段。本目录给出一套可复跑的分诊约定：在两个合成挂载上，用一次 Rack 调用同时取得**外部应答**和**内部事件轨迹**，按阶段把问题分派给对应负责人。

- `synthetic_mounts.rb` — 两个合成挂载 + 诊断中间件（探针、身份门、门面）。
- `not_found_triage.rb` — 可复跑的调用表，自检 13 个场景，退出码即结论。
- `../spec/grape/diagnostics/not_found_triage_spec.rb` — 同一证据的 RSpec 固化。

复跑方式：

```sh
.feedback/bundle-env exec ruby -Ilib diagnostics/not_found_triage.rb
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r grape -r ./spec/spec_helper \
  spec/grape/diagnostics/not_found_triage_spec.rb
```

## 实际 Rack 调用梳理

一个请求穿过 Grape 的真实顺序（以本仓库代码为准）：

1. **路由候选**：`Grape::Router#call`（lib/grape/router.rb:49）规范化路径后按方法分派。命中路由时 `process_route` 把 `grape.routing_args`（含 `:route_info`）写上 env（lib/grape/router.rb:217）；全部未命中时路由器自己回答 `404` + `x-cascade: pass`（lib/grape/router.rb:323），**请求从未进入任何端点中间件栈**。
2. **端点中间件栈**：命中后进入端点栈，顺序为 `Error → use 自定义中间件（身份门在此）→ Versioner → Formatter → 端点运行`（lib/grape/endpoint.rb:481）。注意 `Grape::Middleware::Error` 在自定义中间件**之上**：栈内 throw/raise 的错误都由它渲染，`use 中间件` 在 `@app.call` 返回后**看不到**这些错误响应——所以“停在哪一阶段”的判定必须放在栈外（本约定放在 MountProbe）。
3. **版本协商**：位置取决于策略。`using: :path` 时版本段被编译进路由模式（lib/grape/middleware/versioner/path.rb:54 注释），未登记的版本在**路由阶段**就没有候选；`using: :param` / `:header` 时路径先进栈，由 Versioner 在栈内抛出 `404 API Version Not Found` 并带 `x-cascade: pass`（lib/grape/middleware/versioner/base.rb:57），此时 `api.version` 尚未写入 env。
4. **方法不支持**：本方法无路由但路径存在时，`after_miss` 找到 allowed-methods 路由（lib/grape/router.rb:159），`grape.allowed_methods` 只在该路由运行期间挂在 env 上（lib/grape/router.rb:235，运行完即删），端点回答 `405`（或 auto-OPTIONS 的 `204`）并带公开 `Allow` 头（lib/grape/endpoint.rb:271）。
5. **授权判定**：业务侧（这里是 IdentityGate）按制度对某身份隐藏路由时，回答与未登记完全相同的 404，且**不带** `x-cascade`，让级联到此为止。

## 诊断约定

**事件词汇**（记录在 `env['diagnostics.events']`，只进日志，不出进程）：

| 阶段 stage | 事件 event | 证据来源 |
|---|---|---|
| `router` | `no_candidate` / `candidate_matched` | 调用后 env 有无 `grape.routing_args` |
| `identity` | `entered` / `allowed` / `denied` | 身份门中间件自述 |
| `version` | `rejected` | 404 + 有候选 + `api.version` 未写入 + 未被拒绝 |
| `method` | `allow_readable` / `method_not_allowed` / `auto_options` | 栈内 `grape.allowed_methods`；栈外 `Allow` 响应头 |
| `endpoint` | `executed` / `error` | 挂载最终状态码 |

**规则**：

- R1 每个挂载各自记录路由候选事实。候选根本没进入身份中间件时，由 MountProbe 当场记下 `no_candidate`，**不许**事后从“没有身份事件”反推。
- R2 身份门的拒绝是终态：404、无 `x-cascade`、级联不再咨询后续挂载。
- R3 版本证据按策略读取：path 策略的版本协商证据在路由阶段（无候选即版本未登记）；param/header 策略在栈内（候选已匹配、`api.version` 未写入的 404 即版本被拒）。
- R4 **Allow 只在两处可读**：allowed-methods 路由运行期间的 `grape.allowed_methods`（栈内），以及 405/204 响应上的公开 `Allow` 头。任何 404 上方法支持一律记 `unconfirmed`，绝不回填——对隐藏路由回填 Allow 等于确认路径存在。
- R5 外部只暴露获准的路由事实：PublicFacade 把所有 404 归一成同体 `Not Found`、剥掉 `x-cascade`；405/204 原样放行（`Allow` 按 RFC 9110 本就是公开的）；200 只暴露该身份获准动作本身的返回。
- R6 级联用 `x-cascade` 头判定（HeaderCascade，与 Grape 路由器自身约定一致）。**不要**用 `Rack::Cascade`：它按 404/405 **状态码**穿透，会把制度性拒绝的 404 漏给下一个挂载，也会把 405 的 `Allow` 吞进下一个挂载的 404。

**分派**：

| 终态 | 分派给 |
|---|---|
| 所有挂载 `router:no_candidate` | 路由登记/部署（路径或 path 版本未登记） |
| `version:rejected` | 版本协商配置或客户端调用方式 |
| `identity:denied` | 授权策略负责人（按制度隐藏，非缺陷） |
| `method:method_not_allowed` | 客户端按 `Allow` 改用方法 |
| `endpoint:executed` | 已获准动作，看业务结果 |

## 可复跑调用表

`ruby -Ilib diagnostics/not_found_triage.rb` 的实际输出（自检 13/13 通过）：

```
== Grape 404 triage -- reproducible call table ==
stack: PublicFacade -> HeaderCascade -> [MountProbe(LedgerAPI v1/path), MountProbe(ReportsAPI v2/param)]

#  scenario                         request                                ext    Allow (public)         terminal internal stage
--------------------------------------------------------------------------------------------------------------------------------
1  unregistered path                GET /v1/nope [token=ops-alice]         404 Not Found unconfirmed            reports/router:no_candidate
2  unregistered version (path)      GET /v9/ledger [token=ops-alice]       404 Not Found unconfirmed            reports/router:no_candidate
3  version rejected (param)         GET /reports?apiver=v9 [token=ops-alice] 404 Not Found unconfirmed            reports/version:rejected
4  hidden, operator token           GET /v1/ledger/hidden [token=ops-alice] 404 Not Found unconfirmed            ledger/identity:denied
5  hidden, anonymous                GET /v1/ledger/hidden                  404 Not Found unconfirmed            ledger/identity:denied
6  hidden on mount B, operator      GET /reports/hidden?apiver=v2 [token=ops-alice] 404 Not Found unconfirmed            reports/identity:denied
7  method not supported             POST /v1/ledger [token=ops-alice]      405 {"error":"405 Not Allowed"} OPTIONS, GET, HEAD     ledger/method:method_not_allowed
8  auto-OPTIONS                     OPTIONS /v1/ledger [token=ops-alice]   204    OPTIONS, GET, HEAD     ledger/method:auto_options
9  hidden path, unsupported method  POST /v1/ledger/hidden [token=ops-alice] 404 Not Found unconfirmed            ledger/identity:denied
10 hidden path, method, root        POST /v1/ledger/hidden [token=root-admin] 405 {"error":"405 Not Allowed"} OPTIONS, GET, HEAD     ledger/method:method_not_allowed
11 hidden, authorized root          GET /v1/ledger/hidden [token=root-admin] 200 {"ledger":"off-book"} unconfirmed            ledger/endpoint:executed
12 public, operator token           GET /v1/ledger [token=ops-alice]       200 {"balance":1024} unconfirmed            ledger/endpoint:executed
13 public on mount B                GET /reports?apiver=v2 [token=ops-alice] 200 {"reports":["daily","weekly"]} unconfirmed            reports/endpoint:executed
```

读表要点：

- 第 1–6 行外部应答**逐字节相同**（`404 Not Found`、无 `Allow`、无 `x-cascade`），内部却分别停在路由候选、版本协商、身份门三个阶段——这就是“同一外部 404 对应不同内部阶段”。
- 第 7–8、10 行是**能读取 Allow** 的步骤：栈内 `grape.allowed_methods` 与公开 `Allow` 头互相印证。其余各行只能保留 `unconfirmed`。
- 第 9 行：隐藏路径 + 不支持的方法 + 未获准身份 → 仍是 404，Allow 随隐藏一起被压掉；第 10 行同一路径换成 `root-admin` 才确认 `Allow`。
- 第 11 行：获准动作成功（隐藏路由对 `root-admin` 返回 200）。
