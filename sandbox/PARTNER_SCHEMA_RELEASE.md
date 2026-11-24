# 合作方 OpenAPI 发布：operation 可见性核对与发布策略

基于本仓库 DRF 3.18.3 源码核对，配合 `sandbox/visibility_demo.py` 的小型 router 对照
（输出见 `sandbox/demo_output.txt`，可离线复跑：`.venv/bin/python sandbox/visibility_demo.py`）。

## 1. 当前生成器如何判定一个 operation 是否可见

可见性分两道闸门，任一不通过即不进入最终 schema。

**闸门一：URL 枚举（与角色完全无关）** — `rest_framework/schemas/generators.py:113`
`EndpointEnumerator.should_include_endpoint`：
- 回调不是 DRF 视图（`is_api_view` 为假）→ 剔除；
- `callback.cls.schema is None`，或 `initkwargs['schema'] is None` → 剔除
  （即 `schema = None` 的视图，如 `SchemaView` 自身，见 `rest_framework/schemas/views.py:14`）；
- `.{format}` 风格路径 → 剔除。
- 方法集合来自 `get_allowed_methods`（`generators.py:132`）：`OPTIONS`/`HEAD` 永远不生成；
  ViewSet 只取 `actions ∩ http_method_names`，未在 router 注册的方法天然不存在。

**闸门二：按请求上下文做权限过滤** — `rest_framework/schemas/openapi.py:73-76`
```python
_, view_endpoints = self._get_paths_and_endpoints(None if public else request)
for path, method, view in view_endpoints:
    if not self.has_view_permissions(path, method, view):
        continue
```
- `public=True`：`create_view` 收到 `request=None`，`view.request` 为 `None`，
  `has_view_permissions`（`generators.py:228`）直接返回 `True` —— **全部 operation 无条件可见**。
  `generateschema` 管理命令固定走这条路（`rest_framework/management/commands/generateschema.py:33`）。
- `public=False`：每个 method 用 `clone_request(request, method)` 克隆请求（`generators.py:206`），
  再调 `view.check_permissions(view.request)`，只跑各权限类的 **`has_permission`（全局级）**；
  抛 `APIException`/`Http404`/`PermissionDenied` 即隐藏。

**关键语义缺口（与真实请求不同）**
- 不调用 `check_object_permissions` / `has_object_permission` —— 对象级权限在 schema 阶段不可见。
- 不经过 `initial()`：没有认证入口差异、没有 `check_throttles`、没有内容协商；
  认证只在权限类读取 `request.user` 时惰性触发。
- 视图实例由生成器手工构造（`generators.py:187`）：`view.kwargs={}`、`view.args=()`、
  `view.format_kwarg=None`、`view.request=None`（public 模式）。任何依赖 path kwargs、
  对象查询结果的权限判断，在生成期与真实请求期行为不一致（可能误隐藏，也可能误放行）。
- `SchemaView.public` 默认 `False`（`views.py:17`），但 `get_schema_view(public=True)`
  与管理命令都会让过滤形同虚设。

## 2. 小型 router 对照（demo 的两组生成 × 真实请求）

router 含 4 个 ViewSet：公开目录、商品（混合全局/方法/对象级权限）、纯内部维护、
`schema=None` 的遗留路由；角色为匿名 / partner（partner 组）/ admin（is_staff）。

**A 组：三种生成上下文**

| operation | public=True | partner 上下文 | admin 上下文 | 隐藏依据 |
|---|---|---|---|---|
| `GET /api/internal/`、`POST /api/internal/{id}/rotate_key/` | 可见 | 隐藏 | 可见 | `IsAdminUser.has_permission` 在 partner 上下文拒绝；public 模式跳过检查 |
| `POST /api/items/`、`PUT/PATCH/DELETE /api/items/{id}/` | 可见 | 隐藏 | 可见 | `get_permissions()` 按 action 切到 `IsAdminUser`，写操作被拦 |
| `POST /api/items/bulk_reload/`（@action 自带权限） | 可见 | 隐藏 | 可见 | action 装饰器 `permission_classes=[IsAdminUser]` |
| `GET /api/items/{id}/` | 可见 | 可见 | 可见 | 全局级 `IsPartnerOrAdmin` 通过；**对象级权限未参与生成** |
| `GET/POST /api/public/` | 可见 | 可见 | 可见 | `AllowAny` |
| `GET /api/legacy/` | 隐藏 | 隐藏 | 隐藏 | 闸门一：`schema=None`，任何上下文都不枚举 |

**B 组：同一批 operation 的真实 dispatch 结果（完整认证+权限+对象权限）**

| 探针 | anon | partner | admin |
|---|---|---|---|
| 公开两个 operation | 200/201 | 200/201 | 200/201 |
| `GET /api/items/` | 403 | 200 | 200 |
| `GET /api/items/1/`（partner 对象） | 403 | 200 | 200 |
| `GET /api/items/2/`（staff 对象） | 403 | **403** | 200 |
| items 写操作 / `bulk_reload` | 403 | 403 | 2xx |
| internal 两个 operation | 403 | 403 | 200 |
| `GET /api/legacy/` | 200 | 200 | 200（但 schema 永远没有它） |

**每个隐藏/暴露分歧的依据**
1. partner 上下文生成时隐藏的 7 个 operation —— 与真实请求 partner 收到的 403 完全一致，
   属于**可稳定复用**的全局权限决策。
2. `public=True` 把这 7 个内部 operation 全部输出 —— 与真实 403 矛盾，直接发布即泄露内部接口形状。
3. `GET /api/items/2/`：真实请求 partner 被对象级权限拒绝，但 `GET /api/items/{id}/`
   在 partner 上下文 schema 中仍然可见 —— 生成器无法表达“同一路由部分对象不可见”，
   需要发布政策声明数据范围，而非靠 schema 隐藏。
4. `/api/legacy/`：真实可达但 schema 恒定缺失 —— 枚举层硬剔除，与权限无关；
   说明“schema 里没有”不等于“接口不可访问”，不能把 schema 当访问控制手段。

## 3. 哪些决策能稳定复用，哪些必须显式发布政策

**可稳定复用（生成器与真实请求结论一致，可作为过滤依据）**
- 仅依赖 `request.user` / `request.auth` 静态属性的 `has_permission`：
  `IsAuthenticated`、`IsAdminUser`、角色/组判断、`DjangoModelPermissions`
  （读 view 上的 `queryset`/`http_method_names`，不依赖 kwargs）。
- 基于 action/method 的 `get_permissions()` 分支、`@action(permission_classes=...)`
  —— 生成器会正确设置 `view.action`/`action_map`（`generators.py:196-203`）。
- 枚举层规则：`schema=None`、方法白名单（无 OPTIONS/HEAD）、`.{format}` 路径。
- 序列化器字段形状、分页/过滤参数、operationId、tags 等与角色无关的结构信息。

**必须用显式发布政策补齐（生成器判定不可信或不参与）**
- 对象级权限（`has_object_permission`）与 `get_queryset` 的租户/归属过滤：
  schema 只能按路由粒度可见，数据级范围要在文档中声明。
- 依赖 `view.kwargs`/`self.get_object()`/数据库状态的权限类：生成期 kwargs 为空，
  可能误判，需要逐个审计。
- 限流（throttling）、认证方式本身（session/token/签名）、版本协商、审计与合规要求：
  完全不在生成流程内。
- 枚举层被剔除但仍在线的路由（`schema=None`、非 DRF 视图、未挂 router 的内部入口）：
  需要独立的资产清单确认是否接受“不公开但可访问”。
- 合作方角色与真实请求主体不等价：生成用的合成 request 没有真实鉴权头、签名、IP、
  mTLS 上下文，凡权限类读取这些属性的，结论不具代表性。

## 4. 发布策略（保留现有公共 schema 用法）

1. **不动现有入口**：`get_schema_view()` / `generateschema` 的 public 行为保持原样，
   内部文档与既有消费方不受影响。
2. **新增合作方生成管线**：子类化 `SchemaGenerator`，以**合成的合作方身份 request**
   （服务账号 + 真实合作方认证器链）调用 `get_schema(request=synthetic, public=False)`，
   复用闸门二的全局权限过滤；再叠加一层显式 allow/deny 清单作为兜底
   （建议 deny 默认，按发布清单放行）。
3. **显式发布清单（source of truth）**：以 `(route 模板, method)` 为键维护发布政策，
   标注发布状态、数据范围说明、认证方式、弃用计划；生成器输出与清单做 diff，
   清单外 operation 一律剔除并在 CI 告警。
4. **覆盖生成器盲区**：对象级/数据级限制写进 operation 描述与合作方文档；
   对内部路由优先用 `schema=None` + 网络层隔离双重保证，而非只靠权限。
5. **发布前对照校验（把本 demo 固化成 CI 任务）**：对清单内每个 operation，
   同时跑“合作方上下文生成”与“合作方真实请求探针”，要求两侧可见/可达结论一致；
   出现“schema 可见但真实 403/404”或反向分歧时阻断发布。

## 5. 迁移范围与待查范围

**可直接迁移（结论可靠，按现有权限配置即可过滤）**
- 权限类只用 `request.user.is_authenticated/is_staff/组角色` 的视图与 action；
- `AllowAny` 公开接口；`get_permissions()` 按 action 静态分支、`@action` 权限声明；
- 已设 `schema=None` 的内部视图（确认这是有意为之，而非漏配）。

**待查范围（需人工/测试逐个定性后再决定发布口径）**
- 任何实现 `has_object_permission` 的视图：确认数据范围声明方式；
- 权限类中访问 `view.kwargs`、`self.get_object()`、`self.get_queryset()` 且结果随对象变化的；
- 权限类读取请求头/签名/IP、或依赖限流与版本判断的；
- 自定义 `AutoSchema`/重写 `get_schema` 的项目代码：确认没有绕过 `has_view_permissions`；
- 非 DRF 视图、未挂 router 的内部 URL、管理命令/异步任务触发的入口：不在枚举内，
  需独立资产盘点；
- 合成身份与真实合作方主体的差异点（token 声明、租户属性、认证器顺序），
  需用真实合作方凭证回放验证。
