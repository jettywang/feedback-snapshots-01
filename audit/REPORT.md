# dry-schema JSON Schema 导出保真性审计

> 对象：本仓库 `dry-schema 1.17.0`（`lib/dry/schema/version.rb`）。所有结论均来自本地
> `Dry::Schema.Params` / `Dry::Schema.JSON` 实跑与 `schema.json_schema` 实际输出，
> 无外部服务。复现命令见 `audit/README.md`。

## 1. 导出到底代表什么

`json_schema` 只做一件事：把 `processor.to_ast` 交给 `SchemaCompiler` 遍历
（`lib/dry/schema/extensions/json_schema.rb:19-23`）。而 `to_ast` 来自
`RuleApplier#to_ast` / `DSL#rules`（`lib/dry/schema/rule_applier.rb:38-44`、
`lib/dry/schema/dsl.rb:401-403`）。

因此导出的是**规则 AST 的静态投影**，不是处理器行为。以下运行时机制根本不进 AST：

- 键名校验（`config.validate_keys`，`lib/dry/schema/dsl.rb:200`，实现见
  `lib/dry/schema/key_validator.rb`）；
- 键名 stringify（`key_coercer`，`lib/dry/schema/dsl.rb:440-442`，配合
  `lib/dry/schema/params.rb:12` / `json.rb:12`）；
- 值强转（`value_coercer`，`lib/dry/schema/dsl.rb:449-451`、
  `lib/dry/schema/value_coercer.rb:19-33`）；
- `before` / `after` 回调（`lib/dry/schema/dsl.rb:252-270`，执行见
  `lib/dry/schema/processor_steps.rb:35-43`）；
- `filter` 预校验（`lib/dry/schema/dsl.rb:204`、`lib/dry/schema/macros/key.rb:25-28`）；
- 类型对象上的 `default`（`lib/dry/schema/dsl.rb:316-321` 只保留 meta，不导出）。

一个直接推论：**Params 与 JSON 的导出逐字节相同**，因为两者共用同一 AST，差异只在
`type_registry_namespace` 与 `filter_empty_string`（`params.rb:11-15`、`json.rb:11-16`）。
本次 v1/v2 两版实测 `params_json_equal_json=true`。

另一个易被忽略的点：`json_schema` 返回的是**符号键的 Ruby Hash**，不是 JSON 文本。
合作方拿到的是 `JSON.generate` / `to_json` 之后的结果；序列化会把 `included_in?:`
里的 Symbol 变成字符串（见 2.4 的 `symbol enum`），也会把 `Date` 边界变成
ISO-8601 字符串。审计脚本一律先 `JSON.parse(JSON.generate(...))` 再判断，
以合作方实际收到的文档为准。

## 2. 导出与运行态的差异清单

### 2.1 转换（coercion）造成的差异

| 现象 | 导出 | 运行态 | 依据 |
|---|---|---|---|
| 整数/浮点/布尔/日期/时间强转 | 只有目标 `type` | Params 接受 `"7"`、`7.0`、`"true"`、`"1"`、`"2024-2-9"`、`"Feb 9 2024"` 等；JSON 只接受原生 JSON 类型 | `value_coercer.rb:19-33`；construct_probes `integer coercion` / `float strictness` / `filter + date` |
| `:nil` 类型遇空串 | `{"type":"null"}` | Params 把 `""` 变 `nil`；JSON 报错 | `dry-types` `Coercions::Params.to_nil`（`coercions/params.rb:29-36`） |
| `maybe(:string)` 遇 `""` | `type: ["null","string"]` | 两者都通过，但 Params 输出 `nil`、JSON 保留 `""` | `maybe` 把类型解析为 `params.nil | params.string` 的 Sum，左支先把 `""` 强转成 `nil`（`macros/dsl.rb:280-288`） |
| `maybe(...)` + `enum`/`const` | `type: ["null",...]` **且** `enum`/`const` | 导出把 `null` 排除在允许值之外；运行态 `nil` 合法 | `schema_compiler.rb:39-40` 无条件合并 `enum`/`const`；`visit_implication` 只跳过外层 `required`（`schema_compiler.rb:154-158`）；construct_probes `maybe + enum` / `maybe + const` |
| `maybe(:string, included_in?: ...)` 遇 `""` | `type: ["null","string"]` + `enum` | Params 把 `""` 变 `nil` 通过；JSON 报枚举错误 | construct_probes `maybe + enum` 第三列 |
| `filled(:hash)` 遇 `{}` | `{type: "object", not: {type: "null"}}` | 空 hash 失败（“must be filled”） | `schema_compiler.rb:264-274` 只映射成非 null；construct_probes `filled(:hash)` |
| `filled`（无类型）遇 `""`/`[]`/`{}` | `{not: {type: "null"}}` | 全部失败 | `fetch_filled_options` 的 else 分支（`schema_compiler.rb:272-274`）；construct_probes `filled bare` |

### 2.2 缺省（default）与缺省值造成的差异

| 现象 | 导出 | 运行态 | 依据 |
|---|---|---|---|
| `required(:tier).value(Types::String.default("free"))` | `required: ["tier"]`，无 `default` | 缺键也能通过，输出补 `tier: "free"` | `dsl.rb:316-321` 丢弃 default；construct_probes `defaulted required` |
| `optional` + default | `required: []`，无 `default` | 缺键也补默认值 | 同上 |
| `maybe(:hash) { required(:a) ... }` 内层必填 | 外层 `properties` 有 `a`，但 `required: []` | 内层 `a` 缺失会失败 | `visit_implication` 用 `required: false` 贯穿（`schema_compiler.rb:154-158`）；construct_probes `maybe hash nested` |
| `optional` 嵌套 hash | 嵌套 `required` 保留 | 仅在键出现时校验 | 这是少数导出与运行态一致的缺省语义 |

### 2.3 错误路径 / 运行期异常

| 现象 | 导出 | 运行态 | 依据 |
|---|---|---|---|
| `filled(:array)` | **抛 `UnknownConversionError`** | 正常运行 | `schema_compiler.rb:264-274` 对 `array` 直接 raise；construct_probes `filled(:array)` |
| `maybe(:array).each(...)` 遇 `nil` | 合法（`type: ["null","array"]`） | **抛 `NoMethodError: undefined method 'map' for nil`** | `dry-logic` Each 不判空；construct_probes `maybe array each` |
| 不支持谓词（`excluded_from?`、`bytesize?`、`not_eql?`、`is?`、`case?`、`type?` 等） | 默认 raise；`loose: true` 静默丢弃 | 正常运行 | `schema_compiler.rb:252-256,299-310` |
| `size?` / `min_size?` 用 `Range` | **`NoMethodError: to_i for Range`**，连 `loose` 也救不了 | 正常运行（`size?` 支持 Range） | `schema_compiler.rb:31,239-249`；construct_probes `size? Range` |
| `messages.namespace` 设置后 | `NoMethodError: visit_namespace` | 正常运行 | `rule_applier.rb:39-41` 产出 `:namespace` 节点，compiler 无对应 visit |
| `format()` 含内联 flag | 产出 `(?i-mx:...` 缺右括号的非法 pattern | 正常运行 | `schema_compiler.rb:32-36` 用 `delete_suffix(")")` 粗暴去尾 |
| 无 `str?` 类型直接用 `format?`/`uuid_v4?` | 只有 `pattern`，无 `type` | 非字符串输入触发 `TypeError`，而非正常失败 | `fetch_filled_options`/谓词映射不补类型 |

### 2.4 关键字语义被改写

| 现象 | 导出 | 运行态 | 依据 |
|---|---|---|---|
| hash 的 `min_size?`/`max_size?`/`size?` | `minLength`/`maxLength`（字符串关键字） | 按**键数**校验 | `schema_compiler.rb:29-31` 不区分容器 |
| 数组 `size?` | `items: {minLength, maxLength}` | 按**数组长度**校验 | 同上；construct_probes `array size?` |
| `array(:hash, min_size?: 2)` | `items: {minLength: 2}` | 对**每个 hash 元素**按**键数**校验 | 同上；construct_probes `array(:hash) min_size` |
| `array(:integer, min_size?: 2)` | `items: {minLength: 2}` | 对**每个元素**调 `Integer#size`（字节数）；`[1]` 能过，`[2**200]` 才是失败 | 同上；construct_probes `array(:hash) min_size` 同型，但 hash 按键数 |
| 整数 `min_size?` | `minLength` | 调 `Integer#size`（字节数） | 同上 |
| `gt?`/`gteq?` 用于字符串/日期 | `exclusiveMinimum`/`minimum`（数值关键字） | 字符串比较/日期比较 | `schema_compiler.rb:67-70` 不区分类型；construct_probes `string gt` / `date gt` |
| `uri?` 带 scheme | `format: "uri"` | 只接受指定 scheme（如 `https`） | `schema_compiler.rb:42`；construct_probes `uri scheme` |
| `uuid_v4?` 大小写 | pattern 只允许小写 | 运行态大小写都接受（`Regexp::IGNORECASE`） | `schema_compiler.rb:52-54` vs `dry-logic` `uuid_format` |
| `true?`/`false?` | 空 schema `{}`（或仅保留 `bool?` 的 `type`） | 强制 `=== true` / `=== false` | `schema_compiler.rb:37-38` 映射为空；construct_probes `true? only` / `bool + true?` |
| `odd?`/`even?` 用 `:odd?` | `type: integer` + `multipleOf` | 对 `Float` 调用 `odd?` 直接 `NoMethodError` | `schema_compiler.rb:71-72`；construct_probes `float odd` |
| Symbol 枚举 `included_in?: %i[a b]` | 内存 hash 里是 Symbol，JSON 文本变字符串 | 运行态只接受 Symbol | construct_probes `symbol enum` |
| 无 `type` 的 `included_in?` | 只有 `enum`，无 `type` | 任意对象按 `include?` 判断 | `schema_compiler.rb:39` |

## 3. 小 schema 版本对

基线 v1（宽松）与收紧后的 v2：

```ruby
# v1
required(:tenant_id).value(:integer)
required(:role).value(:string)
optional(:scopes).value(:array).each(:string)
optional(:expires_on).value(:date)
optional(:channel).value(:string)

# v2
config.validate_keys = true
required(:tenant_id).value(:integer, gt?: 0)
required(:role).value(:string, included_in?: %w[admin editor viewer])
required(:scopes).value(:array, min_size?: 1, max_size?: 5)
  .each(:string, included_in?: %w[read write approve])
required(:expires_on).value(:date)
optional(:channel).maybe(:string, included_in?: %w[web mobile])
required(:tier).value(Dry::Schema::Types::String.default("free".freeze))
```

完整导出见 `audit/version_pair.json`。v2 的 JSON 文本：

```json
{"$schema":"http://json-schema.org/draft-06/schema#","type":"object",
 "properties":{
   "tenant_id":{"type":"integer","exclusiveMinimum":0},
   "role":{"type":"string","enum":["admin","editor","viewer"]},
   "scopes":{"type":"array","minItems":1,"maxItems":5,
             "items":{"type":"string","enum":["read","write","approve"]}},
   "expires_on":{"type":"string","format":"date"},
   "channel":{"type":["null","string"],"enum":["web","mobile"]},
   "tier":{"type":"string"}},
 "required":["tenant_id","role","scopes","expires_on","tier"]}
```

`audit/json_schema_fidelity.rb` 的输出中，v1 与 v2 的 Params/JSON 导出均相等。

## 4. 合法输入的结果矩阵

`v2 export` 两列用同一份导出文档（先序列化再解析，即合作方实际收到的 JSON 文本）
做子集求值：`format ignored` 把 `format` 当注解，`format enforced` 对 `date` 施加
ISO-8601。`OK` = 通过，`FAIL` = 拒绝，`N/A` = 导出无法被忠实求值（例如非法 pattern）。
注意：脚本内 `pattern` 用 Ruby 正则求值；ECMA-262 不认 `\A`/`\z`，部分实现会因此
报 schema 非法。本版本对的导出不含 `pattern`，但涉及 `format?` / `uuid_*?` 的审批
应另用消费者的校验器复验。

| case | v1 Params | v1 JSON | v2 Params | v2 JSON | v2 export (format ignored) | v2 export (format enforced) |
|---|---|---|---|---|---|---|
| full | OK | OK | OK | OK | OK | OK |
| no_tier(default) | OK | OK | OK | OK | FAIL | FAIL |
| channel_null | FAIL | FAIL | OK | OK | FAIL | FAIL |
| loose_date | OK | OK | OK | OK | OK | FAIL |
| tenant_string | OK | FAIL | OK | FAIL | FAIL | FAIL |
| tenant_float | OK | FAIL | OK | FAIL | OK | OK |
| scopes_two | OK | OK | OK | OK | OK | OK |
| extra_key | OK | OK | FAIL | FAIL | OK | OK |
| missing_scopes | OK | OK | FAIL | FAIL | FAIL | FAIL |
| scopes_empty | OK | OK | FAIL | FAIL | FAIL | FAIL |
| scopes_six | OK | OK | FAIL | FAIL | FAIL | FAIL |
| scope_invalid | OK | OK | FAIL | FAIL | FAIL | FAIL |
| role_case | OK | OK | FAIL | FAIL | FAIL | FAIL |
| tenant_zero | OK | OK | FAIL | FAIL | FAIL | FAIL |
| tenant_missing | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| date_invalid | FAIL | FAIL | FAIL | FAIL | OK | FAIL |
| tier_null | OK | OK | FAIL | FAIL | FAIL | FAIL |
| channel_tv | OK | OK | FAIL | FAIL | FAIL | FAIL |

可安全依据导出的行（v2 的两套运行态与两列导出全部一致）：`full`、`scopes_two`，
以及拒绝方向上的 `missing_scopes`、`scopes_empty`、`scopes_six`、`scope_invalid`、
`role_case`、`tenant_zero`、`tenant_missing`、`tier_null`、`channel_tv`。

必须附运行态证据的行：

- `no_tier(default)`：运行态补默认值通过，导出因 `required: ["tier"]` 判失败。
- `channel_null`：导出 `enum: ["web","mobile"]` 不包含 `null`，但 `maybe` 允许 `nil`。
- `loose_date` / `date_invalid`：导出是否拒绝取决于消费者是否实现 `format`。
- `tenant_string` / `tenant_float`：Params 强转通过，JSON 与导出都拒绝。
- `extra_key`：只有运行态 `validate_keys` 能拒绝，导出里没有 `additionalProperties: false`。

## 5. 安全审批建议

可以只凭导出批准（导出足够紧，且运行态不会更宽）：

- 字段级枚举收紧：`role`、`scopes` 的 `enum`（注意 `channel` 是 `maybe` + `enum`，
  不能只凭导出批准，见下）。
- 数量收紧：`scopes` 的 `minItems`/`maxItems`。
- 数值下界：`tenant_id` 的 `exclusiveMinimum`。
- 必填字段新增：`required` 数组（但涉及 default 的字段除外，见下）。

必须附运行态证据（导出不忠实或导出更宽）：

- `config.validate_keys = true` 的任何审批：导出没有 `additionalProperties: false`，
  只能由运行态证明未知键被拒绝。
- 任何依赖 `default` 的必填字段：导出仍列为 `required`，与运行态不一致。
- 任何 `maybe` + `enum`/`const`（本版本对里的 `channel`）：导出会把 `null` 排除，
  运行态却允许 `nil`。
- 任何 `filled(:array)`、`maybe(:array).each(...)`、`size?: Range`、
  `messages.namespace` 的 schema：导出可能直接抛异常。
- 任何通过 `filter` 表达的前置约束：导出只有后续 `value` 的类型（`filter` 本身
  不进规则 AST，只在独立 `filter_schema` 步骤执行，`dsl.rb:204`）。
- 任何 `before`/`after` 回调、`gt?` 用于字符串/日期、hash 的 `size` 约束：
  导出关键字语义与运行态不同，需附 Params 与 JSON 两套实跑结果。
