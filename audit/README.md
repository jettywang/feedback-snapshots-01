# JSON Schema 导出一致性审计

针对 dry-schema `1.17.0` 的实际导出结果，与 `Dry::Schema::Params` / `Dry::Schema::JSON`
运行时行为逐项对照。全部在本地完成，无外部服务。

## 复现

```sh
BUNDLE_FROZEN=true .feedback/bundle-env exec ruby -Ilib audit/json_schema_fidelity.rb
BUNDLE_FROZEN=true .feedback/bundle-env exec ruby -Ilib audit/construct_probes.rb
```

- `version_pair.json` — v1/v2 的 Params 与 JSON 导出（两者逐字节相同）。
- `json_schema_fidelity.rb` — 小型 draft-06 子集求值器 + v1/v2 定义 + 18 条输入矩阵。
  求值器支持 `N/A`（导出无法忠实求值的关键字），并在判断前把导出序列化为 JSON 文本。
- `construct_probes.rb` — 单个规则构造的导出 / Params / JSON 三方对照。

## 结论摘要

1. `json_schema` 只读取规则 AST（`lib/dry/schema/extensions/json_schema.rb:21`），
   Params 与 JSON 共用同一 AST，因此两者导出在结构上必然相同。
2. 导出不包含流水线行为：`key_validator`（`dsl.rb:200`）、键名 stringify
   （`dsl.rb:441`）、值强转（`dsl.rb:450`）、`before/after` 回调（`dsl.rb:252,267`）、
   `filter` 预校验（`dsl.rb:204`）、类型 `default`（`set_type`/`value_coercer`）。
3. 多个导出关键字在运行态对应更宽或更窄的规则，详见报告与 construct_probes。
