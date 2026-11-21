# Loofah 升级上线验证方案

目标版本组合：`rails-html-sanitizer 1.7.1 + loofah 2.25.3 + nokogiri >= 1.15.7(排除 1.16.0~1.16.7)`。
本地方针基线：loofah 2.25.3 / nokogiri 1.19.7(见 `Gemfile.lock` 与 `.feedback/Gemfile.lock`)。

## 1. 依赖分支与安全处理对照

| 分支 | 触发条件 | 实际执行的安全处理 |
|---|---|---|
| HTML5 vendor(主分支) | `Loofah.html5_support?` 为 true(CRuby + libgumbo) | `Rails::HTML5::*Sanitizer`：HTML5 解析器 + `PermitScrubber`；属性值走 `Loofah::HTML5::Scrub.scrub_attribute_value`(html5lib 规则，修 GHSA-cpgf-5mjf-73p7)；SVG `use` 的 `href`/`xlink:href` 限本地锚点(GHSA-cj75-f6xr-r4g7)；`mglyph`/`malignmark`/`noscript` 强制移除；带命名空间节点一律 prune 防 mXSS |
| HTML4 vendor(vendor 无法选择时) | `Loofah.html5_support?` 为 false(如 JRuby) | 加载期不定义 `Rails::HTML5` 与 `Parser::HTML5`，`best_supported_vendor` 回退 `Rails::HTML4::Sanitizer`；scrub 逻辑(`PermitScrubber`/`Loofah::HTML5::Scrub.*`)不变，仅解析器换 HTML4 |
| 普通 SafeList(路径A) | 默认或 `tags:`/`attributes:` 选项 | 每次调用新建 `PermitScrubber`(1.7.2 起不再跨调用共享，修 GHSA-h7wh-q2qr-458c 并发串配置)；未设 tags/attributes 时回退 `fragment.scrub!(:strip)` |
| 自定义 scrubber(路径B) | `options[:scrubber]` | Loofah 强制要求 `Loofah::Scrubber` 子类；SafeList 配置完全不参与，安全边界由 scrubber 自身保证 |
| 独立 CSS 净化(路径C) | `sanitize_css` / `style` 属性 | 直接委托 `Loofah::HTML5::Scrub.scrub_css`(crass 解析)，与 HTML vendor 无关；`allowed_uri?` 委托 `Loofah::HTML5::Scrub.allowed_uri?` |
| 依赖版本降回 | loofah < 2.25.3 | gemspec 约束 `~> 2.25, >= 2.25.3` 在解析层拒绝；若被强制绕过，`PermitScrubber#scrub_attribute` 调 `scrub_attribute_value` 抛 `NoMethodError`，带 attributes 的净化请求全部 500 |

## 2. 小型兼容验证设计(全部离线)

脚本位于 `verification/`，运行方式：

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib verification/verify_loofah_upgrade.rb   # 主验证
.feedback/bundle-env exec ruby -Ilib verification/verify_vendor_fallback.rb  # vendor 回退
.feedback/bundle-env exec ruby -Ilib verification/verify_version_floor.rb    # 版本降回
.feedback/bundle-env exec ruby -Ilib -Itest test/sanitizer_test.rb           # 上游基线
```

- `verify_loofah_upgrade.rb`：A1–A10(SafeList)、B1–B3(自定义 scrubber)、C1–C6(CSS/URI)、3 条版本/vendor 探针。
- 探针式断言(`respond_to?`、危险子串不出现)而非全串比对，天然容忍序列化差异。

## 3. 离线证据与允许的输出差异

| 调用路径 | 证据文件 | 结果 | 允许的输出差异 |
|---|---|---|---|
| 上游基线 456 例 | `verification/evidence-full-suite.txt` | 0 failures | 无 |
| 路径A SafeList(A1–A10) | `verification/evidence-main.txt` | ALL PASS | 标签剥离后子文本保留为纯文本(A2)；属性顺序、空白折叠由 Nokogiri 后端决定 |
| 路径B 自定义 scrubber(B1–B3) | 同上 | ALL PASS | 非 `Loofah::Scrubber` 的拒绝异常类型不限(NoMethodError/TypeError 均可) |
| 路径C CSS 净化(C1–C6) | 同上 | ALL PASS | crass 序列化归一化：去空格、补尾分号，如 `color: red` → `color:red;`(C1/C2) |
| vendor 无法选择 | `verification/evidence-vendor-fallback.txt` | 回退 HTML4，净化/CSS/`allowed_uri?` 均正常 | HTML4 与 HTML5 解析器对畸形标签的切分不同；CSS 输出两分支一致 |
| 依赖版本降回 | `verification/evidence-version-floor.txt` | 解析层拒绝 + 运行层 NoMethodError 复现 | 无(降版即阻断项) |

## 4. 上线判定(go / no-go)

全部满足方可交付生产：

1. `Gemfile.lock` 解析出 loofah ≥ 2.25.3 且 nokogiri 不在排除清单；部署目标平台在 lock 的 `PLATFORMS` 内。
2. 启动探针通过：`Loofah::HTML5::Scrub` 响应 `scrub_attribute_value` 与 `scrub_css_attribute`(可放进 health check，降版即部署失败而非运行期 500)。
3. `verify_loofah_upgrade.rb` 全绿，且与上一版证据 diff 仅含第 3 节列出的允许差异。
4. 上游 `test/sanitizer_test.rb` 全绿(当前 406 runs / 0 failures)。
5. 生产运行时为 CRuby + libgumbo(HTML5 分支)；若目标环境是 JRuby 等 HTML5 不可用场景，须先跑通 `verify_vendor_fallback.rb` 并接受 HTML4 解析差异。
6. 灰度观察：净化接口 5xx 与 `NoMethodError` 告警为零、输出长度分布无异常偏移，再全量。
