# 自动字段级隐私加解密改造计划

## Context

当前项目的核心能力是：

- `PrivacyGatewayFilter.encrypt_text` / `decrypt_text`：对整段文本做显式整段加解密。
- `process_inbound_text(..., encrypted=True/False)`：依赖调用方告诉库请求体是否已加密。
- APISIX 示例通过 `X-Privacy-Encrypted` Header 判断是否需要解密，并对成功响应整体加密。
- 敏感内容检测当前主要是 prompt-injection 短语阻断，不是 PII 字段级检测。

已确认的新需求：

- 不依赖特殊 Header 自动判断加密/解密。
- 不做整段 payload 加密。
- JSON 输入/输出必须先解析 JSON，再做字段识别和 PII 识别，不能直接对原始 JSON 字符串做粗暴文本替换。
- 必须支持普通自然语言文本中的 PII 自动识别与加解密。
- 敏感信息识别参考 Presidio：优先使用 Presidio Analyzer 识别常见实体；同时补充字段名规则和中文常见模式（例如身份证号、手机号、地址关键字等）。
- 密文 token 使用简单且有描述性的自描述格式，例如 `<secret:1:...>`，让系统无需 Header 即可识别密文并自动解密。
- 网关启动时通过环境变量预设一个 password/crypto key；所有字段级加解密都用这个服务端密钥。
- 密文必须可逆解密，否则 AI 无法恢复上下文并正确回答用户。

## Approach

推荐改造成“字段级 + 文本实体级隐私保护”能力，并保留现有整段加解密 API 作为兼容层：

1. 新增一个隐私 token/crypto 服务，负责：
   - 生成形如 `<secret:1:...>` 的自描述密文 token。
   - 解密任意文本中的 `<secret:1:...>` token。
   - 加密前先检测 token，避免二次加密。
   - 底层复用现有 `TextCryptoService`，密钥来自 `PRIVACY_GATEWAY_CRYPTO_KEY` 或新别名 `PRIVACY_GATEWAY_PASSWORD`。
2. 新增一个 PII 检测服务，负责：
   - 优先使用 Presidio Analyzer 识别 `PERSON`、`EMAIL_ADDRESS`、`PHONE_NUMBER`、`CREDIT_CARD`、`LOCATION` 等常见实体。
   - 增加自定义 recognizer/regex，覆盖 Presidio 默认不稳定或缺失的中文/业务类型：身份证号、手机号、中文地址关键词、常见中文姓名场景等。
   - 增加字段名规则作为 JSON 专用补充，例如 `name`、`real_name`、`password`、`address`、`id_card`、`phone`、`email`、`姓名`、`密码`、`地址`、`身份证号` 等。
3. JSON 处理必须“先 parse，再识别”：
   - 对请求/响应 body 先尝试 `json.loads`。
   - 若为 JSON object/list，则递归遍历 dict/list。
   - 对敏感字段名命中的整个字段值加密。
   - 对非敏感字段名中的字符串值继续用 PII 检测，只加密字符串内部识别到的实体片段。
   - 对已包含 `<secret:1:...>` 的字段/文本先自动解密或跳过二次加密，视处理方向决定。
   - 最后再 `json.dumps` 回 JSON 字符串。
4. 自然语言文本处理：
   - 非 JSON body 走文本 PII 管线。
   - 入站给 upstream/AI 前自动解密文本中的 `<secret:1:...>` token，使 AI 能看到明文并正确回答。
   - 出站给客户端前自动识别自然语言中的 PII 实体，并将实体片段替换为 `<secret:1:...>` token。
5. 新增高层 API：
   - `protect_data(data, crypto_key=None)`：对 Python JSON-like 数据结构做字段级/实体级加密。
   - `restore_data(data, crypto_key=None)`：对 Python JSON-like 数据结构自动解密 `<secret:1:...>` token。
   - `protect_text(text, crypto_key=None)`：对普通文本实体级加密。
   - `restore_text(text, crypto_key=None)`：对普通文本中的 token 自动解密。
   - `process_inbound_body(body, content_type=None, crypto_key=None)`：自动解析 JSON 或文本，先解密 token，再做 prompt-injection 阻断。
   - `process_outbound_body(body, content_type=None, crypto_key=None)`：先做 prompt-injection 阻断，再自动字段级/实体级加密。
6. APISIX 示例改为：
   - 不再读取或要求 `X-Privacy-Encrypted`。
   - 请求进入 privacy-proxy 后根据内容自动解析 JSON；JSON 解析成功则字段级处理，解析失败则文本实体级处理。
   - 转发给 upstream 的是恢复后的明文 body。
   - upstream 响应返回后，privacy-proxy 自动字段级/实体级保护响应 body。
   - 响应不再需要用 `X-Privacy-Encrypted` 表示整段加密；可选增加普通说明性 Header，例如 `X-Privacy-Protection: field-tokenized`，但逻辑不能依赖它。
7. 测试覆盖幂等、字段名识别、Presidio/regex 模式识别、自然语言实体替换、自动解密、无 Header 请求、APISIX 集成示例。

## Files to modify

预计需要修改/新增：

- `src/privacy_gateway/lib.py`
  - 挂载新的字段级 API 到 `PrivacyGatewayFilter`。
- `src/privacy_gateway/config.py`
  - 增加隐私字段/PII 检测配置，例如字段名列表、密文前缀、是否启用值模式检测。
- `src/privacy_gateway/__init__.py`
  - 导出新增数据结构/API。
- `src/privacy_gateway/services/presidio_crypto.py`
  - 复用文本 AES 加解密；必要时增加 token 包装/解析辅助。
- `src/privacy_gateway/services/privacy_tokens.py`（新增）
  - `<secret:1:...>` token 包装、检测、文本内 token 解密、幂等处理。
- `src/privacy_gateway/services/pii_detection.py`（新增）
  - Presidio Analyzer 封装、自定义中文/业务 recognizer、字段名规则、实体去重/区间合并。
- `src/privacy_gateway/services/privacy_fields.py`（新增）
  - JSON-like dict/list 递归扫描、字段名命中、值内 PII 替换、自动恢复。
- `src/privacy_gateway/adapters/http.py`
  - 弱化/废弃 `X-Privacy-Encrypted` 依赖；可保留常量兼容旧代码，但新流程不得依赖该 Header。
- `pyproject.toml`
  - 显式加入 `presidio-analyzer` 依赖；确认 spaCy/model 加载策略，避免运行时隐式下载模型。
- `apisix-plugin-example/privacy_proxy/server.py`
  - 改为 JSON 字段级自动恢复/保护，不再依赖 Header。
- `apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py`
  - 不再因为 `X-Privacy-Encrypted` 跳过检查；对 JSON 请求可先跳过已加密字段再检查明文字段。
- `apisix-plugin-example/init/configure_routes.py`
  - 移除 `skip_when_encrypted_header` 示例配置。
- `apisix-plugin-example/tests/integration_test.py`
  - 更新集成测试为无 Header、字段级加密/解密断言。
- `features/privacy_gateway.feature`
  - 增加 BDD 场景。
- `features/steps/privacy_gateway_steps.py`
  - 增加对应 step definitions。
- `README.md` 和 `apisix-plugin-example/README.md`
  - 更新行为说明和示例。

## Reuse

可复用现有实现：

- `PrivacyGatewayFilter._resolve_crypto_key` in `src/privacy_gateway/lib.py`
  - 继续支持显式 key 或 `PRIVACY_GATEWAY_CRYPTO_KEY`。
- `TextCryptoService.encrypt/decrypt` in `src/privacy_gateway/services/presidio_crypto.py`
  - 字段值加解密底层继续使用现有 Presidio AES。
- `SensitiveWordService` and `FilterDecision` in `src/privacy_gateway/services/sensitive_words.py` and `src/privacy_gateway/lib.py`
  - 继续用于 prompt-injection 阻断。
- `build_block_error` in `src/privacy_gateway/adapters/http.py`
  - HTTP 错误响应结构可继续复用。
- 现有 behave 测试结构 in `features/`
  - 适合扩展字段级隐私场景。

## Steps

- [ ] 将 `presidio-analyzer` 作为显式依赖加入项目，并设计 AnalyzerEngine 初始化方式；优先避免运行时隐式下载 spaCy 模型，必要时提供 no-op/simple NLP fallback。
- [ ] 设计稳定密文 token 格式：`<secret:1:...>`；内容尽量只放密文本身，保持简单、描述性、可逆。
- [ ] 新增 token 服务，支持检测、幂等加密、文本中多 token 自动解密、错误归一化。
- [ ] 新增 PII 检测服务，整合 Presidio Analyzer + 自定义 recognizer/regex + JSON 字段名规则。
- [ ] 新增 JSON-like 递归处理服务，确保 JSON body 先 parse 成 dict/list，再按字段和值识别处理。
- [ ] 新增自然语言文本处理服务，对非 JSON body 做实体级替换；入站先恢复 token，出站识别 PII 后替换为 token。
- [ ] 在 `PrivacyGatewayFilter` 上新增 object/text/body 级 API，并保留旧整段加解密 API。
- [ ] 更新配置，支持环境变量：
  - [ ] `PRIVACY_GATEWAY_CRYPTO_KEY` / `PRIVACY_GATEWAY_PASSWORD`
  - [ ] token 前缀/版本（默认 `<secret:1:...>`）
  - [ ] 启用的 Presidio entity types
  - [ ] 自定义敏感字段名列表
- [ ] 更新 APISIX privacy-proxy 示例，移除 Header 判断，改为 body 自动 JSON/text 分流和字段级/实体级自动恢复/保护。
- [ ] 更新 runner guard，确保无 Header 模式下仍能阻断明文 prompt injection，并避免把 `<secret:1:...>` 密文内容误判为提示词。
- [ ] 添加 BDD 和 integration tests：
  - [ ] JSON 请求必须先解析后识别字段，敏感字段值被加密，非敏感字段保持不变。
  - [ ] JSON 请求中 `<secret:1:...>` 字段不带 Header 也能自动解密后转发 upstream。
  - [ ] 普通自然语言文本中的邮箱、手机号、身份证号、姓名/地址等实体被替换为 token。
  - [ ] 文本中的 token 入站能自动解密，使 AI/upstream 看到明文。
  - [ ] 已加密字段不会二次加密。
  - [ ] prompt-injection 阻断继续工作。
- [ ] 更新文档，说明不再依赖 Header，说明支持的字段、Presidio 实体类型、中文补充规则和 token 格式。

## Verification

计划实现后运行：

```bash
uv run behave
uv run python -m compileall -q src/privacy_gateway \
  apisix-plugin-example/init \
  apisix-plugin-example/privacy_proxy \
  apisix-plugin-example/runner/apisix/plugins \
  apisix-plugin-example/upstream \
  apisix-plugin-example/tests
```

如需要验证 APISIX 示例：

```bash
podman compose -f apisix-plugin-example/compose.yaml up --build
podman compose -f apisix-plugin-example/compose.yaml run --rm integration-test
```

## Decisions / assumptions from user feedback

- JSON 输入/输出必须先解析再识别字段。
- 必须支持普通自然语言文本实体级加解密。
- PII 自动识别参考 Presidio，并用自定义规则补足中文身份证、地址等场景。
- 使用描述性的自描述 token，默认形如 `<secret:1:...>`。
- token 必须可逆解密；网关启动时从环境变量读取 password/crypto key。
- 新逻辑不能依赖 `X-Privacy-Encrypted` 或其他特殊 Header 来判断是否解密。

## Remaining implementation choices

- Presidio/spaCy 模型策略：实现时应避免 AnalyzerEngine 在生产启动时联网下载模型；推荐优先使用显式依赖/预装模型，缺失时降级到 regex + 字段名规则，并在日志/错误中提示。
- 中文人名/地址识别天然不可能完全准确；第一版用 Presidio + 正则/关键词启发式，后续可配置增强。
