Telegram 订阅查询 Bot

当前版本功能

- Telegram 群组和私聊自动接收普通文本、单条节点 URI、订阅 URL、TXT 文件及 YAML 文件。
- 支持 VLESS、VMess、Shadowsocks（SS）、Trojan、Hysteria、Hysteria2（HY2）、AnyTLS、TUIC、HTTP、SOCKS5。
- 支持 Base64 订阅文本、普通节点 URI，以及 Clash/Mihomo YAML 的 "proxies"。
- 自动统计协议类型、节点总数、国家/地区数量、重复节点数量和实际唯一节点数量。
- 保留所有解析成功的节点，不删除、不合并重复节点，只统计重复数量。
- 节点名称完整保留原始内容，不翻译、不改写、不清理乱码。
- 地区根据节点备注中的国家/地区名称识别，不进行 GeoIP 查询；无法识别时显示 🌐未知。
- 尽可能读取订阅响应头中的流量和到期信息；无法读取时显示未知。
- 六个按钮：
  1. 刷新订阅信息
  2. 展开/折叠节点
  3. 导出 Base64
  4. 导出 YAML
  5. 生成短链
  6. 保存订阅
- 节点展示默认显示前 20 个；点击折叠后只显示前 2 个，再次点击恢复前 20 个。通过编辑原消息完成，不额外发送消息。
- 超过 20 个节点时提示还有多少节点未展示。
- 群组普通成员可以发送订阅内容触发解析，但只有群组管理员可以使用结果按钮；私聊用户可以正常使用按钮。
- 群组管理员身份通过 Telegram "getChatMember" 实时验证。建议 Bot 在群组中拥有管理员权限，以保证身份检查可靠。

操作限次规则

- 刷新、导出 Base64、导出 YAML、生成短链、保存订阅，五项操作分别限次。
- 同一个 Telegram 用户、同一个输入指纹，每项操作成功一次。
- 不同 Telegram 用户分别计算使用次数。
- 不同订阅 URL 或输入内容分别计算使用次数。
- 操作失败不消耗次数，可以重新尝试。
- 使用 Durable Objects SQLite 进行原子领取，避免并发请求突破限次。
- 节点展开/折叠不消耗次数。

短链与保存订阅

- KV 用于解析结果缓存、短链和保存订阅。
- 解析结果缓存有效期为 24 小时。
- 短链有效期为 30 天。
- 短链公开访问，任何拿到短链的人都可以读取对应内容。
- 短链返回原始订阅文本，不会重定向到上游订阅地址。
- 保存订阅按 Telegram 用户 ID 隔离，不同用户不能通过自己的用户 ID 读取其他用户的保存记录。
- 当前保存订阅没有设置自动过期时间。
- 短链属于 bearer link，请勿将包含敏感订阅凭据的短链公开传播。

部署前必须知道

1. 这是第一版可部署基础实现，不是对所有机场私有面板格式的万能识别器。
2. 流量、已用流量、剩余流量和到期时间，只有订阅服务器返回可识别的 "Subscription-Userinfo" 等标准响应头时才能读取；否则显示未知。只有内容明确表示长期有效时才显示长期有效。
3. TXT/YAML 文件通过 Telegram "getFile" 下载，默认限制 1 MiB；订阅 URL 下载同样默认限制 1 MiB。
4. URL 抓取仅允许 HTTPS，拒绝本机/内网常见主机名、IP 字面量和非默认 HTTPS 端口，并禁止自动跟随重定向。遇到重定向时会提示用户使用最终 HTTPS 地址。
5. 当前 URL 安全检查不能完全消除 DNS rebinding 等 SSRF 风险。生产环境建议进一步增加出站域名白名单或可信代理层。
6. YAML 导出为通用 Clash/Mihomo 基础格式，不保证覆盖所有客户端私有字段及复杂协议参数。
7. "SHORT_BASE_URL" 必须设置为 Worker 可公开访问的 HTTPS 地址。
8. 不要将 "BOT_TOKEN"、"WEBHOOK_SECRET" 或包含账号凭据的订阅 URL 提交到 GitHub。

GitHub + Cloudflare 部署（手机可操作）

1. 创建 GitHub 仓库

将项目 ZIP 解压，把全部文件上传到一个新的 GitHub 仓库根目录。

根目录应包含：

- "index.js"
- "telegram.js"
- "parser.js"
- "input.js"
- "short.js"
- "usage.js"
- "usage-client.js"
- "package.json"
- "wrangler.jsonc"
- ".dev.vars.example"
- "README.md"

不要把文件放进额外的 "src" 子目录。

2. 导入 Cloudflare Workers

1. 登录 Cloudflare。
2. 进入 Workers & Pages。
3. 选择 Create → Import a repository。
4. 选择刚创建的 GitHub 仓库。
5. 使用仓库根目录中的 "wrangler.jsonc" 作为项目配置。

项目使用 Wrangler 配置文件管理部署，不需要单独设置 Build command。

部署命令：

npx wrangler deploy

3. 配置 Telegram 密钥

进入 Worker → Settings → Variables and Secrets，添加：

变量名| 类型| 内容
"BOT_TOKEN"| Secret| Telegram BotFather 提供的 Bot Token
"WEBHOOK_SECRET"| Secret| 自行生成的随机长字符串

这两个变量必须作为 Secret 保存，不要放进公开的 "vars" 配置或 GitHub 仓库。

4. 创建 KV Namespace

在 Cloudflare Workers & Pages → KV 中创建 Namespace。

建议名称：

BOT_KV

复制创建后的 Namespace ID，填写到 "wrangler.jsonc"：

"kv_namespaces": [
  {
    "binding": "BOT_KV",
    "id": "替换成Cloudflare实际KV_ID"
  }
]

注意：这里填写的是 Namespace ID，不是 Namespace 名称。

5. 配置 Durable Objects

项目使用 Durable Objects SQLite 保存操作限次状态。

"wrangler.jsonc" 中应保留：

"durable_objects": {
  "bindings": [
    {
      "name": "USAGE_GUARD",
      "class_name": "UsageGuard"
    }
  ]
},
"migrations": [
  {
    "tag": "v1",
    "new_sqlite_classes": ["UsageGuard"]
  }
]

首次部署时由 Wrangler 根据 migration 创建 Durable Object。

不要在已经部署后随意修改或重复使用已有 migration tag。后续数据库迁移应使用新的 tag。

6. 设置短链域名

在 "wrangler.jsonc" 中设置：

"vars": {
  "MAX_INPUT_BYTES": "1048576",
  "MAX_NODES": "1000",
  "SHORT_BASE_URL": "https://你的worker域名"
}

"SHORT_BASE_URL" 必须填写实际可公开访问的 HTTPS Worker 地址。

修改后重新部署：

npx wrangler deploy

7. 设置 Telegram Webhook

当前 Worker 使用的 Webhook 设置接口是：

POST /set-webhook

不是 "/setup-webhook"。

在 Termux 中执行：

curl -X POST "https://你的worker域名/set-webhook?key=你的WEBHOOK_SECRET"

成功后，Worker 会调用 Telegram Bot API 设置 Webhook，监听：

- "message"
- "callback_query"

也可以直接调用 Telegram 官方接口设置：

https://api.telegram.org/bot你的BOT_TOKEN/setWebhook?url=https://你的worker域名/webhook&secret_token=你的WEBHOOK_SECRET&allowed_updates=%5B%22message%22%2C%22callback_query%22%5D

注意：上面的 URL 仅作为接口格式示例。实际使用时替换全部占位内容，不要公开包含真实 Token 或 Secret 的链接。

8. 配置 Telegram 群组

1. 打开 Telegram BotFather。
2. 进入 Bot Settings。
3. 选择 Group Privacy。
4. 关闭 Group Privacy（Turn off）。
5. 将 Bot 添加到目标群组。
6. 建议授予 Bot 管理员权限，以保证 "getChatMember" 能可靠检查用户身份。

群组普通成员可以发送订阅内容触发解析，但只有管理员可以点击结果按钮。

私聊不受群组管理员权限限制。

9. 部署测试

部署完成后，建议按以下顺序测试：

1. 访问 "https://你的worker域名/health"，检查 Worker 是否正常运行。
2. 私聊 Bot，发送一条 VLESS 节点链接。
3. 私聊 Bot，发送一条 HTTPS 订阅 URL。
4. 上传 TXT 文件，测试文件解析。
5. 上传 Clash/Mihomo YAML 文件，测试 YAML 解析。
6. 检查协议数量、节点总数、地区数量、重复节点数量和唯一节点数量。
7. 测试展开/折叠节点。
8. 测试 Base64 和 YAML 导出。
9. 测试短链访问及 30 天有效期配置。
10. 测试保存订阅和不同用户之间的数据隔离。
11. 在群组中测试普通成员触发解析、管理员操作按钮。
12. 测试同一用户重复点击功能按钮时的限次效果。

全部测试通过后，再公开使用。

注意事项

- 不要把 "BOT_TOKEN"、"WEBHOOK_SECRET" 提交到 GitHub。
- 不要公开包含账号凭据的订阅 URL。
- 短链是公开访问的，任何获得短链的人都可以读取内容。
- 不要将 "wrangler.jsonc" 中的 KV Namespace ID 替换成 Namespace 名称。
- 修改代码后需要重新部署，才能让线上 Worker 使用新版本。
- 当前版本是基础实现，实际运行情况仍需通过 Cloudflare 部署后的测试确认。
