Telegram 订阅查询 Bot

一个基于 Cloudflare Workers 和 Telegram Bot API 的订阅解析机器人。

支持在 Telegram 私聊和群组中自动解析节点链接、订阅 URL、Base64 订阅文本、TXT 文件及 Clash/Mihomo YAML 文件，并提供节点统计、格式导出、短链生成和订阅保存功能。

---

一、当前版本功能

1. 输入方式

支持 Telegram 私聊和群组自动接收：

- 普通文本
- 单条节点 URI
- HTTPS 订阅 URL
- Base64 订阅文本
- TXT 文件
- YAML 文件

不需要用户发送特定命令，直接发送内容即可触发解析。

2. 支持协议

- VLESS
- VMess
- Shadowsocks（SS）
- Trojan
- Hysteria
- Hysteria2（HY2）
- AnyTLS
- TUIC
- HTTP
- SOCKS5

支持普通节点 URI、Base64 订阅文本，以及 Clash/Mihomo YAML 中的 "proxies" 节点列表。

3. 节点统计

自动统计：

- 支持的协议类型
- 节点总数
- 国家/地区数量
- 重复节点数量
- 实际唯一节点数量

重复节点处理规则：

- 保留所有解析成功的节点。
- 不删除重复节点。
- 不合并重复节点。
- 只统计并显示重复数量。

节点名称处理规则：

完整保留原始节点名称，不翻译、不改写、不主动清理乱码。

地区识别规则：

根据节点备注中的国家/地区名称识别，不进行 GeoIP 查询。

无法识别时显示：

"🌐未知"

4. 订阅流量信息

尽可能读取订阅服务器响应头中的流量和到期信息。

优先识别：

"Subscription-Userinfo"

无法读取时显示未知。

只有订阅内容明确表示长期有效时，才显示长期有效，不根据缺失的到期时间推断长期有效。

5. 六个操作按钮

解析成功后提供以下按钮：

1. 刷新订阅信息
2. 展开/折叠节点
3. 导出 Base64
4. 导出 YAML
5. 生成短链
6. 保存订阅

6. 节点展开与折叠

默认显示前 20 个节点。

点击折叠按钮后，只显示前 2 个节点。

再次点击后恢复显示前 20 个节点。

通过编辑原 Telegram 消息完成展开和折叠，不额外发送消息。

当节点数量超过 20 个时，显示剩余未展示节点数量。

展开和折叠操作不消耗使用次数。

7. 群组权限

群组和私聊使用不同权限规则。

群组：

- Bot 必须具有当前群组管理员身份。
- 群组普通成员可以发送订阅内容触发解析。
- 只有群组管理员可以使用解析结果上的六个按钮。
- Bot 必须通过 Telegram "getChatMember" 实时验证自身管理员身份。
- 点击按钮时，也必须验证 Bot 自身和点击用户的管理员身份。
- 如果 Bot 被取消管理员身份，群组解析和按钮操作均应停止。
- 恢复 Bot 管理员身份后，群组功能恢复。

仅关闭 Group Privacy 不足以满足本项目要求。

私聊：

- 所有用户均可正常使用。
- 不需要管理员权限。

---

二、操作限次规则

以下五项操作分别计算使用次数：

1. 刷新订阅信息
2. 导出 Base64
3. 导出 YAML
4. 生成短链
5. 保存订阅

限次规则：

- 同一个 Telegram 用户、同一个输入指纹，每项操作成功一次。
- 不同 Telegram 用户分别计算使用次数。
- 不同订阅 URL 或输入内容分别计算使用次数。
- 五项操作分别计算，不互相占用额度。
- 操作失败不消耗次数，可以重新尝试。
- 使用 Durable Objects SQLite 进行原子领取，防止并发请求突破限次。
- 节点展开和折叠不计入限次。

限次状态由 Durable Objects SQLite 管理，不使用 KV 作为并发锁。

---

三、短链与订阅保存

项目使用 Cloudflare KV 保存以下数据：

数据| 有效期
解析结果缓存| 24 小时
生成的短链| 30 天
保存的订阅| 不设置自动过期时间

1. 短链

- 短链公开访问。
- 任何获得短链的人都可以读取对应内容。
- 短链返回原始订阅文本。
- 不会重定向到上游订阅地址。
- 短链有效期为 30 天。

短链属于 Bearer Link。任何持有短链的人都可以访问内容，请勿公开传播包含敏感订阅凭据的短链。

2. 保存订阅

- 保存订阅按 Telegram 用户 ID 隔离。
- 不同用户不能通过自己的用户 ID 读取其他用户的保存记录。
- 当前版本不设置保存订阅自动过期时间。

---

四、部署前必须了解

1. 本项目是第一版可部署基础实现，不是对所有机场私有面板格式的万能识别器。

2. 流量、已用流量、剩余流量和到期时间，只有订阅服务器返回可识别的 "Subscription-Userinfo" 等标准响应头时才能读取，否则显示未知。

3. 只有内容明确表示长期有效时才显示长期有效，不会因为缺少到期信息就自动判断为长期有效。

4. TXT/YAML 文件通过 Telegram "getFile" 下载，默认限制为 1 MiB。

5. 订阅 URL 下载默认限制为 1 MiB。

6. URL 抓取仅允许 HTTPS，拒绝本机、常见内网主机名、IP 字面量和非默认 HTTPS 端口，并禁止自动跟随重定向。遇到重定向时，提示用户使用最终 HTTPS 地址。

7. 当前 URL 安全检查不能完全消除 DNS rebinding 等 SSRF 风险。生产环境建议进一步增加出站域名白名单或可信代理层。

8. YAML 导出为通用 Clash/Mihomo 基础格式，不保证覆盖所有客户端私有字段及复杂协议参数。

9. "SHORT_BASE_URL" 必须设置为 Worker 可公开访问的 HTTPS 地址。

10. 不要将 "BOT_TOKEN"、"WEBHOOK_SECRET" 或包含账号凭据的订阅 URL 提交到 GitHub。

11. 群组必须将 Bot 设置为管理员，仅关闭 Group Privacy 不足以满足项目要求。

12. 群组功能还需要检查 Bot 自身的管理员身份，以及点击按钮的用户是否为群组管理员。

---

五、GitHub + Cloudflare 部署

以下步骤适合手机操作。

第一步：创建 GitHub 仓库

将项目 ZIP 解压，把全部文件上传到一个新的 GitHub 仓库根目录。

根目录应包含：

index.js
telegram.js
parser.js
input.js
short.js
usage.js
usage-client.js
package.json
wrangler.jsonc
.dev.vars.example
README.md

不要把文件放进额外的 "src" 子目录。

".dev.vars.example" 只保存示例变量，不保存真实密钥。

第二步：导入 Cloudflare Workers

1. 登录 Cloudflare。
2. 进入 Workers & Pages。
3. 选择 Create。
4. 选择 Import a repository。
5. 连接 GitHub。
6. 选择刚刚创建的项目仓库。
7. 确认项目根目录包含 "wrangler.jsonc"。
8. 使用仓库中的 Wrangler 配置进行部署。

项目使用 Wrangler 配置文件管理部署。

部署命令：

npx wrangler deploy

注意：首次部署前必须完成 KV Namespace ID、Worker 环境变量及 Durable Objects 配置。

第三步：配置 Telegram 密钥

进入：

Cloudflare → Workers & Pages → 选择项目 → Settings → Variables and Secrets。

添加以下两个 Secret：

变量名| 类型| 内容
"BOT_TOKEN"| Secret| Telegram BotFather 提供的 Bot Token
"WEBHOOK_SECRET"| Secret| 自行生成的随机长字符串

这两个变量必须作为 Secret 保存。

不要放进公开的 "vars" 配置，也不要提交到 GitHub。

第四步：创建 KV Namespace

进入 Cloudflare：

Workers & Pages → KV。

创建一个 Namespace。

建议名称：

"BOT_KV"

创建完成后，复制实际的 Namespace ID。

在 "wrangler.jsonc" 中填写：

"kv_namespaces": [
  {
    "binding": "BOT_KV",
    "id": "替换成Cloudflare实际KV_ID"
  }
]

注意：

- "binding" 必须是 "BOT_KV"。
- "id" 必须填写真实 Namespace ID。
- 不要填写 Namespace 名称代替 ID。

第五步：配置 Durable Objects

项目使用 Durable Objects SQLite 管理操作限次。

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
    "new_sqlite_classes": [
      "UsageGuard"
    ]
  }
]

注意：

- "USAGE_GUARD" 必须与代码中的绑定名称一致。
- "UsageGuard" 必须与 "usage.js" 导出的类名一致。
- 首次部署时由 Wrangler 根据 migration 创建 Durable Object。
- 不要在已经部署后随意修改或重复使用已有 migration tag。
- 后续数据库迁移必须使用新的 tag，并根据迁移内容配置。

第六步：设置短链域名和其他变量

在 "wrangler.jsonc" 中设置：

"vars": {
  "MAX_INPUT_BYTES": "1048576",
  "MAX_NODES": "1000",
  "SHORT_BASE_URL": "https://你的worker域名"
}

其中：

变量| 说明
"MAX_INPUT_BYTES"| 最大输入字节数，默认 1 MiB
"MAX_NODES"| 最大解析节点数量，默认 1000
"SHORT_BASE_URL"| 短链使用的公开 HTTPS 地址

"SHORT_BASE_URL" 必须填写实际可以公开访问的 Worker HTTPS 地址。

修改配置后重新部署：

npx wrangler deploy

第七步：设置 Telegram Webhook

当前 Worker 使用的 Webhook 设置接口：

"POST /set-webhook"

不是 "/setup-webhook"。

使用请求头验证密钥，不使用 URL 参数 "?key="。

在 Termux 中执行：

curl -X POST "https://你的worker域名/set-webhook" \
  -H "X-Setup-Secret: 你的WEBHOOK_SECRET"

成功后，Worker 会调用 Telegram Bot API 设置 Webhook。

监听：

- "message"
- "callback_query"

设置完成后，可以检查 Webhook 状态：

https://api.telegram.org/bot你的BOT_TOKEN/getWebhookInfo

注意：

- 替换为实际 Worker 域名。
- "WEBHOOK_SECRET" 必须与 Cloudflare Secrets 中设置的值一致。
- 不要公开真实 Bot Token 或 Secret。
- 不要将包含真实 Token 的 API 链接提交到 GitHub。

第八步：配置 Telegram 群组

1. 关闭 Group Privacy

打开 Telegram BotFather：

1. 进入 Bot Settings。
2. 选择 Group Privacy。
3. 关闭 Group Privacy（Turn off）。

这允许 Bot 接收群组普通消息。

2. 将 Bot 设置为群组管理员

1. 将 Bot 添加到目标群组。
2. 将 Bot 设置为群组管理员。
3. 授予必要的读取消息和编辑消息权限。

群组必须满足以下规则：

- Bot 必须是当前群组的管理员。
- 群组普通成员可以发送订阅链接、节点 URI 或文件触发解析。
- 只有群组管理员可以点击解析结果上的六个按钮。
- 私聊用户不需要管理员权限。
- Bot 被取消管理员身份后，群组功能停止。
- 恢复 Bot 管理员身份后，群组功能恢复。

---

六、部署后测试

部署完成后，建议按照以下顺序逐项测试。

1. Worker 基础检查

访问：

https://你的worker域名/health

确认 Worker 正常运行。

2. 私聊功能测试

- 发送一条 VLESS 节点链接。
- 发送一条 HTTPS 订阅 URL。
- 上传 TXT 文件。
- 上传 Clash/Mihomo YAML 文件。
- 发送 Base64 订阅文本。
- 测试多协议节点解析。

3. 节点统计测试

检查：

- 协议数量。
- 节点总数。
- 国家/地区数量。
- 重复节点数量。
- 实际唯一节点数量。
- 原始节点名称是否完整保留。
- 未识别地区是否显示 "🌐未知"。

4. 按钮测试

逐项测试：

1. 刷新订阅信息。
2. 展开节点。
3. 折叠节点。
4. 导出 Base64。
5. 导出 YAML。
6. 生成短链。
7. 保存订阅。

检查节点展开和折叠是否通过编辑原消息完成。

5. 短链和保存测试

- 测试短链是否可以公开访问。
- 检查短链返回的是原始订阅文本，而不是重定向。
- 检查短链有效期配置。
- 测试保存订阅。
- 使用不同 Telegram 用户测试数据隔离。

6. 群组权限测试

1. 将 Bot 设置为群组管理员。
2. 测试群组普通成员发送订阅内容能否触发解析。
3. 测试群组管理员能否使用六个按钮。
4. 测试群组普通成员点击按钮是否被拒绝。
5. 移除 Bot 的管理员身份，确认群组解析和按钮操作被禁止。
6. 恢复 Bot 管理员身份，确认群组功能恢复。

7. 操作限次测试

- 同一个用户重复使用同一订阅的同一个功能。
- 同一个用户使用不同订阅。
- 不同用户使用相同订阅。
- 分别测试五项操作。
- 测试操作失败后是否可以重试。
- 测试同时点击同一按钮时是否会突破限次。

全部测试通过后，再公开使用。

---

七、安全注意事项

1. 不要将 "BOT_TOKEN"、"WEBHOOK_SECRET" 提交到 GitHub。
2. 不要公开包含账号凭据的订阅 URL。
3. 短链是公开访问的，任何获得短链的人都可以读取对应内容。
4. 不要将 "wrangler.jsonc" 中的 KV Namespace ID 替换成 Namespace 名称。
5. 不要随意修改已经部署的 Durable Objects migration tag。
6. 修改代码后需要重新部署，线上 Worker 才会使用新版本。
7. 订阅 URL 抓取仍存在 DNS rebinding 等 SSRF 风险。
8. 不要把静态代码检查当成实际部署测试结果。
9. 当前版本属于基础实现，实际运行情况必须通过 Cloudflare 和 Telegram 的完整测试确认。

---

项目说明

本项目采用 Cloudflare Workers 运行，不需要自行购买或维护 VPS。

主要组件：

- Telegram Bot API：接收消息和发送解析结果。
- Cloudflare Workers：运行机器人逻辑。
- Cloudflare KV：缓存、短链和订阅保存。
- Cloudflare Durable Objects SQLite：操作限次和并发控制。

项目目标是提供简单、直接的订阅解析与转换功能，不包含会员、积分、付费、登录等系统。
