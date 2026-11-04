# Telegram 订阅查询 Bot

## 当前版本功能
- Telegram 群组/私聊自动接收文本、节点 URI、订阅 URL、TXT、YAML 文件。
- 解析 VLESS、VMess、Shadowsocks、Trojan、Hysteria2、AnyTLS、TUIC 常见 URI。
- 解析 Base64 订阅文本及 Clash/Mihomo YAML 的 proxies。
- 统计协议、节点数量、地区标签；按协议+服务器+端口+用户凭据去重。
- 六个按钮：刷新、显示全部、导出 Base64、导出 YAML、短链、保存订阅。
- 群组六个按钮仅管理员可用；私聊可用。
- 每个 Telegram 用户 + 规范化订阅/输入指纹，六项操作分别成功一次。Durable Object SQLite 原子领取，失败释放。
- KV 保存短链和订阅保存记录。

## 部署前必须知道
1. 这是第一版可部署基础实现，不是对所有机场私有面板格式的万能识别器。
2. 流量/到期信息只有订阅响应头包含 `subscription-userinfo` 等标准字段时才能读取；否则显示未知。
3. TXT 文件由 Telegram getFile 下载，限制 1 MiB；订阅下载也限制 1 MiB。
4. URL 抓取仅允许 HTTPS，拒绝本机/内网常见主机名、IP 字面量和危险端口，并禁止自动跟随重定向；若遇重定向会提示用户使用最终 HTTPS 地址。生产环境仍建议增加出站域名白名单或可信代理层，以进一步降低 DNS rebinding 风险。
5. YAML 导出是通用 Clash/Mihomo 基础格式；不保证覆盖所有客户端私有字段。
6. `SHORT_BASE_URL` 必须设置为 Worker 可公开访问的 HTTPS 域名。
7. 私聊的短链/保存记录按用户隔离；短链返回本次解析缓存的原始订阅文本，不会重定向暴露原始 URL；短链是随机不可猜测的 bearer link，拿到链接的人可访问内容。

## GitHub + Cloudflare 部署（手机可操作）
1. 把整个 ZIP 解压后，将里面的文件上传到一个新的 GitHub 仓库根目录。
2. Cloudflare Workers & Pages → Create → Import a repository，选择该仓库。
3. 项目根目录使用 `wrangler.jsonc`。无需配置 Build command；部署命令使用 `npx wrangler deploy`。
4. 在 Cloudflare Worker Settings → Variables and Secrets 添加：
   - `BOT_TOKEN`：Telegram BotFather 发的 Token（Secret）
   - `WEBHOOK_SECRET`：自行生成的随机长字符串（Secret）
5. 创建 KV Namespace，名称建议 `BOT_KV`，把其 Namespace ID 填入 `wrangler.jsonc` 的 `id`。
6. 首次部署。若 Cloudflare 控制台不能自动创建 DO，请在 Worker 的 Settings → Bindings 添加 Durable Object binding：名称 `USAGE_GUARD`，类 `UsageGuard`，并按 Wrangler migration 完成首次创建。建议始终由仓库配置管理 DO。
7. 设置 `SHORT_BASE_URL` 为部署后的 Worker 地址，然后重新部署。
8. 访问 `https://你的worker域名/setup-webhook?key=WEBHOOK_SECRET` 不可用：请使用下方 curl 命令在 Termux/Cloudflare 控制台外执行，或用浏览器地址栏访问：
   `https://api.telegram.org/bot你的BOT_TOKEN/setWebhook?url=https://你的worker域名/webhook&secret_token=你的WEBHOOK_SECRET&allowed_updates=%5B%22message%22%2C%22callback_query%22%5D`
9. BotFather → Bot Settings → Group Privacy → Turn off；把 Bot 加入群组并授予读取消息权限。管理员按钮由 Telegram `getChatMember` 实时验证。
10. 群组发一条 VLESS 链接和私聊发一条测试订阅，确认正常后再公开使用。

## 注意
不要把 BOT_TOKEN、WEBHOOK_SECRET 或含账号凭据的订阅 URL 提交到 GitHub。所有密钥只放 Cloudflare Secrets。
