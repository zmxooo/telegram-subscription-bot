const MAX = 1024 * 1024;

export async function extractMessageInput(message, env) {
  if (message.text) {
    const text = message.text.trim();
    const url = text.match(/^https:\/\/[^\s]+$/i)?.[0];
    return { text, url: url || null };
  }
  const doc = message.document;
  if (doc) {
    if (doc.file_size && doc.file_size > MAX) throw new Error("文件超过 1 MiB 限制。");
    const meta = await tg(env, "getFile", { file_id: doc.file_id });
    const r = await fetch(`https://api.telegram.org/file/bot${env.BOT_TOKEN}/${meta.file_path}`);
    if (!r.ok) throw new Error("无法下载 Telegram 文件。");
    const buf = await r.arrayBuffer();
    if (buf.byteLength > MAX) throw new Error("文件超过 1 MiB 限制。");
    return { text: new TextDecoder().decode(buf), url: null };
  }
  throw new Error("请发送文字、订阅链接或 TXT/YAML 文件。");
}
async function tg(env, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify(body)
  });
  const j=await r.json(); if(!j.ok) throw new Error(j.description); return j.result;
}

export async function fetchSubscription(input, env) {
  let u;
  try { u = new URL(input); } catch { throw new Error("订阅 URL 格式不正确。"); }
  if (u.protocol !== "https:") throw new Error("仅允许 HTTPS 订阅地址。");
  if (u.username || u.password) throw new Error("URL 不允许包含用户名或密码。");
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
      host === "metadata.google.internal" || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
      host.includes(":") || host === "0.0.0.0") throw new Error("不允许访问 IP 地址或本地域名。");
  const port = u.port || "443";
  if (port !== "443") throw new Error("订阅地址仅允许 HTTPS 默认端口 443。");
  const r = await fetch(u.toString(), { redirect: "manual", headers: { "user-agent": "SubscriptionParserBot/1.0", "accept": "*/*" } });
  if (r.status >= 300 && r.status < 400) throw new Error("订阅服务器发生重定向，请使用最终 HTTPS 地址。");
  if (!r.ok) throw new Error(`订阅服务器返回 HTTP ${r.status}。`);
  const len = Number(r.headers.get("content-length") || 0);
  if (len > MAX) throw new Error("订阅内容超过 1 MiB 限制。");
  const buf = await r.arrayBuffer();
  if (buf.byteLength > MAX) throw new Error("订阅内容超过 1 MiB 限制。");
  const text = new TextDecoder().decode(buf);
  return { text, headers: {
    userinfo: r.headers.get("subscription-userinfo") || r.headers.get("Subscription-Userinfo") || null,
    contentType: r.headers.get("content-type") || null
  }};
}
