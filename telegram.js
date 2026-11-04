import { parseInput, renderResult, exportBase64, exportYaml } from "./parser.js";
import { fetchSubscription, extractMessageInput } from "./input.js";
import { claimUsage, finishUsage } from "./usage-client.js";
import { makeShort, saveSubscription } from "./short.js";

export async function telegram(env, method, body = {}) {
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body)
  });
  const data = await r.json();
  if (!data.ok) throw new Error(`Telegram ${method}: ${data.description || "unknown error"}`);
  return data.result;
}

async function reply(env, chatId, text, extra = {}) {
  return telegram(env, "sendMessage", {
    chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true, ...extra
  });
}

async function isAdmin(env, chatId, userId) {
  const m = await telegram(env, "getChatMember", { chat_id: chatId, user_id: userId });
  return ["creator", "administrator"].includes(m.status);
}

function callbackKeyboard(key) {
  return { inline_keyboard: [
    [{ text: "🔄 刷新订阅信息", callback_data: `act|refresh|${key}` }],
    [{ text: "📄 显示全部节点", callback_data: `act|all|${key}` }],
    [{ text: "📤 导出 Base64", callback_data: `act|base64|${key}` },
     { text: "📤 导出 YAML", callback_data: `act|yaml|${key}` }],
    [{ text: "🔗 生成短链", callback_data: `act|short|${key}` },
     { text: "💾 保存订阅", callback_data: `act|save|${key}` }]
  ] };
}

async function loadAndParse(message, env) {
  const input = await extractMessageInput(message, env);
  let source = input.text;
  let headers = {};
  if (input.url) {
    const got = await fetchSubscription(input.url, env);
    source = got.text;
    headers = got.headers;
  }
  const parsed = parseInput(source, Number(env.MAX_NODES || 500));
  parsed.sourceUrl = input.url || null;
  parsed.headers = headers;
  parsed.raw = source;
  return parsed;
}

export async function handleTelegramUpdate(update, env) {
  if (update.callback_query) return handleCallback(update.callback_query, env);
  const m = update.message;
  if (!m || !m.chat || !m.from || m.from.is_bot) return;

  const chatId = m.chat.id;
  try {
    const parsed = await loadAndParse(m, env);
    if (!parsed.nodes.length) {
      await reply(env, chatId, "没有识别到支持的节点。请发送订阅链接、节点 URI、TXT 或 Clash YAML。");
      return;
    }
    const key = await storeParsed(parsed, env);
    const text = renderResult(parsed);
    await reply(env, chatId, text, { reply_markup: callbackKeyboard(key) });
  } catch (e) {
    console.error("parse error", e?.stack || e);
    await reply(env, chatId, `解析失败：${escapeHtml(e.message || "未知错误")}`);
  }
}

async function storeParsed(parsed, env) {
  const key = crypto.randomUUID().replaceAll("-", "").slice(0, 20);
  const payload = {
    raw: parsed.raw, sourceUrl: parsed.sourceUrl, nodes: parsed.nodes,
    headers: parsed.headers || {}, createdAt: Date.now()
  };
  await env.BOT_KV.put(`result:${key}`, JSON.stringify(payload), { expirationTtl: 86400 });
  return key;
}

async function handleCallback(q, env) {
  const [prefix, action, key] = String(q.data || "").split("|");
  if (prefix !== "act" || !["refresh","all","base64","yaml","short","save"].includes(action)) return;
  const chatId = q.message.chat.id;
  const userId = q.from.id;
  const chatType = q.message.chat.type;
  try {
    if (chatType !== "private" && !(await isAdmin(env, chatId, userId))) {
      await telegram(env, "answerCallbackQuery", { callback_query_id: q.id, text: "只有群组管理员可以使用此功能。", show_alert: true });
      return;
    }
    const saved = await env.BOT_KV.get(`result:${key}`);
    if (!saved) throw new Error("这份解析结果已过期，请重新发送订阅。");
    const data = JSON.parse(saved);
    const fingerprint = await sha256(data.sourceUrl || data.raw);
    const usageKey = `${userId}:${fingerprint}`;
    const claim = await claimUsage(env, usageKey, action);
    if (!claim.ok) {
      await telegram(env, "answerCallbackQuery", { callback_query_id: q.id, text: "此用户对此订阅的该功能已经使用过一次。", show_alert: true });
      return;
    }
    try {
      let message = "";
      if (action === "refresh") {
        if (!data.sourceUrl) throw new Error("这不是订阅 URL，无法刷新。");
        const fresh = await fetchSubscription(data.sourceUrl, env);
        const parsed = parseInput(fresh.text, Number(env.MAX_NODES || 500));
        if (!parsed.nodes.length) throw new Error("刷新后没有识别到节点。");
        message = renderResult({ ...parsed, headers: fresh.headers });
      } else if (action === "all") {
        message = data.nodes.map((n,i) => `${i+1}. ${escapeHtml(n.name)}\n${escapeHtml(n.uri)}`).join("\n\n");
      } else if (action === "base64") {
        message = exportBase64(data.nodes);
      } else if (action === "yaml") {
        message = exportYaml(data.nodes);
      } else if (action === "short") {
        if (!data.sourceUrl) throw new Error("只有订阅 URL 才能生成短链。");
        const short = await makeShort(env, userId, data.raw);
        message = `短链：${escapeHtml(short)}`;
      } else if (action === "save") {
        await saveSubscription(env, userId, data.sourceUrl || data.raw);
        message = "订阅已保存到你的个人记录。";
      }
      await deliver(env, chatId, message, action);
      await finishUsage(env, usageKey, action, true);
      await telegram(env, "answerCallbackQuery", { callback_query_id: q.id, text: "操作成功。" });
    } catch (e) {
      await finishUsage(env, usageKey, action, false);
      throw e;
    }
  } catch (e) {
    await telegram(env, "answerCallbackQuery", { callback_query_id: q.id, text: e.message || "操作失败", show_alert: true });
  }
}

async function deliver(env, chatId, text, action) {
  if (action === "base64" || action === "yaml" || action === "all") {
    const filename = action === "base64" ? "nodes_base64.txt" : action === "yaml" ? "config.yaml" : "all_nodes.txt";
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const form = new FormData();
    form.set("chat_id", String(chatId));
    form.set("document", blob, filename);
    const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`, { method: "POST", body: form });
    const j = await r.json();
    if (!j.ok) throw new Error(j.description || "发送文件失败");
  } else {
    await reply(env, chatId, text);
  }
}
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));
}
async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
