
import {
  parseInput,
  renderResult,
  exportBase64,
  exportYaml
} from "./parser.js";

import {
  fetchSubscription,
  extractMessageInput
} from "./input.js";

import {
  claimUsage,
  finishUsage
} from "./usage-client.js";

import {
  makeShort,
  saveSubscription
} from "./short.js";

// ================================
// 基础配置
// ================================

function getMaxNodes(env) {
  const value = Number(env.MAX_NODES || 1000);

  if (!Number.isFinite(value) || value < 1) {
    return 1000;
  }

  return Math.min(Math.floor(value), 1000);
}

// ================================
// Telegram API
// ================================

export async function telegram(env, method, body = {}) {
  const r = await fetch(
    `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    }
  );

  let data;

  try {
    data = await r.json();
  } catch {
    throw new Error(`Telegram ${method}: 返回数据异常`);
  }

  if (!r.ok || !data.ok) {
    throw new Error(
      `Telegram ${method}: ${data?.description || "unknown error"}`
    );
  }

  return data.result;
}

// ================================
// 获取 Bot 自身 ID
// 同一个 Worker 实例内缓存
// ================================

let cachedBotId = null;

async function getBotId(env) {
  if (cachedBotId !== null) {
    return cachedBotId;
  }

  const me = await telegram(env, "getMe");

  if (!me || !me.id || !me.is_bot) {
    throw new Error("无法获取 Bot 身份信息。");
  }

  cachedBotId = me.id;

  return cachedBotId;
}

// ================================
// 检查 Bot 自身是否为群组管理员
// ================================

async function isBotAdmin(env, chatId) {
  const botId = await getBotId(env);

  const member = await telegram(env, "getChatMember", {
    chat_id: chatId,
    user_id: botId
  });

  return [
    "creator",
    "administrator"
  ].includes(member.status);
}

// ================================
// 检查点击按钮的用户是否为管理员
// ================================

async function isAdmin(env, chatId, userId) {
  const member = await telegram(env, "getChatMember", {
    chat_id: chatId,
    user_id: userId
  });

  return [
    "creator",
    "administrator"
  ].includes(member.status);
}

// ================================
// 消息发送
// ================================

async function reply(env, chatId, text, extra = {}) {
  return telegram(env, "sendMessage", {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    ...extra
  });
}

// ================================
// 原消息编辑
// ================================

async function editMessage(
  env,
  chatId,
  messageId,
  text,
  key,
  expanded
) {
  return telegram(env, "editMessageText", {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    reply_markup: callbackKeyboard(key, expanded)
  });
}

// ================================
// 回调提示
// ================================

async function answerCallback(
  env,
  callbackId,
  text = "",
  showAlert = false
) {
  try {
    await telegram(env, "answerCallbackQuery", {
      callback_query_id: callbackId,
      text: text || undefined,
      show_alert: showAlert
    });
  } catch (e) {
    console.error(
      "answerCallbackQuery error:",
      e?.message || e
    );
  }
}

// ================================
// 六项操作按钮
// expanded=true：显示20个
// expanded=false：显示2个
// ================================

function callbackKeyboard(key, expanded = true) {
  return {
    inline_keyboard: [
      [
        {
          text: "🔄 刷新订阅信息",
          callback_data: `act|refresh|${key}`
        }
      ],
      [
        {
          text: expanded
            ? "🔼 折叠全部节点"
            : "📄 显示全部节点",
          callback_data: `act|toggle|${key}|${expanded ? "0" : "1"}`
        }
      ],
      [
        {
          text: "📤 导出 Base64",
          callback_data: `act|base64|${key}`
        },
        {
          text: "📤 导出 YAML",
          callback_data: `act|yaml|${key}`
        }
      ],
      [
        {
          text: "🔗 生成短链",
          callback_data: `act|short|${key}`
        },
        {
          text: "💾 保存订阅",
          callback_data: `act|save|${key}`
        }
      ]
    ]
  };
}

// ================================
// 解析输入
// ================================

async function loadAndParse(message, env) {
  const input = await extractMessageInput(message, env);

  let source = input.text;
  let headers = {};

  if (input.url) {
    const got = await fetchSubscription(input.url, env);

    source = got.text;
    headers = got.headers || {};
  }

  const parsed = parseInput(
    source,
    getMaxNodes(env)
  );

  parsed.sourceUrl = input.url || null;
  parsed.headers = headers;
  parsed.raw = source;

  return parsed;
}

// ================================
// 接收 Telegram 更新
// ================================

export async function handleTelegramUpdate(update, env) {
  if (update.callback_query) {
    return handleCallback(update.callback_query, env);
  }

  const m = update.message;

  if (!m || !m.chat || !m.from || m.from.is_bot) {
    return;
  }

  const chatId = m.chat.id;
  const chatType = m.chat.type;

  try {
    // ============================
    // 群组 Bot 管理员强制检查
    // 私聊不检查
    // ============================

    if (chatType !== "private") {
      let botAdmin = false;

      try {
        botAdmin = await isBotAdmin(env, chatId);
      } catch (e) {
        console.error(
          "bot admin check error:",
          e?.message || e
        );

        await reply(
          env,
          chatId,
          "无法验证 Bot 的群组管理员身份，请确认 Bot 已加入群组并被设置为管理员。"
        );

        return;
      }

      if (!botAdmin) {
        await reply(
          env,
          chatId,
          "当前群组尚未授予 Bot 管理员权限。\n请先将 Bot 设置为群组管理员，再使用订阅查询功能。"
        );

        return;
      }
    }

    // ============================
    // 开始解析
    // ============================

    const parsed = await loadAndParse(m, env);

    if (!parsed.nodes || !parsed.nodes.length) {
      await reply(
        env,
        chatId,
        "没有识别到支持的节点。请发送订阅链接、节点 URI、TXT 或 Clash YAML。"
      );

      return;
    }

    const key = await storeParsed(parsed, env);

    // 默认展开：显示前20个节点
    const text = renderResult(parsed, 20);

    await reply(env, chatId, text, {
      reply_markup: callbackKeyboard(key, true)
    });

  } catch (e) {
    console.error("parse error:", e?.stack || e);

    await reply(
      env,
      chatId,
      `解析失败：${escapeHtml(e.message || "未知错误")}`
    );
  }
}

// ================================
// 统一缓存解析结果
// ================================

function buildPayload(parsed) {
  return {
    raw: parsed.raw,
    sourceUrl: parsed.sourceUrl || null,
    nodes: parsed.nodes || [],
    headers: parsed.headers || {},

    totalCount: parsed.totalCount ?? parsed.nodes?.length ?? 0,
    parsedCount: parsed.parsedCount ?? parsed.nodes?.length ?? 0,
    truncatedCount: parsed.truncatedCount ?? 0,

    duplicateCount: parsed.duplicateCount ?? 0,
    uniqueCount: parsed.uniqueCount ?? 0,

    protocolCounts: parsed.protocolCounts || {},
    regionCounts: parsed.regionCounts || {},

    createdAt: Date.now()
  };
}

// ================================
// 保存解析结果
// ================================

async function storeParsed(parsed, env) {
  const key = crypto.randomUUID()
    .replaceAll("-", "")
    .slice(0, 20);

  const payload = buildPayload(parsed);

  await env.BOT_KV.put(
    `result:${key}`,
    JSON.stringify(payload),
    {
      expirationTtl: 86400
    }
  );

  return key;
}

// ================================
// 更新解析缓存
// ================================

async function updateParsed(key, parsed, env) {
  const payload = buildPayload(parsed);

  await env.BOT_KV.put(
    `result:${key}`,
    JSON.stringify(payload),
    {
      expirationTtl: 86400
    }
  );
}

// ================================
// 重新解析完整原始内容
// 用于完整导出
// ================================

function parseFullContent(data) {
  if (!data.raw) {
    throw new Error("原始订阅内容不存在，无法导出。");
  }

  const parsed = parseInput(
    data.raw,
    Number.MAX_SAFE_INTEGER
  );

  if (!parsed.nodes || !parsed.nodes.length) {
    throw new Error("没有可导出的节点。");
  }

  return parsed;
}

// ================================
// 展开 / 折叠节点
// 不消耗功能次数
// ================================

async function toggleNodes(q, env, key, state, data) {
  const expanded = state === "1";

  const limit = expanded ? 20 : 2;

  const text = renderResult(data, limit);

  await editMessage(
    env,
    q.message.chat.id,
    q.message.message_id,
    text,
    key,
    expanded
  );

  await answerCallback(env, q.id);
}

// ================================
// Callback 主处理
// ================================

async function handleCallback(q, env) {
  if (!q || !q.message || !q.from || !q.id) {
    return;
  }

  const parts = String(q.data || "").split("|");

  const prefix = parts[0];
  const action = parts[1];
  const key = parts[2];
  const state = parts[3];

  const allowedActions = [
    "refresh",
    "toggle",
    "base64",
    "yaml",
    "short",
    "save"
  ];

  if (
    prefix !== "act" ||
    !allowedActions.includes(action) ||
    !/^[a-f0-9]{20}$/i.test(key || "")
  ) {
    await answerCallback(
      env,
      q.id,
      "无效的操作请求。",
      true
    );

    return;
  }

  const chatId = q.message.chat.id;
  const userId = q.from.id;
  const chatType = q.message.chat.type;

  try {
    // ============================
    // 群组权限检查
    // 第一步：Bot 必须是管理员
    // 第二步：点击者必须是管理员
    // ============================

    if (chatType !== "private") {
      let botAdmin = false;

      try {
        botAdmin = await isBotAdmin(env, chatId);
      } catch (e) {
        console.error(
          "bot admin check error:",
          e?.message || e
        );

        await answerCallback(
          env,
          q.id,
          "无法验证 Bot 管理员身份，请检查 Bot 是否仍为群组管理员。",
          true
        );

        return;
      }

      if (!botAdmin) {
        await answerCallback(
          env,
          q.id,
          "Bot 必须是群组管理员才能使用此功能。",
          true
        );

        return;
      }

      if (!(await isAdmin(env, chatId, userId))) {
        await answerCallback(
          env,
          q.id,
          "只有群组管理员可以使用此功能。",
          true
        );

        return;
      }
    }

    // ============================
    // 读取解析结果
    // ============================

    const saved = await env.BOT_KV.get(
      `result:${key}`
    );

    if (!saved) {
      throw new Error(
        "这份解析结果已过期，请重新发送订阅。"
      );
    }

    const data = JSON.parse(saved);

    // ============================
    // 展开 / 折叠
    // 不消耗次数
    // ============================

    if (action === "toggle") {
      if (state !== "0" && state !== "1") {
        throw new Error("无效的展开状态。");
      }

      await toggleNodes(
        q,
        env,
        key,
        state,
        data
      );

      return;
    }

    // ============================
    // 功能次数控制
    // ============================

    const fingerprint = await sha256(
      data.sourceUrl || data.raw
    );

    const usageKey = `${userId}:${fingerprint}`;

    const claim = await claimUsage(
      env,
      usageKey,
      action
    );

    if (!claim || !claim.ok) {
      await answerCallback(
        env,
        q.id,
        "此用户对此订阅的该功能已经使用过一次。",
        true
      );

      return;
    }

    const token = claim.token;

    try {
      let message = "";

      // ==========================
      // 刷新订阅
      // ==========================

      if (action === "refresh") {
        if (!data.sourceUrl) {
          throw new Error(
            "这不是订阅 URL，无法刷新。"
          );
        }

        const fresh = await fetchSubscription(
          data.sourceUrl,
          env
        );

        const parsed = parseInput(
          fresh.text,
          getMaxNodes(env)
        );

        if (!parsed.nodes.length) {
          throw new Error(
            "刷新后没有识别到节点。"
          );
        }

        parsed.sourceUrl = data.sourceUrl;
        parsed.raw = fresh.text;
        parsed.headers = fresh.headers || {};

        await updateParsed(key, parsed, env);

        const text = renderResult(parsed, 20);

        await editMessage(
          env,
          chatId,
          q.message.message_id,
          text,
          key,
          true
        );

        message = null;
      }

      // ==========================
      // 导出 Base64
      // ==========================

      else if (action === "base64") {
        const full = parseFullContent(data);

        message = exportBase64(full.nodes);
      }

      // ==========================
      // 导出 YAML
      // ==========================

      else if (action === "yaml") {
        const full = parseFullContent(data);

        message = exportYaml(full.nodes);
      }

      // ==========================
      // 生成公开短链
      // ==========================

      else if (action === "short") {
        if (!data.sourceUrl) {
          throw new Error(
            "只有订阅 URL 才能生成短链。"
          );
        }

        const short = await makeShort(
          env,
          userId,
          data.raw
        );

        message = `短链：${escapeHtml(short)}`;
      }

      // ==========================
      // 保存订阅
      // ==========================

      else if (action === "save") {
        await saveSubscription(
          env,
          userId,
          data.sourceUrl || data.raw
        );

        message = "订阅已保存到你的个人记录。";
      }

      // ==========================
      // 发送文件或结果
      // ==========================

      if (message !== null && message !== "") {
        await deliver(
          env,
          chatId,
          message,
          action
        );
      }

      // ==========================
      // 操作成功才消耗次数
      // ==========================

      await finishUsage(
        env,
        usageKey,
        action,
        token,
        true
      );

      await answerCallback(
        env,
        q.id,
        "操作成功。"
      );

    } catch (e) {
      // 失败释放次数
      try {
        await finishUsage(
          env,
          usageKey,
          action,
          token,
          false
        );
      } catch (finishError) {
        console.error(
          "release usage error:",
          finishError?.message || finishError
        );
      }

      throw e;
    }

  } catch (e) {
    console.error(
      "callback error:",
      e?.stack || e
    );

    await answerCallback(
      env,
      q.id,
      e.message || "操作失败",
      true
    );
  }
}

// ================================
// 文件发送
// ================================

async function deliver(env, chatId, text, action) {
  if (action === "base64" || action === "yaml") {
    const filename =
      action === "base64"
        ? "nodes_base64.txt"
        : "config.yaml";

    const blob = new Blob(
      [text],
      {
        type: "text/plain;charset=utf-8"
      }
    );

    const form = new FormData();

    form.set("chat_id", String(chatId));
    form.set("document", blob, filename);

    const r = await fetch(
      `https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`,
      {
        method: "POST",
        body: form
      }
    );

    let j;

    try {
      j = await r.json();
    } catch {
      throw new Error("Telegram 文件发送返回异常。");
    }

    if (!r.ok || !j.ok) {
      throw new Error(
        j.description || "发送文件失败"
      );
    }

    return;
  }

  await reply(env, chatId, text);
}

// ================================
// HTML 转义
// ================================

function escapeHtml(s) {
  return String(s ?? "").replace(
    /[&<>"]/g,
    c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[c])
  );
}

// ================================
// SHA256
// ================================

async function sha256(s) {
  const b = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(s))
  );

  return [...new Uint8Array(b)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}
