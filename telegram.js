
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

// ======================================
// 基础配置
// ======================================

function getMaxNodes(env) {
  const value = Number(env.MAX_NODES || 1000);

  if (!Number.isFinite(value) || value < 1) {
    return 1000;
  }

  return Math.min(Math.floor(value), 1000);
}

const ALLOWED_ACTIONS = new Set([
  "refresh",
  "toggle",
  "base64",
  "yaml",
  "short",
  "save"
]);

// ======================================
// Telegram API
// ======================================

export async function telegram(env, method, body = {}) {
  if (!env.BOT_TOKEN) {
    throw new Error("BOT_TOKEN 未配置。");
  }

  const response = await fetch(
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
    data = await response.json();
  } catch {
    throw new Error(`Telegram ${method}: 返回数据异常`);
  }

  if (!response.ok || !data.ok) {
    throw new Error(
      `Telegram ${method}: ${data?.description || "unknown error"}`
    );
  }

  return data.result;
}

// ======================================
// 获取 Bot 自身 ID
// 按 Token 缓存，避免更换 Token 后使用旧 ID
// ======================================

let cachedBot = null;

async function getBotId(env) {
  if (
    cachedBot &&
    cachedBot.token === env.BOT_TOKEN
  ) {
    return cachedBot.id;
  }

  const me = await telegram(env, "getMe");

  if (!me || !me.id || !me.is_bot) {
    throw new Error("无法获取 Bot 身份信息。");
  }

  cachedBot = {
    token: env.BOT_TOKEN,
    id: me.id
  };

  return me.id;
}

// ======================================
// 检查 Bot 是否为群组管理员
// ======================================

async function isBotAdmin(env, chatId) {
  const botId = await getBotId(env);

  const member = await telegram(
    env,
    "getChatMember",
    {
      chat_id: chatId,
      user_id: botId
    }
  );

  return [
    "creator",
    "administrator"
  ].includes(member.status);
}

// ======================================
// 检查点击按钮的用户是否为管理员
// ======================================

async function isAdmin(env, chatId, userId) {
  const member = await telegram(
    env,
    "getChatMember",
    {
      chat_id: chatId,
      user_id: userId
    }
  );

  return [
    "creator",
    "administrator"
  ].includes(member.status);
}

// ======================================
// 消息发送
// ======================================

async function reply(env, chatId, text, extra = {}) {
  return telegram(env, "sendMessage", {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    ...extra
  });
}

// ======================================
// 编辑原消息
// ======================================

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

// ======================================
// 回调提示
// ======================================

async function answerCallback(
  env,
  callbackId,
  text = "",
  showAlert = false
) {
  try {
    await telegram(
      env,
      "answerCallbackQuery",
      {
        callback_query_id: callbackId,
        text: text || undefined,
        show_alert: showAlert
      }
    );
  } catch (error) {
    console.error(
      "answerCallbackQuery error:",
      error?.message || error
    );
  }
}

// ======================================
// 六项操作按钮
// expanded=true：显示前20个
// expanded=false：显示前2个
// ======================================

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

// ======================================
// 解析输入
// ======================================

async function loadAndParse(message, env) {
  const input = await extractMessageInput(message, env);

  let source = input.text;
  let headers = {};

  if (input.url) {
    const result = await fetchSubscription(
      input.url,
      env
    );

    source = result.text;
    headers = result.headers || {};
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

// ======================================
// 接收 Telegram 更新
// ======================================

export async function handleTelegramUpdate(update, env) {
  if (update.callback_query) {
    return handleCallback(
      update.callback_query,
      env
    );
  }

  const message = update.message;

  if (
    !message ||
    !message.chat ||
    !message.from ||
    message.from.is_bot
  ) {
    return;
  }

  const chatId = message.chat.id;
  const chatType = message.chat.type;

  try {
    // 群组必须先验证 Bot 自身管理员身份
    if (chatType !== "private") {
      let botAdmin;

      try {
        botAdmin = await isBotAdmin(
          env,
          chatId
        );
      } catch (error) {
        console.error(
          "Bot admin check error:",
          error?.message || error
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

    const parsed = await loadAndParse(
      message,
      env
    );

    if (
      !parsed.nodes ||
      !parsed.nodes.length
    ) {
      await reply(
        env,
        chatId,
        "没有识别到支持的节点。请发送订阅链接、节点 URI、TXT 或 Clash YAML。"
      );

      return;
    }

    const key = await storeParsed(
      parsed,
      env
    );

    await reply(
      env,
      chatId,
      renderResult(parsed, 20),
      {
        reply_markup: callbackKeyboard(
          key,
          true
        )
      }
    );

  } catch (error) {
    console.error(
      "Parse error:",
      error?.stack || error
    );

    await reply(
      env,
      chatId,
      `解析失败：${escapeHtml(error.message || "未知错误")}`
    );
  }
}

// ======================================
// 统一缓存解析结果
// ======================================

function buildPayload(parsed) {
  return {
    raw: parsed.raw,
    sourceUrl: parsed.sourceUrl || null,
    nodes: parsed.nodes || [],
    headers: parsed.headers || {},

    totalCount:
      parsed.totalCount ??
      parsed.nodes?.length ??
      0,

    parsedCount:
      parsed.parsedCount ??
      parsed.nodes?.length ??
      0,

    truncatedCount:
      parsed.truncatedCount ?? 0,

    duplicateCount:
      parsed.duplicateCount ?? 0,

    uniqueCount:
      parsed.uniqueCount ?? 0,

    protocolCounts:
      parsed.protocolCounts || {},

    regionCounts:
      parsed.regionCounts || {},

    createdAt: Date.now()
  };
}

// ======================================
// 保存解析结果
// ======================================

async function storeParsed(parsed, env) {
  if (!env.BOT_KV) {
    throw new Error("BOT_KV 未配置。");
  }

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

// ======================================
// 更新解析缓存
// ======================================

async function updateParsed(key, parsed, env) {
  await env.BOT_KV.put(
    `result:${key}`,
    JSON.stringify(buildPayload(parsed)),
    {
      expirationTtl: 86400
    }
  );
}

// ======================================
// 完整内容重新解析
// ======================================

function parseFullContent(data) {
  if (!data.raw) {
    throw new Error(
      "原始订阅内容不存在，无法导出。"
    );
  }

  const parsed = parseInput(
    data.raw,
    Number.MAX_SAFE_INTEGER
  );

  if (
    !parsed.nodes ||
    !parsed.nodes.length
  ) {
    throw new Error("没有可导出的节点。");
  }

  return parsed;
}

// ======================================
// 展开 / 折叠节点
// 不消耗功能次数
// ======================================

async function toggleNodes(
  query,
  env,
  key,
  state,
  data
) {
  const expanded = state === "1";
  const limit = expanded ? 20 : 2;

  await editMessage(
    env,
    query.message.chat.id,
    query.message.message_id,
    renderResult(data, limit),
    key,
    expanded
  );

  await answerCallback(
    env,
    query.id
  );
}

// ======================================
// 额度释放
// 仅用于尚未产生实际业务结果的失败
// ======================================

async function releaseUsage(
  env,
  usageKey,
  action,
  token
) {
  try {
    await finishUsage(
      env,
      usageKey,
      action,
      token,
      false
    );
  } catch (error) {
    console.error(
      "Release usage failed:",
      error?.stack || error
    );
  }
}

// ======================================
// 额度确认
// 已完成的业务操作绝不主动释放额度
// ======================================

async function commitUsage(
  env,
  usageKey,
  action,
  token
) {
  try {
    await finishUsage(
      env,
      usageKey,
      action,
      token,
      true
    );

    return true;
  } catch (error) {
    console.error(
      "Commit usage failed:",
      error?.stack || error
    );

    return false;
  }
}

// ======================================
// Callback 主处理
// ======================================

async function handleCallback(query, env) {
  if (
    !query ||
    !query.message ||
    !query.from ||
    !query.id
  ) {
    return;
  }

  const parts = String(
    query.data || ""
  ).split("|");

  const prefix = parts[0];
  const action = parts[1];
  const key = parts[2];
  const state = parts[3];

  if (
    prefix !== "act" ||
    !ALLOWED_ACTIONS.has(action) ||
    !/^[a-f0-9]{20}$/i.test(key || "")
  ) {
    await answerCallback(
      env,
      query.id,
      "无效的操作请求。",
      true
    );

    return;
  }

  const chatId = query.message.chat.id;
  const chatType = query.message.chat.type;
  const userId = query.from.id;

  try {
    // 群组权限检查
    if (chatType !== "private") {
      let botAdmin;

      try {
        botAdmin = await isBotAdmin(
          env,
          chatId
        );
      } catch (error) {
        console.error(
          "Bot admin check error:",
          error?.message || error
        );

        await answerCallback(
          env,
          query.id,
          "无法验证 Bot 管理员身份，请检查 Bot 是否仍为群组管理员。",
          true
        );

        return;
      }

      if (!botAdmin) {
        await answerCallback(
          env,
          query.id,
          "Bot 必须是群组管理员才能使用此功能。",
          true
        );

        return;
      }

      let userAdmin = false;

      try {
        userAdmin = await isAdmin(
          env,
          chatId,
          userId
        );
      } catch (error) {
        console.error(
          "User admin check error:",
          error?.message || error
        );
      }

      if (!userAdmin) {
        await answerCallback(
          env,
          query.id,
          "只有群组管理员可以使用此功能。",
          true
        );

        return;
      }
    }

    // 读取解析缓存
    const saved = await env.BOT_KV.get(
      `result:${key}`
    );

    if (!saved) {
      throw new Error(
        "这份解析结果已过期，请重新发送订阅。"
      );
    }

    const data = JSON.parse(saved);

    // 展开 / 折叠
    if (action === "toggle") {
      if (
        state !== "0" &&
        state !== "1"
      ) {
        throw new Error("无效的展开状态。");
      }

      await toggleNodes(
        query,
        env,
        key,
        state,
        data
      );

      return;
    }

    // 生成操作指纹
    const fingerprint = await sha256(
      data.sourceUrl || data.raw
    );

    const usageKey =
      `${userId}:${fingerprint}`;

    // 原子领取额度
    const claim = await claimUsage(
      env,
      usageKey,
      action
    );

    if (
      !claim ||
      !claim.ok ||
      !claim.token
    ) {
      await answerCallback(
        env,
        query.id,
        claim?.error || "此用户对此订阅的该功能已经使用过一次，或操作正在处理中。",
        true
      );

      return;
    }

    const token = claim.token;

    // committed 表示实际业务结果已经产生
    let committed = false;

    try {
      let message = null;

      // ==================================
      // 刷新订阅
      // ==================================

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

        if (
          !parsed.nodes ||
          !parsed.nodes.length
        ) {
          throw new Error(
            "刷新后没有识别到节点。"
          );
        }

        parsed.sourceUrl = data.sourceUrl;
        parsed.raw = fresh.text;
        parsed.headers = fresh.headers || {};

        await updateParsed(
          key,
          parsed,
          env
        );

        // 缓存已经更新，不能再释放额度
        committed = true;

        await editMessage(
          env,
          chatId,
          query.message.message_id,
          renderResult(parsed, 20),
          key,
          true
        );
      }

      // ==================================
      // 导出 Base64
      // ==================================

      else if (action === "base64") {
        const full = parseFullContent(data);

        message = exportBase64(full.nodes);
      }

      // ==================================
      // 导出 YAML
      // ==================================

      else if (action === "yaml") {
        const full = parseFullContent(data);

        message = exportYaml(full.nodes);
      }

      // ==================================
      // 生成公开短链
      // ==================================

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

        // 短链已经写入 KV
        committed = true;

        message =
          `短链：${escapeHtml(short)}`;
      }

      // ==================================
      // 保存订阅
      // ==================================

      else if (action === "save") {
        await saveSubscription(
          env,
          userId,
          data.sourceUrl || data.raw
        );

        // 订阅已经写入 KV
        committed = true;

        message = "订阅已保存到你的个人记录。";
      }

      // ==================================
      // 发送结果或文件
      // ==================================

      if (
        message !== null &&
        message !== ""
      ) {
        await deliver(
          env,
          chatId,
          message,
          action
        );

        committed = true;
      }

      // ==================================
      // 确认额度
      // ==================================

      const usageCommitted = await commitUsage(
        env,
        usageKey,
        action,
        token
      );

      if (!usageCommitted) {
        await answerCallback(
          env,
          query.id,
          "操作已经完成，但额度记录同步失败，请勿重复点击。",
          true
        );

        return;
      }

      await answerCallback(
        env,
        query.id,
        "操作成功。"
      );

    } catch (error) {
      // 只有业务结果尚未产生时才能释放额度
      if (!committed) {
        await releaseUsage(
          env,
          usageKey,
          action,
          token
        );
      } else {
        console.error(
          "Operation completed but follow-up failed; usage will not be released:",
          error?.stack || error
        );
      }

      throw error;
    }

  } catch (error) {
    console.error(
      "Callback error:",
      error?.stack || error
    );

    await answerCallback(
      env,
      query.id,
      error.message || "操作失败",
      true
    );
  }
}

// ======================================
// 发送文件或普通消息
// ======================================

async function deliver(
  env,
  chatId,
  text,
  action
) {
  if (
    action === "base64" ||
    action === "yaml"
  ) {
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

    form.set(
      "chat_id",
      String(chatId)
    );

    form.set(
      "document",
      blob,
      filename
    );

    const response = await fetch(
      `https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`,
      {
        method: "POST",
        body: form
      }
    );

    let result;

    try {
      result = await response.json();
    } catch {
      throw new Error(
        "Telegram 文件发送返回异常。"
      );
    }

    if (
      !response.ok ||
      !result.ok
    ) {
      throw new Error(
        result?.description || "发送文件失败"
      );
    }

    return;
  }

  await reply(
    env,
    chatId,
    text
  );
}

// ======================================
// HTML 转义
// ======================================

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"]/g,
    character => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[character])
  );
}

// ======================================
// SHA256
// ======================================

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      String(value ?? "")
    )
  );

  return [...new Uint8Array(digest)]
    .map(byte =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
}
