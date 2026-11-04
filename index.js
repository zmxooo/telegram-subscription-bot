
import { handleTelegramUpdate, telegram } from "./telegram.js";
import { handleShortLink } from "./short.js";

export { UsageGuard } from "./usage.js";

// ======================================
// 基础配置
// ======================================

const MAX_WEBHOOK_BYTES = 1024 * 1024;
const MAX_SETUP_SECRET_LENGTH = 256;

const TELEGRAM_SECRET_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

// ======================================
// 通用响应
// ======================================

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...extraHeaders
    }
  });
}

function jsonError(message, status) {
  return jsonResponse(
    {
      ok: false,
      error: message
    },
    status
  );
}

function textResponse(message, status = 200, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

// ======================================
// 请求方法检查
// ======================================

function methodNotAllowed(allow) {
  return jsonResponse(
    {
      ok: false,
      error: "Method not allowed"
    },
    405,
    {
      Allow: allow
    }
  );
}

// ======================================
// 流式读取请求体
// ======================================

async function readRequestBody(request, maxBytes) {
  const contentLength = request.headers.get("content-length");

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      throw new Error("INVALID_CONTENT_LENGTH");
    }

    if (Number(contentLength) > maxBytes) {
      throw new Error("BODY_TOO_LARGE");
    }
  }

  if (!request.body) {
    throw new Error("EMPTY_BODY");
  }

  const reader = request.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      totalBytes += value.byteLength;

      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("BODY_TOO_LARGE");
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const result = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder("utf-8", {
    fatal: true
  }).decode(result);
}

// ======================================
// Telegram Update 基础检查
// ======================================

function isValidUpdate(update) {
  if (
    !update ||
    typeof update !== "object" ||
    Array.isArray(update)
  ) {
    return false;
  }

  if (
    !Number.isSafeInteger(update.update_id) ||
    update.update_id < 0
  ) {
    return false;
  }

  return true;
}

// ======================================
// Webhook 环境检查
// ======================================

function checkWebhookEnvironment(env) {
  return Boolean(
    typeof env.BOT_TOKEN === "string" &&
    env.BOT_TOKEN.length > 0 &&
    typeof env.WEBHOOK_SECRET === "string" &&
    env.WEBHOOK_SECRET.length > 0
  );
}

// ======================================
// 健康检查
// ======================================

async function handleHealth(request) {
  if (request.method !== "GET") {
    return methodNotAllowed("GET");
  }

  return jsonResponse({
    ok: true,
    service: "telegram-subscription-parser"
  });
}

// ======================================
// 公开短链
// ======================================

async function handleShortRequest(request, url, env) {
  if (request.method !== "GET") {
    return textResponse(
      "Method not allowed",
      405,
      {
        Allow: "GET"
      }
    );
  }

  const id = url.pathname.slice(3);

  if (!/^[a-f0-9]{32}$/.test(id)) {
    return textResponse("Not found", 404);
  }

  try {
    return await handleShortLink(id, env);
  } catch (error) {
    console.error(
      "Short link failed:",
      error?.stack || error
    );

    return textResponse(
      "Service unavailable",
      503
    );
  }
}

// ======================================
// Telegram Webhook
// ======================================

async function handleWebhook(request, env, ctx) {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }

  if (!checkWebhookEnvironment(env)) {
    console.error(
      "Webhook environment variables missing"
    );

    return jsonError(
      "Service unavailable",
      503
    );
  }

  const secret = request.headers.get(
    "X-Telegram-Bot-Api-Secret-Token"
  );

  if (secret !== env.WEBHOOK_SECRET) {
    return textResponse("Forbidden", 403);
  }

  let update;

  try {
    const raw = await readRequestBody(
      request,
      MAX_WEBHOOK_BYTES
    );

    update = JSON.parse(raw);
  } catch (error) {
    const message = error?.message;

    if (message === "BODY_TOO_LARGE") {
      return jsonError(
        "Request too large",
        413
      );
    }

    if (message === "INVALID_CONTENT_LENGTH") {
      return jsonError(
        "Invalid Content-Length",
        400
      );
    }

    if (error instanceof SyntaxError) {
      return jsonError(
        "Invalid JSON",
        400
      );
    }

    if (error instanceof TypeError) {
      return jsonError(
        "Invalid UTF-8",
        400
      );
    }

    console.error(
      "Webhook body read failed:",
      error?.stack || error
    );

    return jsonError(
      "Invalid request body",
      400
    );
  }

  if (!isValidUpdate(update)) {
    return jsonError(
      "Invalid Telegram update",
      400
    );
  }

  // 快速响应 Telegram，消息交给后台处理。
  // 后台处理失败会记录日志，但不会自动触发 Telegram 重投。
  ctx.waitUntil(
    Promise.resolve()
      .then(() => handleTelegramUpdate(update, env))
      .catch(error => {
        console.error(
          "Telegram update failed:",
          error?.stack || error
        );
      })
  );

  return jsonResponse({
    ok: true
  });
}

// ======================================
// 设置 Telegram Webhook
// ======================================

async function handleSetWebhook(request, url, env) {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }

  if (!checkWebhookEnvironment(env)) {
    return jsonError(
      "BOT_TOKEN 或 WEBHOOK_SECRET 未配置",
      503
    );
  }

  // Telegram secret_token 只允许字母、数字、下划线和连字符。
  if (
    env.WEBHOOK_SECRET.length > MAX_SETUP_SECRET_LENGTH ||
    !TELEGRAM_SECRET_PATTERN.test(env.WEBHOOK_SECRET)
  ) {
    return jsonError(
      "WEBHOOK_SECRET 格式不符合 Telegram 要求",
      500
    );
  }

  // 使用请求头验证，不使用 URL 参数传递密钥。
  const key = request.headers.get(
    "X-Setup-Secret"
  );

  if (
    !key ||
    key.length > MAX_SETUP_SECRET_LENGTH ||
    key !== env.WEBHOOK_SECRET
  ) {
    return textResponse(
      "Forbidden",
      403
    );
  }

  // Telegram Webhook 必须使用公开 HTTPS 地址。
  if (url.protocol !== "https:") {
    return jsonError(
      "Webhook 必须使用 HTTPS 地址",
      400
    );
  }

  try {
    const webhookUrl = `${url.origin}/webhook`;

    const result = await telegram(
      env,
      "setWebhook",
      {
        url: webhookUrl,
        secret_token: env.WEBHOOK_SECRET,
        allowed_updates: [
          "message",
          "callback_query"
        ]
      }
    );

    if (!result || result.ok !== true) {
      console.error(
        "Telegram rejected setWebhook:",
        result
      );

      return jsonResponse(
        {
          ok: false,
          error: "Telegram 设置 Webhook 失败",
          telegram: result || null
        },
        502
      );
    }

    return jsonResponse({
      ok: true,
      message: "Webhook 设置成功",
      webhook: webhookUrl
    });
  } catch (error) {
    console.error(
      "Set webhook failed:",
      error?.stack || error
    );

    return jsonError(
      "设置 Webhook 失败",
      502
    );
  }
}

// ======================================
// Worker 主入口
// ======================================

export default {
  async fetch(request, env, ctx) {
    let url;

    try {
      url = new URL(request.url);
    } catch {
      return jsonError(
        "Invalid request URL",
        400
      );
    }

    const pathname = url.pathname;

    try {
      // 健康检查
      if (pathname === "/health") {
        return await handleHealth(request);
      }

      // 公开短链
      if (pathname.startsWith("/s/")) {
        return await handleShortRequest(
          request,
          url,
          env
        );
      }

      // Telegram Webhook
      if (pathname === "/webhook") {
        return await handleWebhook(
          request,
          env,
          ctx
        );
      }

      // 设置 Telegram Webhook
      if (pathname === "/set-webhook") {
        return await handleSetWebhook(
          request,
          url,
          env
        );
      }

      // 默认页面
      return textResponse(
        "Telegram subscription parser is running."
      );
    } catch (error) {
      console.error(
        "Worker request failed:",
        error?.stack || error
      );

      return jsonError(
        "Internal server error",
        500
      );
    }
  }
};
