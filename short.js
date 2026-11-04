
const SHORT_TTL = 30 * 24 * 60 * 60;
const MAX_CONTENT_BYTES = 5 * 1024 * 1024;
const MAX_SAVED_BYTES = 5 * 1024 * 1024;

// ======================================
// 基础检查
// ======================================

function getKV(env) {
  if (!env.BOT_KV) {
    throw new Error("BOT_KV 未配置。");
  }

  return env.BOT_KV;
}

function validateContent(content) {
  if (typeof content !== "string" || !content.trim()) {
    throw new Error("订阅内容为空，无法保存。");
  }

  const size = new TextEncoder().encode(content).byteLength;

  if (size > MAX_CONTENT_BYTES) {
    throw new Error("订阅内容超过短链保存限制。");
  }

  return size;
}

function getShortBaseUrl(env) {
  if (
    typeof env.SHORT_BASE_URL !== "string" ||
    !env.SHORT_BASE_URL.trim()
  ) {
    throw new Error("SHORT_BASE_URL 未配置。");
  }

  let url;

  try {
    url = new URL(env.SHORT_BASE_URL);
  } catch {
    throw new Error("SHORT_BASE_URL 配置不正确。");
  }

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("SHORT_BASE_URL 必须是有效的 HTTPS 基础地址。");
  }

  return url.origin + url.pathname.replace(/\/+$/, "");
}

function createId() {
  return crypto.randomUUID().replaceAll("-", "");
}

// ======================================
// 生成公开短链
// ======================================

export async function makeShort(env, userId, content) {
  const kv = getKV(env);

  validateContent(content);

  if (
    userId === undefined ||
    userId === null ||
    String(userId).length < 1
  ) {
    throw new Error("用户 ID 不正确。");
  }

  const baseUrl = getShortBaseUrl(env);

  const id = createId();

  await kv.put(
    `short:${id}`,
    content,
    {
      expirationTtl: SHORT_TTL,
      metadata: {
        userId: String(userId),
        createdAt: Date.now()
      }
    }
  );

  return `${baseUrl}/s/${id}`;
}

// ======================================
// 保存用户订阅
// ======================================

export async function saveSubscription(env, userId, value) {
  const kv = getKV(env);

  if (
    userId === undefined ||
    userId === null ||
    String(userId).length < 1
  ) {
    throw new Error("用户 ID 不正确。");
  }

  if (
    value === undefined ||
    value === null ||
    typeof value !== "string" ||
    !value.trim()
  ) {
    throw new Error("订阅内容为空，无法保存。");
  }

  const size = new TextEncoder().encode(value).byteLength;

  if (size > MAX_SAVED_BYTES) {
    throw new Error("保存内容超过大小限制。");
  }

  const id = crypto.randomUUID();

  const data = {
    value,
    createdAt: Date.now()
  };

  await kv.put(
    `saved:${String(userId)}:${id}`,
    JSON.stringify(data)
  );

  return {
    id,
    createdAt: data.createdAt
  };
}

// ======================================
// 公开短链访问
// ======================================

export async function handleShortLink(id, env) {
  if (!/^[a-f0-9]{32}$/.test(id)) {
    return new Response("Not found", {
      status: 404
    });
  }

  if (!env.BOT_KV) {
    return new Response("Service unavailable", {
      status: 503
    });
  }

  let item;

  try {
    item = await env.BOT_KV.get(`short:${id}`);
  } catch {
    return new Response("Service unavailable", {
      status: 503
    });
  }

  if (item === null) {
    return new Response("Short link expired or not found", {
      status: 404
    });
  }

  return new Response(item, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "public, max-age=60",
      "x-content-type-options": "nosniff",
      "content-disposition": "inline"
    }
  });
}
