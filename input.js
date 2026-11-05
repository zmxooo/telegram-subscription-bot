
const DEFAULT_MAX_BYTES = 1024 * 1024;
const HARD_MAX_BYTES = 5 * 1024 * 1024;
const REQUEST_TIMEOUT = 15000;
const MAX_URL_LENGTH = 4096;
const MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([
  301,
  302,
  303,
  307,
  308
]);

const ALLOWED_FILE_EXTENSIONS = new Set([
  "txt",
  "yaml",
  "yml"
]);

// ======================================
// 输入大小限制
// ======================================

function getMaxBytes(env = {}) {
  const configured = Number(
    env.MAX_INPUT_BYTES || DEFAULT_MAX_BYTES
  );

  if (
    !Number.isFinite(configured) ||
    configured <= 0
  ) {
    return DEFAULT_MAX_BYTES;
  }

  return Math.min(
    Math.floor(configured),
    HARD_MAX_BYTES
  );
}

// ======================================
// 超时请求
// ======================================

async function fetchWithTimeout(
  url,
  options = {},
  timeout = REQUEST_TIMEOUT
) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    timeout
  );

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("请求超时，请稍后重试。");
    }

    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ======================================
// IP 地址检查
// ======================================

function isIpAddress(host) {
  const value = String(host || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");

  // IPv6
  if (value.includes(":")) {
    return true;
  }

  // 标准 IPv4
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return true;
  }

  // 十进制、十六进制等数字形式
  if (/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    return true;
  }

  return false;
}

// ======================================
// 订阅 URL 安全检查
// ======================================

function validateSubscriptionUrl(input) {
  if (
    typeof input !== "string" ||
    !input.trim() ||
    input.length > MAX_URL_LENGTH
  ) {
    throw new Error("订阅 URL 格式不正确。");
  }

  let url;

  try {
    url = new URL(input.trim());
  } catch {
    throw new Error("订阅 URL 格式不正确。");
  }

  // 只允许 HTTPS
  if (url.protocol !== "https:") {
    throw new Error("仅允许 HTTPS 订阅地址。");
  }

  // 禁止 URL 用户名和密码
  if (url.username || url.password) {
    throw new Error("URL 不允许包含用户名或密码。");
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/\.$/, "");

  // 禁止 IP 和本地域名
  if (
    !host ||
    isIpAddress(host) ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home") ||
    host.endsWith(".lan") ||
    host.endsWith(".test") ||
    host.endsWith(".example") ||
    host.endsWith(".invalid") ||
    host.endsWith(".onion") ||
    host === "metadata.google.internal" ||
    host === "metadata.google"
  ) {
    throw new Error(
      "不允许访问 IP 地址或本地域名。"
    );
  }

  // 必须使用正常公网域名
  if (!host.includes(".")) {
    throw new Error(
      "订阅地址必须使用有效的公网域名。"
    );
  }

  // 只允许 HTTPS 默认端口
  if (url.port && url.port !== "443") {
    throw new Error(
      "订阅地址仅允许 HTTPS 默认端口 443。"
    );
  }

  // 移除 URL 锚点
  url.hash = "";

  return url;
}

// ======================================
// 读取并限制响应内容大小
// 同时限制响应体读取时间
// ======================================

async function readLimitedText(
  response,
  maxBytes,
  errorMessage,
  timeout = REQUEST_TIMEOUT
) {
  const contentLength = response.headers.get(
    "content-length"
  );

  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      throw new Error(
        "服务器返回了无效的 Content-Length。"
      );
    }

    const size = Number(contentLength);

    if (!Number.isSafeInteger(size)) {
      throw new Error(
        "服务器返回了无效的内容大小。"
      );
    }

    if (size > maxBytes) {
      await response.body?.cancel().catch(() => {});

      throw new Error(errorMessage);
    }
  }

  if (!response.body) {
    throw new Error(
      "服务器没有返回有效内容。"
    );
  }

  const reader = response.body.getReader();

  const chunks = [];

  let total = 0;
  let timedOut = false;

  const timer = setTimeout(() => {
    timedOut = true;
    reader.cancel().catch(() => {});
  }, timeout);

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (timedOut) {
        throw new Error(
          "读取服务器响应超时，请稍后重试。"
        );
      }

      if (done) break;

      total += value.byteLength;

      if (total > maxBytes) {
        await reader.cancel().catch(() => {});

        throw new Error(errorMessage);
      }

      chunks.push(value);
    }
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }

  if (timedOut) {
    throw new Error(
      "读取服务器响应超时，请稍后重试。"
    );
  }

  const result = new Uint8Array(total);

  let offset = 0;

  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder(
    "utf-8",
    {
      fatal: false
    }
  ).decode(result);
}

// ======================================
// Telegram API
// ======================================

async function tg(
  env,
  method,
  body = {}
) {
  if (!env.BOT_TOKEN) {
    throw new Error("BOT_TOKEN 未配置。");
  }

  let response;

  try {
    response = await fetchWithTimeout(
      `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify(body)
      }
    );
  } catch {
    throw new Error(
      "连接 Telegram API 失败或请求超时。"
    );
  }

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error(
      "Telegram API 返回了无效数据。"
    );
  }

  if (
    !response.ok ||
    !result ||
    result.ok !== true
  ) {
    throw new Error(
      result?.description ||
      `Telegram API 请求失败：HTTP ${response.status}`
    );
  }

  return result.result;
}

// ======================================
// 从文本中识别单条订阅 URL
// ======================================

function extractSubscriptionUrl(text) {
  if (typeof text !== "string") {
    return null;
  }

  const matches = [
    ...text.matchAll(/https:\/\/[^\s<>"']+/gi)
  ];

  // 必须只有一条 URL
  if (matches.length !== 1) {
    return null;
  }

  const original = matches[0][0];

  // 去除常见尾部标点
  const candidate = original.replace(
    /[，。；;,.!！?？)）\]}]+$/g,
    ""
  );

  if (!candidate) {
    return null;
  }

  const start = matches[0].index;

  if (typeof start !== "number" || start < 0) {
    return null;
  }

  const end = start + original.length;

  const remaining = (
    text.slice(0, start) +
    text.slice(end)
  ).trim();

  // 同一条消息包含节点 URI 时，
  // 不将其中的 URL 单独当成订阅地址
  if (
    /(?:vless|vmess|ss|ssr|trojan|hysteria2?|hy2|anytls|tuic|socks5?|http|wireguard):\/\//i.test(
      remaining
    )
  ) {
    return null;
  }

  // 避免普通长文本误识别
  if (remaining.length > 100) {
    return null;
  }

  return candidate;
}

// ======================================
// 提取 Telegram 消息输入
// ======================================

export async function extractMessageInput(
  message,
  env
) {
  const MAX = getMaxBytes(env);

  // ==================================
  // 普通文字
  // ==================================

  if (
    typeof message.text === "string" &&
    message.text.trim()
  ) {
    const text = message.text.trim();

    const byteLength = new TextEncoder()
      .encode(text)
      .byteLength;

    if (byteLength > MAX) {
      throw new Error(
        "输入内容超过大小限制。"
      );
    }

    const url = extractSubscriptionUrl(text);

    if (url) {
      validateSubscriptionUrl(url);

      return {
        text,
        url
      };
    }

    return {
      text,
      url: null
    };
  }

  // ==================================
  // Telegram 文件
  // ==================================

  const doc = message.document;

  if (doc) {
    if (
      typeof doc.file_id !== "string" ||
      !doc.file_id
    ) {
      throw new Error(
        "文件信息不正确。"
      );
    }

    if (
      doc.file_size !== undefined &&
      doc.file_size !== null
    ) {
      const fileSize = Number(doc.file_size);

      if (
        !Number.isSafeInteger(fileSize) ||
        fileSize < 0
      ) {
        throw new Error(
          "文件大小信息不正确。"
        );
      }

      if (fileSize > MAX) {
        throw new Error(
          "文件超过允许的大小限制。"
        );
      }
    }

    // 只接受 TXT 和 YAML
    const fileName = String(
      doc.file_name || ""
    );

    const extension = fileName
      .match(/\.([a-z0-9]+)$/i)?.[1]
      ?.toLowerCase();

    if (
      extension &&
      !ALLOWED_FILE_EXTENSIONS.has(extension)
    ) {
      throw new Error(
        "文件格式不支持，请发送 TXT 或 YAML 文件。"
      );
    }

    // 获取文件信息
    const meta = await tg(
      env,
      "getFile",
      {
        file_id: doc.file_id
      }
    );

    if (
      !meta ||
      typeof meta.file_path !== "string" ||
      !meta.file_path
    ) {
      throw new Error(
        "无法获取 Telegram 文件地址。"
      );
    }

    // 防止异常文件路径
    const pathParts = meta.file_path.split("/");

    if (
      meta.file_path.startsWith("/") ||
      pathParts.some(
        part =>
          !part ||
          part === "." ||
          part === ".."
      )
    ) {
      throw new Error(
        "Telegram 返回的文件路径不正确。"
      );
    }

    const encodedPath = pathParts
      .map(part => encodeURIComponent(part))
      .join("/");

    const fileUrl =
      `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${encodedPath}`;

    let response;

    try {
      response = await fetchWithTimeout(
        fileUrl,
        {
          method: "GET",
          redirect: "manual"
        }
      );
    } catch {
      throw new Error(
        "Telegram 文件下载失败或请求超时。"
      );
    }

    if (REDIRECT_STATUSES.has(response.status)) {
      await response.body?.cancel().catch(() => {});

      throw new Error(
        "Telegram 文件下载发生重定向，已拒绝访问。"
      );
    }

    if (!response.ok) {
      await response.body?.cancel().catch(() => {});

      throw new Error(
        `Telegram 文件下载失败：HTTP ${response.status}`
      );
    }

    const text = await readLimitedText(
      response,
      MAX,
      "文件超过允许的大小限制。"
    );

    if (!text.trim()) {
      throw new Error(
        "文件内容为空。"
      );
    }

    return {
      text,
      url: null
    };
  }

  throw new Error(
    "请发送文字、订阅链接或 TXT/YAML 文件。"
  );
}

// ======================================
// 下载订阅
// 支持多级重定向和短链接
// ======================================

export async function fetchSubscription(
  input,
  env
) {
  const MAX = getMaxBytes(env);

  let currentUrl = validateSubscriptionUrl(input);

  const visited = new Set();

  let response = null;

  // 最多 5 次重定向，即最多 6 次请求
  for (
    let redirectCount = 0;
    redirectCount <= MAX_REDIRECTS;
    redirectCount++
  ) {
    const current = currentUrl.toString();

    // 防止循环跳转
    if (visited.has(current)) {
      throw new Error(
        "订阅链接发生循环重定向，无法继续访问。"
      );
    }

    visited.add(current);

    try {
      response = await fetchWithTimeout(
        current,
        {
          method: "GET",
          redirect: "manual",
          headers: {
            "user-agent": "SubscriptionParserBot/1.0",
            "accept": [
              "text/plain",
              "application/yaml",
              "application/json",
              "application/octet-stream",
              "*/*"
            ].join(", ")
          }
        }
      );
    } catch (error) {
      if (
        error?.message ===
        "请求超时，请稍后重试。"
      ) {
        throw error;
      }

      throw new Error(
        "订阅下载失败，请检查订阅地址或稍后重试。"
      );
    }

    // ==================================
    // 处理重定向
    // ==================================

    if (REDIRECT_STATUSES.has(response.status)) {
      const location = response.headers.get(
        "location"
      );

      await response.body?.cancel().catch(() => {});

      if (!location || !location.trim()) {
        throw new Error(
          "订阅服务器要求重定向，但没有提供目标地址。"
        );
      }

      if (redirectCount >= MAX_REDIRECTS) {
        throw new Error(
          `订阅链接重定向次数超过限制（${MAX_REDIRECTS} 次）。`
        );
      }

      let nextUrl;

      try {
        // 支持：
        // https://example.com/next
        // /next
        // ../next
        // ?token=123
        // //example.com/next

        nextUrl = new URL(
          location.trim(),
          currentUrl
        );
      } catch {
        throw new Error(
          "订阅服务器返回了无效的重定向地址。"
        );
      }

      // 每次跳转都重新检查 HTTPS 和域名
      currentUrl = validateSubscriptionUrl(
        nextUrl.toString()
      );

      continue;
    }

    // ==================================
    // 处理异常状态
    // ==================================

    if (!response.ok) {
      await response.body?.cancel().catch(() => {});

      throw new Error(
        `订阅服务器返回 HTTP ${response.status}。`
      );
    }

    // 非重定向，获取最终响应
    break;
  }

  if (!response || !response.ok) {
    throw new Error(
      "无法获取最终订阅内容。"
    );
  }

  // ==================================
  // 读取最终订阅内容
  // ==================================

  const text = await readLimitedText(
    response,
    MAX,
    "订阅内容超过允许的大小限制。"
  );

  if (!text.trim()) {
    throw new Error(
      "订阅服务器返回了空内容。"
    );
  }

  // ==================================
  // 返回内容和最终响应头
  // ==================================

  return {
    text,

    headers: {
      userinfo: response.headers.get(
        "subscription-userinfo"
      ),

      contentType: response.headers.get(
        "content-type"
      )
    }
  };
}
