
const DEFAULT_MAX_BYTES = 1024 * 1024;
const HARD_MAX_BYTES = 5 * 1024 * 1024;
const REQUEST_TIMEOUT = 15000;
const MAX_URL_LENGTH = 4096;

// ======================================
// 输入大小限制
// ======================================

function getMaxBytes(env) {
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
  const value = host
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

  if (url.protocol !== "https:") {
    throw new Error("仅允许 HTTPS 订阅地址。");
  }

  if (url.username || url.password) {
    throw new Error("URL 不允许包含用户名或密码。");
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/\.$/, "");

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

  // 必须使用正常域名格式
  if (!host.includes(".")) {
    throw new Error(
      "订阅地址必须使用有效的公网域名。"
    );
  }

  // 只允许默认 HTTPS 端口
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
// ======================================

async function readLimitedText(
  response,
  maxBytes,
  errorMessage
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

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      total += value.byteLength;

      if (total > maxBytes) {
        await reader.cancel().catch(() => {});

        throw new Error(errorMessage);
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
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
  const matches = [
    ...text.matchAll(/https:\/\/[^\s<>"']+/gi)
  ];

  if (matches.length !== 1) {
    return null;
  }

  let candidate = matches[0][0];

  // 去除常见的尾部标点
  candidate = candidate.replace(
    /[，。；;,.!！?？)）\]}]+$/g,
    ""
  );

  const start = text.indexOf(matches[0][0]);

  if (start < 0 || !candidate) {
    return null;
  }

  const end = start + matches[0][0].length;

  const remaining = (
    text.slice(0, start) +
    text.slice(end)
  ).trim();

  // 如果同一条消息还包含节点链接，
  // 则按普通文本交给解析器处理
  if (
    /(?:vless|vmess|ss|ssr|trojan|hysteria2?|hy2|anytls|tuic|socks5?|http):\/\//i.test(
      remaining
    )
  ) {
    return null;
  }

  // 避免将大量普通文字误识别为订阅链接
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

    // 整条消息就是订阅 URL
    const exactUrl = /^https:\/\/[^\s]+$/i.test(text)
      ? text
      : null;

    // 支持简单说明文字加一条订阅 URL
    const embeddedUrl = exactUrl
      ? null
      : extractSubscriptionUrl(text);

    const url = exactUrl || embeddedUrl;

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
      !["txt", "yaml", "yml"].includes(extension)
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
        part => !part || part === "." || part === ".."
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

    if (
      response.status >= 300 &&
      response.status < 400
    ) {
      throw new Error(
        "Telegram 文件下载发生重定向，已拒绝访问。"
      );
    }

    if (!response.ok) {
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
// ======================================

export async function fetchSubscription(
  input,
  env
) {
  const MAX = getMaxBytes(env);

  const url = validateSubscriptionUrl(input);

  let response;

  try {
    response = await fetchWithTimeout(
      url.toString(),
      {
        method: "GET",
        redirect: "manual",
        headers: {
          "user-agent": "SubscriptionParserBot/1.0",
          "accept": "*/*"
        }
      }
    );
  } catch {
    throw new Error(
      "订阅下载失败或请求超时。"
    );
  }

  // 禁止自动跟随重定向
  if (
    response.status >= 300 &&
    response.status < 400
  ) {
    throw new Error(
      "订阅服务器发生重定向，请使用最终 HTTPS 地址。"
    );
  }

  if (!response.ok) {
    throw new Error(
      `订阅服务器返回 HTTP ${response.status}。`
    );
  }

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
