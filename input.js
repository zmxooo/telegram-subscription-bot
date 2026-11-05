
const DEFAULT_MAX_BYTES = 1024 * 1024;
const HARD_MAX_BYTES = 5 * 1024 * 1024;
const REQUEST_TIMEOUT = 15000;
const MAX_URL_LENGTH = 4096;
const MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([
  301, 302, 303, 307, 308
]);

// 常见订阅文件格式
const ALLOWED_FILE_EXTENSIONS = new Set([
  "txt",
  "yaml",
  "yml",
  "json",
  "conf",
  "ini",
  "list"
]);

// 允许的常见 HTTP 服务端口
const ALLOWED_PORTS = new Set([
  "80",
  "443",
  "8080",
  "8443",
  "2053",
  "2083",
  "2087",
  "2096"
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
      throw new Error(
        "请求超时，请稍后重试。"
      );
    }

    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ======================================
// IPv4 转数字
// ======================================

function ipv4ToNumber(host) {
  const parts = String(host || "").split(".");

  if (parts.length !== 4) {
    return null;
  }

  const numbers = parts.map(part => {
    if (!/^\d+$/.test(part)) {
      return NaN;
    }

    return Number(part);
  });

  if (
    numbers.some(
      n =>
        !Number.isInteger(n) ||
        n < 0 ||
        n > 255
    )
  ) {
    return null;
  }

  return (
    numbers[0] * 16777216 +
    numbers[1] * 65536 +
    numbers[2] * 256 +
    numbers[3]
  );
}

// ======================================
// CIDR 判断
// ======================================

function inIPv4Range(ip, network, prefix) {
  const ipNumber = ipv4ToNumber(ip);
  const networkNumber = ipv4ToNumber(network);

  if (
    ipNumber === null ||
    networkNumber === null
  ) {
    return false;
  }

  const blockSize = 2 ** (32 - prefix);

  return (
    Math.floor(ipNumber / blockSize) ===
    Math.floor(networkNumber / blockSize)
  );
}

// ======================================
// 判断是否为公网 IPv4
// ======================================

function isPublicIPv4(host) {
  const value = String(host || "");

  if (ipv4ToNumber(value) === null) {
    return false;
  }

  // 特殊用途、私有、保留及非公网地址段
  const blockedRanges = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],

    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],

    ["198.18.0.0", 15],
    ["198.51.100.0", 24],

    ["203.0.113.0", 24],

    ["224.0.0.0", 4],
    ["240.0.0.0", 4]
  ];

  for (const [network, prefix] of blockedRanges) {
    if (
      inIPv4Range(value, network, prefix)
    ) {
      return false;
    }
  }

  return true;
}

// ======================================
// 判断是否为 IP 地址
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
  if (ipv4ToNumber(value) !== null) {
    return true;
  }

  // 数字、十六进制及非标准 IP 表示
  if (
    /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)
  ) {
    return true;
  }

  return false;
}

// ======================================
// 域名检查
// ======================================

function isValidPublicHostname(host) {
  if (
    !host ||
    host.length > 253 ||
    !host.includes(".")
  ) {
    return false;
  }

  // 禁止本地及特殊用途域名
  const blockedHosts = new Set([
    "localhost",
    "metadata.google",
    "metadata.google.internal"
  ]);

  const blockedSuffixes = [
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".arpa"
  ];

  if (blockedHosts.has(host)) {
    return false;
  }

  if (
    blockedSuffixes.some(
      suffix => host.endsWith(suffix)
    )
  ) {
    return false;
  }

  // 域名字符检查
  if (!/^[a-z0-9.-]+$/i.test(host)) {
    return false;
  }

  const labels = host.split(".");

  if (
    labels.some(
      label =>
        !label ||
        label.length > 63 ||
        label.startsWith("-") ||
        label.endsWith("-")
    )
  ) {
    return false;
  }

  return true;
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
    throw new Error(
      "订阅 URL 格式不正确。"
    );
  }

  let url;

  try {
    url = new URL(input.trim());
  } catch {
    throw new Error(
      "订阅 URL 格式不正确。"
    );
  }

  // 允许 HTTP 和 HTTPS
  if (
    url.protocol !== "https:" &&
    url.protocol !== "http:"
  ) {
    throw new Error(
      "仅支持 HTTP 或 HTTPS 订阅地址。"
    );
  }

  // 禁止 URL 用户名和密码
  if (url.username || url.password) {
    throw new Error(
      "URL 不允许包含用户名或密码。"
    );
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/\.$/, "");

  if (!host) {
    throw new Error(
      "订阅地址缺少有效域名。"
    );
  }

  // IP 地址单独处理
  if (isIpAddress(host)) {
    // 只允许公网 IPv4
    if (!isPublicIPv4(host)) {
      throw new Error(
        "不允许访问私有、保留或非公网 IP 地址。"
      );
    }
  } else {
    // 普通域名检查
    if (!isValidPublicHostname(host)) {
      throw new Error(
        "订阅地址必须使用有效的公网域名。"
      );
    }
  }

  // 只开放常见 Web 端口
  if (
    url.port &&
    !ALLOWED_PORTS.has(url.port)
  ) {
    throw new Error(
      "订阅地址使用了不允许的端口。"
    );
  }

  // 移除锚点
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

    try {
      reader.releaseLock();
    } catch {
      // 忽略释放锁时的异常
    }
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
    throw new Error(
      "BOT_TOKEN 未配置。"
    );
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

  // HTTP / HTTPS 均可
  const matches = [
    ...text.matchAll(/https?:\/\/[^\s<>"']+/gi)
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

  if (
    typeof start !== "number" ||
    start < 0
  ) {
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

    // 检查文件格式
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
        "文件格式不支持，请发送 TXT、YAML、JSON 或配置文件。"
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

    // Telegram 文件下载不跟随未知跳转
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
    "请发送文字、订阅链接或 TXT/YAML/JSON 文件。"
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
        nextUrl = new URL(
          location.trim(),
          currentUrl
        );
      } catch {
        throw new Error(
          "订阅服务器返回了无效的重定向地址。"
        );
      }

      // 每次跳转都重新进行安全检查
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
