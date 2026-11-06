const DEFAULT_MAX_BYTES = 1024 * 1024;
const HARD_MAX_BYTES = 5 * 1024 * 1024;
const REQUEST_TIMEOUT = 15000;
const MAX_URL_LENGTH = 4096;
const MAX_REDIRECTS = 5;
const MAX_SERVER_RETRIES = 2;

const REDIRECT_STATUSES = new Set([
  301, 302, 303, 307, 308
]);

const RETRY_STATUSES = new Set([
  500, 502, 503, 504
]);

const RETRY_HEADER_STATUSES = new Set([
  403, 406
]);

const ALLOWED_FILE_EXTENSIONS = new Set([
  "txt", "yaml", "yml", "json",
  "conf", "ini", "list"
]);

// ======================================
// 请求头策略
// ======================================

const REQUEST_PROFILES = [
  {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/plain,application/yaml,application/json,application/octet-stream,*/*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8"
  },
  {
    "user-agent": "SubscriptionParserBot/1.0",
    "accept": "*/*"
  },
  {
    "user-agent": "Clash.Meta",
    "accept": "*/*"
  }
];

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
        `请求超时（${timeout / 1000} 秒）。`
      );
    }

    throw new Error(
      `网络请求失败：${error?.message || String(error)}`
    );
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
    if (inIPv4Range(value, network, prefix)) {
      return false;
    }
  }

  return true;
}

// ======================================
// IPv6 地址解析
// ======================================

function parseIPv6(host) {
  let value = String(host || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");

  if (
    !value ||
    value.includes("%")
  ) {
    return null;
  }

  // IPv4 嵌入式 IPv6
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");

    if (lastColon < 0) {
      return null;
    }

    const ipv4 = value.slice(lastColon + 1);
    const ipv4Number = ipv4ToNumber(ipv4);

    if (ipv4Number === null) {
      return null;
    }

    const high = ((ipv4Number >>> 16) & 0xffff)
      .toString(16);

    const low = (ipv4Number & 0xffff)
      .toString(16);

    value =
      value.slice(0, lastColon + 1) +
      high +
      ":" +
      low;
  }

  if (
    !/^[0-9a-f:]+$/i.test(value) ||
    !value.includes(":")
  ) {
    return null;
  }

  if (value.split("::").length > 2) {
    return null;
  }

  let parts;

  if (value.includes("::")) {
    const [leftText, rightText] = value.split("::");

    const left = leftText
      ? leftText.split(":")
      : [];

    const right = rightText
      ? rightText.split(":")
      : [];

    const missing = 8 - left.length - right.length;

    if (missing < 1) {
      return null;
    }

    parts = [
      ...left,
      ...Array(missing).fill("0"),
      ...right
    ];
  } else {
    parts = value.split(":");

    if (parts.length !== 8) {
      return null;
    }
  }

  if (parts.length !== 8) {
    return null;
  }

  const numbers = parts.map(part => {
    if (
      !/^[0-9a-f]{1,4}$/i.test(part)
    ) {
      return NaN;
    }

    return parseInt(part, 16);
  });

  if (
    numbers.some(
      n =>
        !Number.isInteger(n) ||
        n < 0 ||
        n > 65535
    )
  ) {
    return null;
  }

  return numbers;
}

// ======================================
// 判断 IPv6 是否属于公网地址
// ======================================

function isPublicIPv6(host) {
  const parts = parseIPv6(host);

  if (!parts) {
    return false;
  }

  // IPv4-mapped IPv6
  const isIPv4Mapped =
    parts.slice(0, 5).every(n => n === 0) &&
    parts[5] === 0xffff;

  if (isIPv4Mapped) {
    const ipv4Number =
      parts[6] * 65536 + parts[7];

    const ipv4 = [
      (ipv4Number >>> 24) & 255,
      (ipv4Number >>> 16) & 255,
      (ipv4Number >>> 8) & 255,
      ipv4Number & 255
    ].join(".");

    return isPublicIPv4(ipv4);
  }

  // 仅接受 IPv6 Global Unicast：2000::/3
  if ((parts[0] & 0xe000) !== 0x2000) {
    return false;
  }

  // 文档示例地址：2001:db8::/32
  if (
    parts[0] === 0x2001 &&
    parts[1] === 0x0db8
  ) {
    return false;
  }

  // 基准测试地址：2001:2::/48
  if (
    parts[0] === 0x2001 &&
    parts[1] === 0x0002 &&
    parts[2] === 0x0000
  ) {
    return false;
  }

  // IETF 特殊用途地址段：2001::/23
  if (
    parts[0] === 0x2001 &&
    (parts[1] & 0xfe00) === 0
  ) {
    return false;
  }

  // 6to4 地址段
  if (parts[0] === 0x2002) {
    return false;
  }

  // 文档地址：3fff::/20
  if (
    parts[0] === 0x3fff &&
    (parts[1] & 0xf000) === 0
  ) {
    return false;
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

  if (value.includes(":")) {
    return true;
  }

  if (ipv4ToNumber(value) !== null) {
    return true;
  }

  // 阻止整数、十六进制等非标准 IPv4 写法
  if (/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    return true;
  }

  return false;
}

// ======================================
// 判断 IP 是否属于公网
// ======================================

function isPublicIPAddress(host) {
  const value = String(host || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "");

  if (value.includes(":")) {
    return isPublicIPv6(value);
  }

  return isPublicIPv4(value);
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
    throw new Error("订阅 URL 格式不正确。");
  }

  let url;

  try {
    url = new URL(input.trim());
  } catch {
    throw new Error("订阅 URL 格式不正确。");
  }

  if (
    url.protocol !== "https:" &&
    url.protocol !== "http:"
  ) {
    throw new Error(
      "仅支持 HTTP 或 HTTPS 订阅地址。"
    );
  }

  if (url.username || url.password) {
    throw new Error(
      "URL 不允许包含用户名或密码。"
    );
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/\.$/, "");

  if (!host) {
    throw new Error("订阅地址缺少有效域名。");
  }

  // IP 地址检查
  if (isIpAddress(host)) {
    if (!isPublicIPAddress(host)) {
      throw new Error(
        "不允许访问私有、保留或非公网 IP 地址。"
      );
    }
  } else {
    // 域名检查
    if (!isValidPublicHostname(host)) {
      throw new Error(
        "订阅地址必须使用有效的公网域名。"
      );
    }
  }

  // 不再限制端口。
  // URL 自身会处理非法端口格式。

  url.hash = "";

  return url;
}

// ======================================
// 读取并限制响应内容大小
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
    throw new Error("服务器没有返回有效内容。");
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
      // 忽略释放锁异常
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

  return new TextDecoder("utf-8", {
    fatal: false
  }).decode(result);
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
  } catch (error) {
    throw new Error(
      `连接 Telegram API 失败：${error.message}`
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
    ...text.matchAll(/https?:\/\/[^\s<>"']+/gi)
  ];

  if (matches.length !== 1) {
    return null;
  }

  const original = matches[0][0];

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

  // 普通文字
  if (
    typeof message.text === "string" &&
    message.text.trim()
  ) {
    const text = message.text.trim();

    const byteLength = new TextEncoder()
      .encode(text)
      .byteLength;

    if (byteLength > MAX) {
      throw new Error("输入内容超过大小限制。");
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

  // Telegram 文件
  const doc = message.document;

  if (doc) {
    if (
      typeof doc.file_id !== "string" ||
      !doc.file_id
    ) {
      throw new Error("文件信息不正确。");
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
        throw new Error("文件大小信息不正确。");
      }

      if (fileSize > MAX) {
        throw new Error(
          "文件超过允许的大小限制。"
        );
      }
    }

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
    } catch (error) {
      throw new Error(
        `Telegram 文件下载失败：${error.message}`
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
      throw new Error("文件内容为空。");
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
// HTTP 错误信息
// ======================================

function getResponseError(response) {
  const status = response.status;

  const server =
    response.headers.get("server") || "未知";

  const contentType =
    response.headers.get("content-type") || "未知";

  const requestId =
    response.headers.get("cf-ray") ||
    response.headers.get("x-request-id") ||
    response.headers.get("x-trace-id") ||
    "无";

  return new Error(
    `HTTP ${status}；服务器：${server}；Content-Type：${contentType}；请求追踪 ID：${requestId}`
  );
}

// ======================================
// 多策略请求订阅服务器
// 保留最终 HTTP 状态和诊断信息
// ======================================

async function requestSubscription(url) {
  let lastNetworkError = null;
  let lastHttpError = null;

  for (
    let profileIndex = 0;
    profileIndex < REQUEST_PROFILES.length;
    profileIndex++
  ) {
    const headers = REQUEST_PROFILES[profileIndex];

    for (
      let retry = 0;
      retry <= MAX_SERVER_RETRIES;
      retry++
    ) {
      let response;

      try {
        response = await fetchWithTimeout(
          url,
          {
            method: "GET",
            redirect: "manual",
            headers
          }
        );

        lastNetworkError = null;
      } catch (error) {
        lastNetworkError = error;

        if (retry < 1) {
          continue;
        }

        break;
      }

      if (
        response.ok ||
        REDIRECT_STATUSES.has(response.status)
      ) {
        return response;
      }

      if (RETRY_HEADER_STATUSES.has(response.status)) {
        lastHttpError = getResponseError(response);

        await response.body?.cancel().catch(() => {});

        break;
      }

      if (RETRY_STATUSES.has(response.status)) {
        lastHttpError = getResponseError(response);

        await response.body?.cancel().catch(() => {});

        if (retry < MAX_SERVER_RETRIES) {
          continue;
        }

        break;
      }

      return response;
    }
  }

  if (lastHttpError) {
    throw lastHttpError;
  }

  if (lastNetworkError) {
    throw lastNetworkError;
  }

  throw new Error(
    "订阅服务器暂时无法访问，未收到有效 HTTP 响应。"
  );
}

// ======================================
// 下载订阅
// 支持多级重定向、多策略请求
// ======================================

export async function fetchSubscription(
  input,
  env
) {
  const MAX = getMaxBytes(env);

  let currentUrl = validateSubscriptionUrl(input);

  const visited = new Set();

  let response = null;

  for (
    let redirectCount = 0;
    redirectCount <= MAX_REDIRECTS;
    redirectCount++
  ) {
    const current = currentUrl.toString();

    if (visited.has(current)) {
      throw new Error(
        "订阅链接发生循环重定向，无法继续访问。"
      );
    }

    visited.add(current);

    try {
      response = await requestSubscription(current);
    } catch (error) {
      throw new Error(
        `订阅下载失败：${error?.message || String(error)}`
      );
    }

    // 处理重定向
    if (REDIRECT_STATUSES.has(response.status)) {
      const location = response.headers.get("location");

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

      // 每次跳转重新校验协议、域名和 IP
      currentUrl = validateSubscriptionUrl(
        nextUrl.toString()
      );

      continue;
    }

    // 处理异常 HTTP 状态
    if (!response.ok) {
      const status = response.status;

      const server =
        response.headers.get("server") || "未知";

      const contentType =
        response.headers.get("content-type") || "未知";

      const requestId =
        response.headers.get("cf-ray") ||
        response.headers.get("x-request-id") ||
        response.headers.get("x-trace-id") ||
        "无";

      await response.body?.cancel().catch(() => {});

      if (status === 401) {
        throw new Error(
          "订阅服务器要求身份验证（401），请检查订阅授权信息。"
        );
      }

      if (status === 403) {
        throw new Error(
          `订阅服务器拒绝访问（403）。服务器：${server}；请求追踪 ID：${requestId}。可能存在来源 IP 或访问权限限制。`
        );
      }

      if (status === 404) {
        throw new Error(
          "订阅地址不存在（404），请检查链接是否完整或已经失效。"
        );
      }

      if (status === 429) {
        throw new Error(
          "订阅服务器请求过于频繁（429），请稍后重试。"
        );
      }

      throw new Error(
        `订阅服务器返回 HTTP ${status}；服务器：${server}；Content-Type：${contentType}；请求追踪 ID：${requestId}。`
      );
    }

    break;
  }

  if (!response || !response.ok) {
    throw new Error(
      "无法获取最终订阅内容。"
    );
  }

  // ======================================
  // 读取最终订阅内容
  // ======================================

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

  // ======================================
  // 真实订阅响应诊断日志
  // 不脱敏，直接输出原始内容
  // ======================================

  console.log("订阅响应诊断：", {
    status: response.status,

    finalUrl: response.url || currentUrl.toString(),

    profileTitle: response.headers.get(
      "profile-title"
    ),

    contentDisposition: response.headers.get(
      "content-disposition"
    ),

    subscriptionUserinfo: response.headers.get(
      "subscription-userinfo"
    ),

    contentType: response.headers.get(
      "content-type"
    ),

    server: response.headers.get(
      "server"
    ),

    bodyPreview: text.slice(0, 500)
  });

  // ======================================
  // 返回订阅正文和响应头
  // ======================================

  return {
    text,

    headers: {
      userinfo: response.headers.get(
        "subscription-userinfo"
      ),

      contentType: response.headers.get(
        "content-type"
      ),

      profileTitle: response.headers.get(
        "profile-title"
      ),

      contentDisposition: response.headers.get(
        "content-disposition"
      )
    }
  };
}
