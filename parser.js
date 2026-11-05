import YAML from "yaml";

// ======================================
// 支持的协议
// ======================================

const SUPPORTED = new Set([
  "vless", "vmess", "ss", "ssr", "trojan",
  "hysteria", "hysteria2", "hy2",
  "anytls", "tuic", "http", "https",
  "socks", "socks5", "wireguard"
]);

const PROTOCOL_ALIASES = {
  hy2: "hysteria2",
  socks: "socks5",
  https: "http"
};

const PROTOCOL_LABELS = {
  vless: "VLESS",
  vmess: "VMess",
  ss: "SS",
  ssr: "SSR",
  trojan: "Trojan",
  hysteria: "Hysteria",
  hysteria2: "Hysteria2",
  anytls: "AnyTLS",
  tuic: "TUIC",
  http: "HTTP",
  socks5: "SOCKS5",
  wireguard: "WireGuard"
};

const SINGBOX_TYPES = new Set([
  "vless", "vmess", "shadowsocks", "shadowsocksr",
  "trojan", "hysteria", "hysteria2", "tuic",
  "anytls", "wireguard", "socks", "http"
]);

function normalizeType(type) {
  const key = String(type || "").toLowerCase();
  return PROTOCOL_ALIASES[key] || key;
}

function protocolLabel(type) {
  const key = normalizeType(type);
  return PROTOCOL_LABELS[key] || String(type || "未知");
}

// ======================================
// 主解析入口
// ======================================

export function parseInput(input, maxNodes = 1000) {
  const originalText = String(input || "").trim();

  if (!originalText) {
    return emptyResult();
  }

  let nodes = [];
  let parsedText = originalText;

  // 1. 直接解析结构化内容
  nodes = parseStructured(parsedText);

  // 2. 尝试 Base64 和多层 Base64
  if (!nodes.length) {
    const decodedTexts = decodeBase64Layers(parsedText);

    for (const decoded of decodedTexts) {
      const found = parseStructured(decoded);

      if (found.length) {
        nodes = found;
        parsedText = decoded;
        break;
      }
    }
  }

  // 3. 解析明文 URI、客户端配置
  if (!nodes.length) {
    nodes = parseTextFormats(parsedText);
  }

  // 4. 如果仍未解析，尝试逐层解码后的文本
  if (!nodes.length) {
    const decodedTexts = decodeBase64Layers(originalText);

    for (const decoded of decodedTexts) {
      const found = parseTextFormats(decoded);

      if (found.length) {
        nodes = found;
        break;
      }
    }
  }

  // ======================================
  // 全量统计
  // ======================================

  const fingerprints = nodes.map(getFingerprint);
  const uniqueCount = new Set(fingerprints).size;
  const totalCount = nodes.length;
  const duplicateCount = totalCount - uniqueCount;

  const protocolCounts = {};
  const regionCounts = {};

  for (const node of nodes) {
    protocolCounts[node.type] =
      (protocolCounts[node.type] || 0) + 1;

    const r = region(node.name);

    regionCounts[r] =
      (regionCounts[r] || 0) + 1;
  }

  // ======================================
  // 限制缓存数量
  // ======================================

  let limit = Number(maxNodes);

  if (maxNodes === Infinity || limit === Infinity) {
    limit = totalCount;
  } else if (!Number.isFinite(limit)) {
    limit = 1000;
  }

  limit = Math.max(1, Math.floor(limit));

  const limitedNodes = nodes.slice(0, limit);

  return {
    nodes: limitedNodes,
    totalCount,
    parsedCount: totalCount,
    truncatedCount: Math.max(
      0,
      totalCount - limitedNodes.length
    ),
    uniqueCount,
    duplicateCount,
    protocolCounts,
    regionCounts
  };
}

function emptyResult() {
  return {
    nodes: [],
    totalCount: 0,
    parsedCount: 0,
    truncatedCount: 0,
    duplicateCount: 0,
    uniqueCount: 0,
    protocolCounts: {},
    regionCounts: {}
  };
}

// ======================================
// 统一结构化解析
// ======================================

function parseStructured(text) {
  const value = String(text || "").trim();

  if (!value) return [];

  // JSON
  const json = tryJson(value);

  if (json) {
    const singboxNodes = parseSingBox(json);

    if (singboxNodes.length) {
      return singboxNodes;
    }

    const genericNodes = parseGenericJson(json);

    if (genericNodes.length) {
      return genericNodes;
    }
  }

  // YAML
  const yaml = tryYaml(value);

  if (yaml) {
    const nodes = [];

    if (Array.isArray(yaml.proxies)) {
      for (const proxy of yaml.proxies) {
        const node = proxyToNode(proxy);

        if (node) nodes.push(node);
      }
    }

    if (nodes.length) return nodes;

    // 部分配置将节点放在 proxies 下的其他结构中
    if (yaml.proxy && Array.isArray(yaml.proxy)) {
      for (const proxy of yaml.proxy) {
        const node = proxyToNode(proxy);

        if (node) nodes.push(node);
      }
    }

    if (nodes.length) return nodes;
  }

  return [];
}

// ======================================
// JSON 解析
// ======================================

function tryJson(text) {
  const value = String(text || "").trim();

  if (!value.startsWith("{") && !value.startsWith("[")) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

// ======================================
// YAML 识别
// ======================================

function tryYaml(text) {
  const value = String(text || "").trim();

  if (!/^\s*(proxies|mixed-port|port|proxy-groups|proxy-providers|rules)\s*:/m.test(value)) {
    return null;
  }

  try {
    return YAML.parse(value);
  } catch {
    return null;
  }
}

// ======================================
// Base64 多层解码
// ======================================

function decodeBase64Layers(input, maxLayers = 3) {
  const results = [];
  let current = String(input || "").trim();

  for (let i = 0; i < maxLayers; i++) {
    const decoded = decodeBase64(current);

    if (!decoded || decoded === current) break;

    // 过滤明显不是文本的内容
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(decoded)) {
      break;
    }

    results.push(decoded);
    current = decoded.trim();

    if (
      /(?:vless|vmess|ss|ssr|trojan|hysteria|hysteria2|hy2|anytls|tuic|socks5?|wireguard):\/\//i.test(current) ||
      /^\s*(proxies|outbounds|mixed-port|port|proxy-groups)\s*:/m.test(current) ||
      current.startsWith("{")
    ) {
      // 已经是可识别内容，仍保留结果
      break;
    }
  }

  return results;
}

// ======================================
// Base64 UTF-8 解码
// ======================================

function decodeBase64(text) {
  let clean = String(text || "").trim();

  if (!clean || clean.length < 8) return null;

  // 允许换行
  clean = clean.replace(/\s/g, "");

  if (!/^[A-Za-z0-9+/_=-]+$/.test(clean)) {
    return null;
  }

  try {
    let normalized = clean
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/=+$/, "");

    if (normalized.length % 4 === 1) {
      return null;
    }

    normalized = normalized.padEnd(
      Math.ceil(normalized.length / 4) * 4,
      "="
    );

    const binary = atob(normalized);

    const bytes = Uint8Array.from(
      binary,
      c => c.charCodeAt(0)
    );

    const decoded = new TextDecoder(
      "utf-8",
      { fatal: true }
    ).decode(bytes);

    if (!decoded.trim()) return null;

    return decoded;
  } catch {
    return null;
  }
}

// ======================================
// Base64 UTF-8 编码
// ======================================

function encodeBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary);
}

// ======================================
// 稳定对象排序
// ======================================

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }

  if (value && typeof value === "object") {
    const result = {};

    for (const key of Object.keys(value).sort()) {
      if (
        key === "name" ||
        key === "tag" ||
        key === "remarks"
      ) {
        continue;
      }

      result[key] = stableValue(value[key]);
    }

    return result;
  }

  return value;
}

// ======================================
// 重复节点指纹
// ======================================

function getFingerprint(n) {
  if (n.rawProxy) {
    return (
      String(n.type || "") +
      "|" +
      JSON.stringify(stableValue(n.rawProxy))
    );
  }

  if (n.uri) {
    try {
      if (n.type === "vmess") {
        const data = { ...(n.vmessData || {}) };

        delete data.ps;

        return "vmess|" + JSON.stringify(stableValue(data));
      }

      const u = new URL(n.uri);

      u.hash = "";
      u.protocol = u.protocol.toLowerCase();
      u.hostname = u.hostname.toLowerCase();

      const params = [...u.searchParams.entries()]
        .sort((a, b) => {
          const keyCompare = a[0].localeCompare(b[0]);

          return keyCompare || a[1].localeCompare(b[1]);
        });

      u.search = "";

      for (const [key, value] of params) {
        u.searchParams.append(key, value);
      }

      return u.toString();
    } catch {
      return String(n.uri).split("#")[0];
    }
  }

  return [
    String(n.type || "").toLowerCase(),
    n.server || "",
    n.port || "",
    n.identity || "",
    n.password || "",
    n.security || "",
    n.sni || ""
  ].join("|");
}

// ======================================
// URI 判断
// ======================================

function isSupportedUri(uri) {
  const match = String(uri || "").match(
    /^([a-z0-9]+):\/\//i
  );

  return !!match && SUPPORTED.has(match[1].toLowerCase());
}

// ======================================
// URI 文本解析入口
// ======================================

function parseTextFormats(text) {
  const value = String(text || "");
  const nodes = [];

  // 1. 逐行解析标准 URI
  for (const line of value.split(/\r?\n/)) {
    const clean = line.trim();

    if (!clean) continue;

    const uriMatch = clean.match(
      /(?:vless|vmess|ss|ssr|trojan|hysteria|hysteria2|hy2|anytls|tuic|https?|socks5?|wireguard):\/\/[^\s"'<>]+/i
    );

    if (uriMatch) {
      const uri = trimUriPunctuation(uriMatch[0]);
      const node = parseUri(uri);

      if (node) nodes.push(node);
    }
  }

  if (nodes.length) return nodes;

  // 2. Surge / Loon / Quantumult X 常见配置
  const clientNodes = parseClientConfig(value);

  if (clientNodes.length) return clientNodes;

  // 3. SSR 独立 Base64 内容
  const ssrNodes = parseSsrText(value);

  if (ssrNodes.length) return ssrNodes;

  return [];
}

function trimUriPunctuation(uri) {
  return String(uri || "").replace(/[),，。；;]+$/g, "");
}

// ======================================
// VMess 解码
// ======================================

function decodeVmess(uri) {
  try {
    const raw = uri
      .slice("vmess://".length)
      .split("#")[0];

    const decoded = decodeBase64(raw);

    if (!decoded) return null;

    const j = JSON.parse(decoded);

    if (!j.add || !j.port || !j.id) return null;

    return {
      type: "vmess",
      server: String(j.add),
      port: Number(j.port),
      name: String(j.ps ?? j.add),
      identity: String(j.id),
      password: "",
      security: String(j.tls || ""),
      sni: String(j.sni || j.host || ""),
      uri,
      vmessData: j,
      rawProxy: null,
      sourceFormat: "uri"
    };
  } catch {
    return null;
  }
}

// ======================================
// SSR 解码
// ======================================

function decodeSsr(uri) {
  try {
    const raw = String(uri).slice("ssr://".length);
    const decoded = decodeBase64(raw);

    if (!decoded) return null;

    const main = decoded.split("/?")[0];

    const match = main.match(
      /^(.+):(\d+):([^:]+):([^:]+):([^:]+):(.+)$/
    );

    if (!match) return null;

    const server = match[1];
    const port = Number(match[2]);
    const protocol = safeDecode(match[3]);
    const method = safeDecode(match[4]);
    const obfs = safeDecode(match[5]);
    const password = decodeBase64(match[6]) || match[6];

    if (!server || !port || port > 65535) return null;

    const paramsPart = decoded.split("/?")[1] || "";
    const params = new URLSearchParams(paramsPart);

    const remarks = params.get("remarks");
    const name = remarks
      ? decodeBase64(remarks) || safeDecode(remarks)
      : server;

    const obfsParam = params.get("obfsparam");
    const protocolParam = params.get("protoparam");

    return {
      type: "ssr",
      server,
      port,
      name,
      identity: `${method}:${password}`,
      password,
      security: method,
      sni: "",
      uri,
      rawProxy: {
        name,
        type: "ssr",
        server,
        port,
        cipher: method,
        password,
        protocol,
        protocolparam: protocolParam
          ? decodeBase64(protocolParam) || protocolParam
          : "",
        obfs,
        obfsparam: obfsParam
          ? decodeBase64(obfsParam) || obfsParam
          : ""
      },
      sourceFormat: "uri"
    };
  } catch {
    return null;
  }
}

function parseSsrText(text) {
  const nodes = [];

  for (const line of String(text || "").split(/\r?\n/)) {
    const match = line.trim().match(/ssr:\/\/[A-Za-z0-9+/_=-]+/i);

    if (!match) continue;

    const node = decodeSsr(match[0]);

    if (node) nodes.push(node);
  }

  return nodes;
}

// ======================================
// URI 节点解析
// ======================================

function parseUri(uri) {
  try {
    const match = String(uri).match(
      /^([a-z0-9]+):\/\//i
    );

    if (!match) return null;

    let type = match[1].toLowerCase();

    if (!SUPPORTED.has(type)) return null;

    if (type === "vmess") {
      return decodeVmess(uri);
    }

    if (type === "ssr") {
      return decodeSsr(uri);
    }

    type = normalizeType(type);

    if (type === "ss" && !uri.includes("@")) {
      return parseLegacySS(uri);
    }

    // SS SIP002
    if (type === "ss") {
      return parseSsSip002(uri);
    }

    const u = new URL(uri);

    const server = u.hostname;
    const port = Number(u.port);

    if (!server || !port || port < 1 || port > 65535) {
      return null;
    }

    let name = server;

    try {
      if (u.hash.length > 1) {
        name = decodeURIComponent(u.hash.slice(1));
      }
    } catch {
      name = u.hash.slice(1);
    }

    const identity = safeDecode(u.username || "");
    const password = safeDecode(u.password || "");

    const query = Object.fromEntries(
      u.searchParams.entries()
    );

    return {
      type,
      server,
      port,
      name,
      identity,
      password,
      security: query.security || "",
      sni:
        query.sni ||
        query.peer ||
        query.servername ||
        "",
      uri,
      query,
      rawProxy: null,
      sourceFormat: "uri"
    };
  } catch {
    return null;
  }
}

// ======================================
// SS SIP002
// ======================================

function parseSsSip002(uri) {
  try {
    const u = new URL(uri);

    const server = u.hostname;
    const port = Number(u.port);

    if (!server || !port) return null;

    let userInfo = u.username;

    if (!userInfo && u.password) {
      userInfo = u.password;
    }

    let auth = safeDecode(userInfo);

    if (!auth.includes(":")) {
      auth = decodeBase64(auth) || auth;
    }

    const index = auth.indexOf(":");

    if (index < 0) return null;

    const cipher = auth.slice(0, index);
    const password = auth.slice(index + 1);

    let name = server;

    if (u.hash) {
      name = safeDecode(u.hash.slice(1));
    }

    return {
      type: "ss",
      server,
      port,
      name,
      identity: `${cipher}:${password}`,
      password: "",
      security: "",
      sni: "",
      uri,
      rawProxy: null,
      sourceFormat: "uri"
    };
  } catch {
    return null;
  }
}

// ======================================
// SS 旧格式
// ======================================

function parseLegacySS(uri) {
  try {
    const content = uri
      .slice(5)
      .split("#")[0];

    const decoded = decodeBase64(content);

    if (!decoded || !decoded.includes("@")) return null;

    const at = decoded.lastIndexOf("@");
    const auth = decoded.slice(0, at);
    const address = decoded.slice(at + 1);

    const colon = auth.indexOf(":");

    if (colon < 0) return null;

    const cipher = auth.slice(0, colon);
    const password = auth.slice(colon + 1);

    const addressMatch = address.match(
      /^(.+):(\d+)$/
    );

    if (!addressMatch) return null;

    let name = addressMatch[1];

    try {
      const hash = uri.split("#")[1];

      if (hash) name = decodeURIComponent(hash);
    } catch {
      // 保留原始名称
    }

    return {
      type: "ss",
      server: addressMatch[1],
      port: Number(addressMatch[2]),
      name,
      identity: `${cipher}:${password}`,
      password: "",
      security: "",
      sni: "",
      uri,
      rawProxy: null,
      sourceFormat: "uri"
    };
  } catch {
    return null;
  }
}

// ======================================
// URL 解码安全处理
// ======================================

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// ======================================
// Clash / Mihomo YAML 转节点
// ======================================

function proxyToNode(p) {
  if (!p || typeof p !== "object") return null;

  const type = normalizeType(p.type);

  if (!SUPPORTED.has(type)) return null;

  const server = String(p.server || "");
  const port = Number(p.port || 0);

  if (!server || !port || port < 1 || port > 65535) {
    return null;
  }

  const name = String(p.name ?? server);

  let identity = String(
    p.uuid ??
    p.password ??
    p.auth ??
    ""
  );

  let password = "";

  if (type === "http" || type === "socks5") {
    identity = String(p.username || "");
    password = String(p.password || "");
  }

  if (type === "ss" || type === "ssr") {
    identity = `${p.cipher || ""}:${p.password || ""}`;
  }

  if (type === "wireguard") {
    identity = String(
      p["private-key"] ||
      p.privateKey ||
      p.private_key ||
      ""
    );
  }

  const node = {
    type,
    server,
    port,
    name,
    identity,
    password,
    security: String(p.tls || ""),
    sni: String(
      p.servername ||
      p.sni ||
      ""
    ),
    uri: "",
    rawProxy: { ...p },
    sourceFormat: "clash"
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// Sing-box JSON 解析
// ======================================

function parseSingBox(data) {
  if (!data || typeof data !== "object") return [];

  const outbounds = Array.isArray(data.outbounds)
    ? data.outbounds
    : [];

  if (!outbounds.length) return [];

  const nodes = [];

  for (const outbound of outbounds) {
    const node = singboxOutboundToNode(outbound);

    if (node) nodes.push(node);
  }

  return nodes;
}

function singboxOutboundToNode(p) {
  if (!p || typeof p !== "object") return null;

  const originalType = String(p.type || "").toLowerCase();

  if (!SINGBOX_TYPES.has(originalType)) return null;

  const typeMap = {
    shadowsocks: "ss",
    shadowsocksr: "ssr",
    socks: "socks5"
  };

  const type = typeMap[originalType] || normalizeType(originalType);

  const server = String(p.server || "");
  const port = Number(p.server_port || p.port || 0);

  if (!server || !port || port < 1 || port > 65535) {
    return null;
  }

  const tls = p.tls || {};
  const transport = p.transport || {};

  let identity = String(
    p.uuid ||
    p.password ||
    p.auth ||
    ""
  );

  let password = "";

  if (type === "ss" || type === "ssr") {
    identity = `${p.method || p.cipher || ""}:${p.password || ""}`;
  }

  if (type === "http" || type === "socks5") {
    identity = String(p.username || "");
    password = String(p.password || "");
  }

  if (type === "wireguard") {
    identity = String(p.private_key || "");
  }

  const name = String(
    p.tag ||
    p.name ||
    server
  );

  const node = {
    type,
    server,
    port,
    name,
    identity,
    password,
    security: tls.enabled ? "tls" : "",
    sni: String(tls.server_name || ""),
    uri: "",
    rawProxy: { ...p },
    sourceFormat: "sing-box",
    singboxData: {
      tls,
      transport
    }
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// 其他 JSON 节点格式
// ======================================

function parseGenericJson(data) {
  if (!data || typeof data !== "object") return [];

  const candidates = [];

  if (Array.isArray(data.nodes)) {
    candidates.push(...data.nodes);
  }

  if (Array.isArray(data.proxies)) {
    candidates.push(...data.proxies);
  }

  if (Array.isArray(data.servers)) {
    candidates.push(...data.servers);
  }

  if (!candidates.length) return [];

  return candidates
    .map(proxyToNode)
    .filter(Boolean);
}

// ======================================
// Surge / Loon / Quantumult X
// 常见 Proxy 行解析
// ======================================

function parseClientConfig(text) {
  const lines = String(text || "").split(/\r?\n/);

  const nodes = [];
  let inProxySection = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }

    const section = line.match(/^\[([^\]]+)\]$/);

    if (section) {
      inProxySection = /^(proxy|server|servers)$/i.test(
        section[1].trim()
      );

      continue;
    }

    if (!inProxySection) {
      // Quantumult X 部分配置没有 [Proxy] 区块
      if (
        /^(shadowsocks|vmess|vless|trojan|http|socks5|hysteria2)\s*=/i.test(line)
      ) {
        const qxNode = parseQuantumultLine(line);

        if (qxNode) nodes.push(qxNode);
      }

      continue;
    }

    const node = parseCommaProxyLine(line);

    if (node) nodes.push(node);
  }

  return nodes;
}

// ======================================
// Surge / Loon 逗号配置
// name = type, server, port, key=value
// ======================================

function parseCommaProxyLine(line) {
  const index = line.indexOf("=");

  if (index < 1) return null;

  const name = line.slice(0, index).trim();
  const body = line.slice(index + 1).trim();

  if (!name || !body) return null;

  const parts = splitComma(body);

  if (parts.length < 3) return null;

  const rawType = parts[0].trim().toLowerCase();

  const typeMap = {
    "shadowsocks": "ss",
    "shadowsocksr": "ssr",
    "socks": "socks5",
    "socks5": "socks5",
    "http": "http",
    "https": "http",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2"
  };

  const type = normalizeType(
    typeMap[rawType] || rawType
  );

  if (!SUPPORTED.has(type)) return null;

  const server = parts[1].trim();
  const port = Number(parts[2]);

  if (!server || !port || port > 65535) return null;

  const options = {};

  for (const item of parts.slice(3)) {
    const i = item.indexOf("=");

    if (i < 0) {
      options[item.trim().toLowerCase()] = true;
    } else {
      options[item.slice(0, i).trim().toLowerCase()] =
        item.slice(i + 1).trim();
    }
  }

  const password = options.password || "";
  const username = options.username || "";
  const uuid = options.uuid || options.user || "";

  let identity = uuid || password;

  if (type === "ss") {
    identity = `${options.encrypt-method || options.method || options.cipher || ""}:${password}`;
  }

  if (type === "http" || type === "socks5") {
    identity = username;
  }

  const node = {
    type,
    server,
    port,
    name,
    identity,
    password:
      type === "http" || type === "socks5"
        ? password
        : "",
    security: options.tls || "",
    sni:
      options.sni ||
      options.servername ||
      options.peer ||
      "",
    uri: "",
    rawProxy: {
      name,
      type,
      server,
      port,
      ...options
    },
    sourceFormat: "surge"
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// 逗号分割，兼容引号
// ======================================

function splitComma(value) {
  const result = [];
  let current = "";
  let quote = "";
  let escaped = false;

  for (const char of String(value)) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      current += char;
      continue;
    }

    if (
      (char === '"' || char === "'") &&
      (!quote || quote === char)
    ) {
      quote = quote ? "" : char;
      continue;
    }

    if (char === "," && !quote) {
      result.push(current.trim());
      current = "";
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    result.push(current.trim());
  }

  return result;
}

// ======================================
// Quantumult X 常见节点行
// ======================================

function parseQuantumultLine(line) {
  const index = line.indexOf("=");

  if (index < 1) return null;

  const rawType = line.slice(0, index).trim().toLowerCase();
  const body = line.slice(index + 1).trim();

  const typeMap = {
    shadowsocks: "ss",
    vmess: "vmess",
    vless: "vless",
    trojan: "trojan",
    http: "http",
    socks5: "socks5",
    hysteria2: "hysteria2"
  };

  const type = typeMap[rawType];

  if (!type) return null;

  // 尝试解析 URL 形式参数
  if (body.includes("://")) {
    return parseUri(body);
  }

  const parts = splitComma(body);

  if (parts.length < 2) return null;

  const server = parts[0].trim();
  const port = Number(parts[1]);

  if (!server || !port || port > 65535) return null;

  const options = {};

  for (const item of parts.slice(2)) {
    const i = item.indexOf("=");

    if (i > 0) {
      options[item.slice(0, i).trim().toLowerCase()] =
        item.slice(i + 1).trim();
    }
  }

  const name =
    options.tag ||
    options.remarks ||
    options.name ||
    server;

  const identity =
    options.password ||
    options.uuid ||
    options.user ||
    "";

  const node = {
    type,
    server,
    port,
    name,
    identity,
    password: options.password || "",
    security: options.tls || "",
    sni: options.peer || options.sni || "",
    uri: "",
    rawProxy: {
      name,
      type,
      server,
      port,
      ...options
    },
    sourceFormat: "quantumult-x"
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// 节点转 URI
// ======================================

function buildNodeUri(n) {
  const enc = value =>
    encodeURIComponent(String(value ?? ""));

  const p = n.rawProxy || {};

  const server = n.server;
  const port = n.port;
  const name = enc(n.name);

  if (!server || !port) return "";

  if (n.type === "vmess") {
    const j = {
      v: "2",
      ps: n.name,
      add: server,
      port: String(port),
      id: p.uuid || n.identity,
      aid: String(p.alterId ?? p.alter_id ?? 0),
      scy: p.cipher || p.security || "auto",
      net: p.network || "tcp",
      tls: p.tls ? "tls" : "",
      sni: p.servername || p.sni || n.sni || ""
    };

    return "vmess://" + encodeBase64(JSON.stringify(j));
  }

  if (n.type === "ss") {
    const identity = String(n.identity || "");
    const index = identity.indexOf(":");

    const cipher = index >= 0
      ? identity.slice(0, index)
      : p.cipher || "aes-128-gcm";

    const password = index >= 0
      ? identity.slice(index + 1)
      : p.password || "";

    const auth = encodeBase64(
      `${cipher}:${password}`
    );

    return `ss://${auth}@${server}:${port}#${name}`;
  }

  if (n.type === "ssr") {
    return "";
  }

  if (n.type === "http" || n.type === "socks5") {
    const username = n.identity || p.username || "";
    const password = n.password || p.password || "";

    let auth = "";

    if (username || password) {
      auth = `${enc(username)}:${enc(password)}@`;
    }

    return `${n.type}://${auth}${server}:${port}#${name}`;
  }

  if (n.type === "wireguard") {
    return "";
  }

  const scheme = n.type === "hysteria2"
    ? "hysteria2"
    : n.type;

  const user =
    p.uuid ||
    p.password ||
    p.auth ||
    n.identity ||
    "";

  const auth = user ? `${enc(user)}@` : "";

  const q = new URLSearchParams();

  if (p.sni || p.servername || n.sni) {
    q.set(
      "sni",
      p.sni || p.servername || n.sni
    );
  }

  if (p.encryption) q.set("encryption", p.encryption);
  if (p.flow) q.set("flow", p.flow);
  if (p.fingerprint) q.set("fp", p.fingerprint);

  if (p.network) q.set("type", p.network);
  if (p.alpn) {
    q.set(
      "alpn",
      Array.isArray(p.alpn)
        ? p.alpn.join(",")
        : p.alpn
    );
  }

  if (p.skipCertVerify) q.set("insecure", "1");

  const query = q.toString();

  return (
    `${scheme}://${auth}${server}:${port}` +
    `${query ? "?" + query : ""}#${name}`
  );
}

// ======================================
// 全球国家和地区名称 / ISO 代码
// ======================================

const REGION_DATA = `
阿富汗|AF|Afghanistan
阿尔巴尼亚|AL|Albania
阿尔及利亚|DZ|Algeria
安道尔|AD|Andorra
安哥拉|AO|Angola
安提瓜和巴布达|AG|Antigua and Barbuda
阿根廷|AR|Argentina
亚美尼亚|AM|Armenia
澳大利亚|AU|Australia
奥地利|AT|Austria
阿塞拜疆|AZ|Azerbaijan
巴哈马|BS|Bahamas
巴林|BH|Bahrain
孟加拉国|BD|Bangladesh
巴巴多斯|BB|Barbados
白俄罗斯|BY|Belarus
比利时|BE|Belgium
伯利兹|BZ|Belize
贝宁|BJ|Benin
不丹|BT|Bhutan
玻利维亚|BO|Bolivia
波黑|BA|Bosnia and Herzegovina,Bosnia
博茨瓦纳|BW|Botswana
巴西|BR|Brazil
文莱|BN|Brunei
保加利亚|BG|Bulgaria
布基纳法索|BF|Burkina Faso
布隆迪|BI|Burundi
佛得角|CV|Cape Verde,Cabo Verde
柬埔寨|KH|Cambodia
喀麦隆|CM|Cameroon
加拿大|CA|Canada
中非|CF|Central African Republic
乍得|TD|Chad
智利|CL|Chile
中国|CN|China
哥伦比亚|CO|Colombia
科摩罗|KM|Comoros
刚果（金）|CD|DR Congo,Democratic Republic of the Congo
刚果（布）|CG|Republic of the Congo,Congo
哥斯达黎加|CR|Costa Rica
科特迪瓦|CI|Ivory Coast,Cote d'Ivoire
克罗地亚|HR|Croatia
古巴|CU|Cuba
塞浦路斯|CY|Cyprus
捷克|CZ|Czechia,Czech Republic
丹麦|DK|Denmark
吉布提|DJ|Djibouti
多米尼克|DM|Dominica
多米尼加|DO|Dominican Republic
厄瓜多尔|EC|Ecuador
埃及|EG|Egypt
萨尔瓦多|SV|El Salvador
赤道几内亚|GQ|Equatorial Guinea
厄立特里亚|ER|Eritrea
爱沙尼亚|EE|Estonia
斯威士兰|SZ|Eswatini
埃塞俄比亚|ET|Ethiopia
斐济|FJ|Fiji
芬兰|FI|Finland
法国|FR|France,巴黎
加蓬|GA|Gabon
冈比亚|GM|Gambia
格鲁吉亚|GE|Georgia
德国|DE|Germany,法兰克福
加纳|GH|Ghana
希腊|GR|Greece
格林纳达|GD|Grenada
危地马拉|GT|Guatemala
几内亚|GN|Guinea
几内亚比绍|GW|Guinea-Bissau
圭亚那|GY|Guyana
海地|HT|Haiti
洪都拉斯|HN|Honduras
匈牙利|HU|Hungary
冰岛|IS|Iceland
印度|IN|India
印度尼西亚|ID|Indonesia
伊朗|IR|Iran
伊拉克|IQ|Iraq
爱尔兰|IE|Ireland
以色列|IL|Israel
意大利|IT|Italy
牙买加|JM|Jamaica
日本|JP|Japan,日本东京,东京,大阪
约旦|JO|Jordan
哈萨克斯坦|KZ|Kazakhstan
肯尼亚|KE|Kenya
基里巴斯|KI|Kiribati
朝鲜|KP|North Korea
韩国|KR|South Korea,Korea,首尔
科威特|KW|Kuwait
吉尔吉斯斯坦|KG|Kyrgyzstan
老挝|LA|Laos
拉脱维亚|LV|Latvia
黎巴嫩|LB|Lebanon
莱索托|LS|Lesotho
利比里亚|LR|Liberia
利比亚|LY|Libya
列支敦士登|LI|Liechtenstein
立陶宛|LT|Lithuania
卢森堡|LU|Luxembourg
马达加斯加|MG|Madagascar
马拉维|MW|Malawi
马来西亚|MY|Malaysia
马尔代夫|MV|Maldives
马里|ML|Mali
马耳他|MT|Malta
马绍尔群岛|MH|Marshall Islands
毛里塔尼亚|MR|Mauritania
毛里求斯|MU|Mauritius
墨西哥|MX|Mexico
密克罗尼西亚|FM|Micronesia
摩尔多瓦|MD|Moldova
摩纳哥|MC|Monaco
蒙古|MN|Mongolia
黑山|ME|Montenegro
摩洛哥|MA|Morocco
莫桑比克|MZ|Mozambique
缅甸|MM|Myanmar,Burma
纳米比亚|NA|Namibia
瑙鲁|NR|Nauru
尼泊尔|NP|Nepal
荷兰|NL|Netherlands,阿姆斯特丹
新西兰|NZ|New Zealand
尼加拉瓜|NI|Nicaragua
尼日尔|NE|Niger
尼日利亚|NG|Nigeria
北马其顿|MK|North Macedonia
挪威|NO|Norway
阿曼|OM|Oman
巴基斯坦|PK|Pakistan
帕劳|PW|Palau
巴勒斯坦|PS|Palestine
巴拿马|PA|Panama
巴布亚新几内亚|PG|Papua New Guinea
巴拉圭|PY|Paraguay
秘鲁|PE|Peru
菲律宾|PH|Philippines
波兰|PL|Poland
葡萄牙|PT|Portugal
卡塔尔|QA|Qatar
罗马尼亚|RO|Romania
俄罗斯|RU|Russia
卢旺达|RW|Rwanda
圣基茨和尼维斯|KN|Saint Kitts and Nevis
圣卢西亚|LC|Saint Lucia
圣文森特和格林纳丁斯|VC|Saint Vincent and the Grenadines
萨摩亚|WS|Samoa
圣马力诺|SM|San Marino
圣多美和普林西比|ST|Sao Tome and Principe
沙特阿拉伯|SA|Saudi Arabia
塞内加尔|SN|Senegal
塞尔维亚|RS|Serbia
塞舌尔|SC|Seychelles
塞拉利昂|SL|Sierra Leone
新加坡|SG|Singapore,狮城
斯洛伐克|SK|Slovakia
斯洛文尼亚|SI|Slovenia
所罗门群岛|SB|Solomon Islands
索马里|SO|Somalia
南非|ZA|South Africa
南苏丹|SS|South Sudan
西班牙|ES|Spain
斯里兰卡|LK|Sri Lanka
苏丹|SD|Sudan
苏里南|SR|Suriname
瑞典|SE|Sweden
瑞士|CH|Switzerland
叙利亚|SY|Syria
塔吉克斯坦|TJ|Tajikistan
坦桑尼亚|TZ|Tanzania
泰国|TH|Thailand
东帝汶|TL|Timor-Leste
多哥|TG|Togo
汤加|TO|Tonga
特立尼达和多巴哥|TT|Trinidad and Tobago
突尼斯|TN|Tunisia
土耳其|TR|Turkey,Türkiye
土库曼斯坦|TM|Turkmenistan
图瓦卢|TV|Tuvalu
乌干达|UG|Uganda
乌克兰|UA|Ukraine
阿联酋|AE|United Arab Emirates,UAE
英国|GB|United Kingdom,UK,伦敦
美国|US|United States,USA,US,洛杉矶,硅谷,纽约
乌拉圭|UY|Uruguay
乌兹别克斯坦|UZ|Uzbekistan
瓦努阿图|VU|Vanuatu
梵蒂冈|VA|Vatican
委内瑞拉|VE|Venezuela
越南|VN|Vietnam
也门|YE|Yemen
赞比亚|ZM|Zambia
津巴布韦|ZW|Zimbabwe
香港|HK|Hong Kong,香港特别行政区
澳门|MO|Macau,Macao,澳门特别行政区
台湾|TW|Taiwan,台湾地区,台北
科索沃|XK|Kosovo
`;

const REGION_MAP = [];
const REGION_BY_NAME = new Map();

for (const line of REGION_DATA.trim().split("\n")) {
  const [name, code, aliasText = ""] = line.split("|");

  const aliases = [
    name,
    ...aliasText.split(",")
  ].filter(Boolean);

  const item = { name, code, aliases };

  REGION_MAP.push(item);

  for (const alias of aliases) {
    REGION_BY_NAME.set(alias.toLowerCase(), item);
  }
}

const REGION_MATCHERS = REGION_MAP
  .flatMap(item =>
    item.aliases.map(alias => ({
      alias,
      item
    }))
  )
  .sort((a, b) => b.alias.length - a.alias.length);

// ======================================
// 地区识别
// 只根据节点备注文字识别
// ======================================

function region(name) {
  const original = String(name || "").trim();

  if (!original) return "未知";

  const s = original.toLowerCase();

  for (const entry of REGION_MATCHERS) {
    const alias = entry.alias.toLowerCase();

    if (/[a-z]/i.test(alias)) {
      const escaped = alias.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      const re = new RegExp(
        `(^|[^a-z])${escaped}([^a-z]|$)`,
        "i"
      );

      if (re.test(s)) return entry.item.name;
    } else if (s.includes(alias)) {
      return entry.item.name;
    }
  }

  for (const item of REGION_MAP) {
    const re = new RegExp(
      `(^|[^a-z])${item.code.toLowerCase()}([^a-z]|$)`,
      "i"
    );

    if (re.test(s)) return item.name;
  }

  return "未知";
}

// ======================================
// 国旗
// ======================================

function flag(r) {
  const item = REGION_BY_NAME.get(
    String(r || "").trim().toLowerCase()
  );

  if (!item) return "🌐";

  return [...item.code].map(char =>
    String.fromCodePoint(127397 + char.charCodeAt(0))
  ).join("");
}

// ======================================
// HTML 转义
// ======================================

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"]/g,
    c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[c])
  );
}

// ======================================
// 机场名称
// ======================================

function getAirportName(sourceUrl) {
  if (!sourceUrl) return "文本/文件解析";

  try {
    const u = new URL(sourceUrl);
    const parts = u.pathname.split("/").filter(Boolean);

    if (parts.length) {
      return safeDecode(parts[parts.length - 1]);
    }

    return u.hostname;
  } catch {
    return "未知";
  }
}

// ======================================
// 流量与过期信息
// ======================================

function parseUserinfo(value) {
  if (!value) return null;

  const v = {};

  for (const part of String(value).split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const key = part.slice(0, index).trim().toLowerCase();
    const val = part.slice(index + 1).trim();

    v[key] = val;
  }

  const upload = Number(v.upload || 0);
  const download = Number(v.download || 0);
  const total = Number(v.total || 0);
  const expire = Number(v.expire || 0);

  const used = upload + download;

  let expireText = "未知";

  if (Number.isFinite(expire) && expire > 0) {
    const date = new Date(expire * 1000);

    if (!Number.isNaN(date.getTime())) {
      expireText = date.toISOString().slice(0, 10);
    }
  }

  return {
    upload: fmt(upload),
    download: fmt(download),
    used: fmt(used),
    total: total > 0 ? fmt(total) : "未知",
    remaining: total > 0
      ? fmt(Math.max(0, total - used))
      : "未知",
    expire: expireText
  };
}

// ======================================
// 流量格式化
// ======================================

function fmt(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;

  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }

  return n.toFixed(2) + " " + units[i];
}

// ======================================
// 解析结果展示
// ======================================

export function renderResult(p, nodeLimit = 20) {
  const nodes = p.nodes || [];

  const limit = Math.max(
    0,
    Math.floor(Number(nodeLimit) || 20)
  );

  const protocols = p.protocolCounts || {};
  const regions = p.regionCounts || {};

  // 兼容旧缓存
  if (!p.protocolCounts || !p.regionCounts) {
    for (const n of nodes) {
      if (!p.protocolCounts) {
        protocols[n.type] =
          (protocols[n.type] || 0) + 1;
      }

      if (!p.regionCounts) {
        const r = region(n.name);

        regions[r] =
          (regions[r] || 0) + 1;
      }
    }
  }

  const fingerprints = new Set(
    nodes.map(getFingerprint)
  );

  const duplicateCount =
    p.duplicateCount ??
    (nodes.length - fingerprints.size);

  const uniqueCount =
    p.uniqueCount ??
    fingerprints.size;

  const totalCount =
    p.totalCount ??
    nodes.length;

  const parsedCount =
    p.parsedCount ??
    totalCount;

  const truncatedCount =
    p.truncatedCount ??
    Math.max(0, parsedCount - nodes.length);

  // 流量信息
  const info = parseUserinfo(
    p.headers?.userinfo ||
    p.headers?.["subscription-userinfo"] ||
    p.headers?.["Subscription-Userinfo"]
  );

  // 地区统计
  const regionEntries = Object.entries(regions)
    .sort((a, b) => b[1] - a[1]);

  const regionTotal = regionEntries.length;

  const regionText = regionEntries
    .map(([name, count]) => {
      return `${flag(name)}${escapeHtml(name)}${count}`;
    })
    .join(" ");

  // 协议类型
  const protocolNames = [...new Set(
    Object.keys(protocols).map(protocolLabel)
  )];

  const protocolText = protocolNames.length
    ? protocolNames.map(escapeHtml).join("、")
    : "未知";

  // 订阅链接
  let subscriptionText = "未提供";

  if (p.sourceUrl) {
    try {
      const url = new URL(p.sourceUrl);

      if (
        url.protocol === "http:" ||
        url.protocol === "https:"
      ) {
        subscriptionText =
          `<a href="${escapeHtml(url.href)}">点击查看原始订阅链接</a>`;
      } else {
        subscriptionText = escapeHtml(p.sourceUrl);
      }
    } catch {
      subscriptionText = escapeHtml(p.sourceUrl);
    }
  }

  // 机场名称
  const airportName = escapeHtml(
    getAirportName(p.sourceUrl)
  );

  // 节点列表
  const visibleNodes = nodes.slice(0, limit);

  const hiddenCachedCount = Math.max(
    0,
    nodes.length - visibleNodes.length
  );

  const nodeLines = visibleNodes.map((n, index) => {
    const r = region(n.name);
    const regionFlag = flag(r);

    let name = String(n.name || "");

    if (
      r !== "未知" &&
      name.startsWith(regionFlag)
    ) {
      name = name
        .slice(regionFlag.length)
        .trimStart();
    }

    const separator = r === "未知" ? "" : " ";

    return (
      `${index + 1}. ${regionFlag}` +
      `${escapeHtml(protocolLabel(n.type))}` +
      `${separator}` +
      `${escapeHtml(name)}`
    );
  });

  // 组装消息
  const lines = [
    "📡 <b>订阅解析报告</b>",
    "<i>SUBSCRIPTION ANALYSIS</i>",
    "────────────",
    "💳 <b>流量信息</b>",
    `总流量：<b>${info?.total || "未知"}</b>`,
    `已用流量：<b>${info?.used || "未知"}</b>`,
    `剩余流量：<b>${info?.remaining || "未知"}</b>`,
    `到期时间：<b>${info?.expire || "未知"}</b>`,
    "────────────",
    "📦 <b>订阅信息</b>",
    `机场名称：<b>${airportName}</b>`,
    `订阅链接：${subscriptionText}`,
    "────────────",
    "📊 <b>节点概况</b>",
    `节点总数：<b>${totalCount}</b>`,
    `唯一节点：<b>${uniqueCount}</b>`,
    `重复节点：<b>${duplicateCount}</b>`,
    `地区数量：<b>${regionTotal}</b>`,
    "────────────",
    "🔌 <b>协议类型</b>",
    protocolText,
    "────────────",
    "🌍 <b>地区分布</b>",
    regionText || "🌐未知0",
    "────────────",
    `📋 <b>节点列表</b> ${visibleNodes.length}/${totalCount}`
  ];

  if (nodeLines.length) {
    lines.push(...nodeLines);
  } else {
    lines.push("暂无可显示节点");
  }

  if (hiddenCachedCount > 0) {
    lines.push(
      `还有 <b>${hiddenCachedCount}</b> 个已缓存节点未显示`
    );
  }

  if (truncatedCount > 0) {
    lines.push(
      `⚠️ 另有 <b>${truncatedCount}</b> 个节点未载入缓存`,
      "导出完整内容时需要重新解析原始订阅"
    );
  }

  lines.push(
    "────────────",
    "<i>解析完成 · 节点名称保留原始内容</i>"
  );

  return lines.join("\n");
}

// ======================================
// Base64 导出
// ======================================

export function exportBase64(nodes) {
  const text = (nodes || [])
    .map(n => n.uri)
    .filter(Boolean)
    .join("\n");

  return encodeBase64(text);
}

// ======================================
// Sing-box 转 Clash 节点
// ======================================

function singboxToClash(n) {
  const p = n.rawProxy || {};
  const tls = p.tls || {};
  const transport = p.transport || {};

  const result = {
    name: n.name,
    type: n.type,
    server: n.server,
    port: n.port
  };

  if (n.type === "vless" || n.type === "vmess") {
    result.uuid = p.uuid || n.identity;
  }

  if (
    n.type === "trojan" ||
    n.type === "hysteria" ||
    n.type === "hysteria2" ||
    n.type === "anytls"
  ) {
    result.password = p.password || n.identity;
  }

  if (n.type === "tuic") {
    result.uuid = p.uuid || n.identity;
    result.password = p.password || "";
  }

  if (n.type === "ss" || n.type === "ssr") {
    result.cipher = p.method || p.cipher || "";
    result.password = p.password || "";
  }

  if (n.type === "http" || n.type === "socks5") {
    if (p.username) result.username = p.username;
    if (p.password) result.password = p.password;
  }

  if (n.type === "wireguard") {
    result["private-key"] =
      p.private_key ||
      p.privateKey ||
      "";

    result.public_key =
      p.peer_public_key ||
      p.public_key ||
      "";

    result.ip = p.local_address || p.address || [];
    result.ipv6 = p.local_address || [];
    result.mtu = p.mtu || 1280;
  }

  if (tls.enabled) {
    result.tls = true;

    if (tls.server_name) {
      result.servername = tls.server_name;
    }

    if (tls.insecure) {
      result["skip-cert-verify"] = true;
    }

    if (tls.alpn) {
      result.alpn = tls.alpn;
    }

    if (tls.utls?.fingerprint) {
      result["client-fingerprint"] =
        tls.utls.fingerprint;
    }
  }

  if (transport.type) {
    result.network = transport.type;

    if (transport.type === "ws") {
      result["ws-opts"] = {
        path: transport.path || "/",
        headers: transport.headers || {}
      };
    }

    if (transport.type === "grpc") {
      result["grpc-opts"] = {
        "grpc-service-name":
          transport.service_name || ""
      };
    }
  }

  if (p.flow) result.flow = p.flow;
  if (p.alter_id !== undefined) result.alterId = p.alter_id;
  if (p.packet_encoding) result["packet-encoding"] = p.packet_encoding;

  return result;
}

// ======================================
// URI / Clash 节点转 Clash YAML
// ======================================

function nodeToClash(n) {
  if (!n) return null;

  // 原生 Clash 配置：完整保留原字段
  if (
    n.rawProxy &&
    n.sourceFormat === "clash"
  ) {
    return {
      ...n.rawProxy,
      name: n.name
    };
  }

  // Sing-box 配置：转换字段
  if (
    n.rawProxy &&
    n.sourceFormat === "sing-box"
  ) {
    return singboxToClash(n);
  }

  // Surge / Quantumult X：使用已识别字段
  if (
    n.rawProxy &&
    (
      n.sourceFormat === "surge" ||
      n.sourceFormat === "quantumult-x"
    )
  ) {
    const p = n.rawProxy;

    const result = {
      name: n.name,
      type: n.type,
      server: n.server,
      port: n.port
    };

    if (n.type === "vless" || n.type === "vmess") {
      result.uuid = p.uuid || p.user || n.identity;
    }

    if (
      n.type === "trojan" ||
      n.type === "hysteria" ||
      n.type === "hysteria2" ||
      n.type === "anytls"
    ) {
      result.password = p.password || n.identity;
    }

    if (n.type === "ss") {
      const index = String(n.identity).indexOf(":");

      if (index >= 0) {
        result.cipher = n.identity.slice(0, index);
        result.password = n.identity.slice(index + 1);
      }
    }

    if (n.type === "http" || n.type === "socks5") {
      if (n.identity) result.username = n.identity;
      if (n.password) result.password = n.password;
    }

    if (n.sni) {
      result.servername = n.sni;
      result.tls = true;
    }

    return result;
  }

  const p = {
    name: n.name,
    type: n.type,
    server: n.server,
    port: n.port
  };

  const identity = n.identity || "";

  if (n.type === "vless" || n.type === "vmess") {
    p.uuid = identity;
  }

  if (
    n.type === "trojan" ||
    n.type === "anytls"
  ) {
    p.password = identity;
  }

  if (
    n.type === "hysteria" ||
    n.type === "hysteria2"
  ) {
    p.password = identity;
  }

  if (n.type === "tuic") {
    p.uuid = identity;
    if (n.password) p.password = n.password;
  }

  if (n.type === "ss") {
    const index = identity.indexOf(":");

    if (index > 0) {
      p.cipher = identity.slice(0, index);
      p.password = identity.slice(index + 1);
    }
  }

  if (n.type === "http" || n.type === "socks5") {
    if (identity) p.username = identity;
    if (n.password) p.password = n.password;
  }

  if (n.sni) {
    p.servername = n.sni;
    p.tls = true;
  }

  if (n.query?.flow) p.flow = n.query.flow;

  return p;
}

// ======================================
// Clash YAML 导出
// ======================================

export function exportYaml(nodes) {
  const proxies = (nodes || [])
    .map(nodeToClash)
    .filter(Boolean);

  const proxyNames = proxies.map(x => x.name);

  return YAML.stringify({
    "mixed-port": 7890,
    "allow-lan": false,
    mode: "rule",
    "log-level": "warning",
    proxies,
    "proxy-groups": [
      {
        name: "节点选择",
        type: "select",
        proxies: proxyNames
      }
    ],
    rules: [
      "MATCH,节点选择"
    ]
  });
}
