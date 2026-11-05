import YAML from "yaml";

// ======================================
// 支持的协议
// ======================================

const SUPPORTED = new Set([
  "vless", "vmess", "ss", "ssr", "trojan",
  "hysteria", "hysteria2", "hy2",
  "anytls", "tuic", "http", "socks", "socks5",
  "mieru", "mierus", "wireguard", "wg"
]);

const PROTOCOL_ALIASES = {
  hy2: "hysteria2",
  socks: "socks5",
  wg: "wireguard",
  mierus: "mieru"
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
  mieru: "Mieru",
  wireguard: "WireGuard"
};

function protocolLabel(type) {
  const key = String(type || "").toLowerCase();
  return PROTOCOL_LABELS[key] || String(type || "未知");
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

function normalizeType(type) {
  const key = String(type || "").toLowerCase();
  return PROTOCOL_ALIASES[key] || key;
}

function validPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535
    ? port
    : 0;
}

// ======================================
// 主解析入口
// ======================================

export function parseInput(input, maxNodes = 1000) {
  let text = String(input || "").replace(/^\uFEFF/, "").trim();

  if (!text) return emptyResult();

  let nodes = [];

  // 1. JSON：Sing-box 等
  const json = tryJson(text);

  if (json) {
    if (Array.isArray(json.outbounds)) {
      nodes = parseSingbox(json);
    } else if (Array.isArray(json.proxies)) {
      nodes = json.proxies.map(proxyToNode).filter(Boolean);
    }
  }

  // 2. YAML：Clash / Mihomo
  if (!nodes.length) {
    const yaml = tryYaml(text);

    if (yaml && Array.isArray(yaml.proxies)) {
      nodes = yaml.proxies.map(proxyToNode).filter(Boolean);
    }
  }

  // 3. Base64 多层解码
  if (!nodes.length) {
    const decoded = decodeSubscription(text);

    if (decoded) text = decoded;
  }

  // 4. 解码后再次检查 JSON
  if (!nodes.length) {
    const json = tryJson(text);

    if (json && Array.isArray(json.outbounds)) {
      nodes = parseSingbox(json);
    } else if (json && Array.isArray(json.proxies)) {
      nodes = json.proxies.map(proxyToNode).filter(Boolean);
    }
  }

  // 5. 解码后再次检查 YAML
  if (!nodes.length) {
    const yaml = tryYaml(text);

    if (yaml && Array.isArray(yaml.proxies)) {
      nodes = yaml.proxies.map(proxyToNode).filter(Boolean);
    }
  }

  // 6. Surge / Loon / Quantumult X 常见文本
  if (!nodes.length) {
    nodes = parseConfigText(text);
  }

  // 7. URI 列表
  if (!nodes.length) {
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();

      if (!value || value.startsWith("#") || value.startsWith(";")) {
        continue;
      }

      if (!isSupportedUri(value)) continue;

      const node = parseUri(value);

      if (node) nodes.push(node);
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

  if (maxNodes === Infinity) {
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
    truncatedCount: Math.max(0, totalCount - limitedNodes.length),
    uniqueCount,
    duplicateCount,
    protocolCounts,
    regionCounts
  };
}

// ======================================
// JSON 识别
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

  if (!/^(?:proxies|mixed-port|port|proxy-groups|rules|dns)\s*:/m.test(value)) {
    return null;
  }

  try {
    const parsed = YAML.parse(value);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

// ======================================
// Base64 解码
// ======================================

function decodeBase64(text) {
  const clean = String(text || "").replace(/\s/g, "");

  if (
    !clean ||
    !/^[A-Za-z0-9+/_=-]+$/.test(clean) ||
    clean.length < 8
  ) {
    return null;
  }

  try {
    let normalized = clean
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/=+$/, "");

    if (normalized.length % 4 === 1) return null;

    normalized += "=".repeat(
      (4 - normalized.length % 4) % 4
    );

    const binary = atob(normalized);

    const bytes = Uint8Array.from(
      binary,
      c => c.charCodeAt(0)
    );

    const result = new TextDecoder("utf-8", {
      fatal: true
    }).decode(bytes);

    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(result)) {
      return null;
    }

    return result;
  } catch {
    return null;
  }
}

// ======================================
// 多层 Base64 订阅解码
// ======================================

function looksLikeConfig(text) {
  const value = String(text || "").trim();

  return (
    /^(?:vless|vmess|ss|ssr|trojan|hysteria|hysteria2|hy2|anytls|tuic|http|socks5|mieru|mierus|wireguard|wg):\/\//im.test(value) ||
    /^\s*(?:proxies|outbounds)\s*[:{]/m.test(value) ||
    /^\s*\[Proxy\]/im.test(value) ||
    /^\s*\[General\]/im.test(value) ||
    /^\s*\[节点\]/im.test(value)
  );
}

function decodeSubscription(input) {
  let current = String(input || "").trim();

  for (let i = 0; i < 4; i++) {
    if (looksLikeConfig(current)) return current;

    const decoded = decodeBase64(current);

    if (!decoded || decoded === current) break;

    current = decoded.trim();
  }

  return current;
}

// ======================================
// Base64 编码
// ======================================

function encodeBase64(text) {
  const bytes = new TextEncoder().encode(String(text || ""));
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

// ======================================
// URI 判断
// ======================================

function isSupportedUri(uri) {
  const match = String(uri).match(/^([a-z0-9]+):\/\//i);

  return !!match && SUPPORTED.has(match[1].toLowerCase());
}

// ======================================
// 安全解码
// ======================================

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    return String(value || "");
  }
}

function safeBase64Decode(value) {
  const decoded = decodeBase64(value);
  return decoded || "";
}

// ======================================
// VMess 解析
// ======================================

function decodeVmess(uri) {
  try {
    const raw = uri.slice("vmess://".length).split("#")[0];
    const decoded = decodeBase64(raw);

    if (!decoded) return null;

    const j = JSON.parse(decoded);

    if (!j.add || !j.port || !j.id) return null;

    const port = validPort(j.port);

    if (!port) return null;

    return {
      type: "vmess",
      server: String(j.add),
      port,
      name: String(j.ps ?? j.add),
      identity: String(j.id),
      password: "",
      security: String(j.tls || ""),
      sni: String(j.sni || j.host || ""),
      uri,
      vmessData: j,
      rawProxy: null,
      params: {}
    };
  } catch {
    return null;
  }
}

// ======================================
// SS SIP002 / 旧格式解析
// ======================================

function parseSS(uri) {
  try {
    const body = uri.slice("ss://".length);
    const hashIndex = body.indexOf("#");

    const rawBody = hashIndex >= 0
      ? body.slice(0, hashIndex)
      : body;

    const rawName = hashIndex >= 0
      ? body.slice(hashIndex + 1)
      : "";

    let name = rawName ? safeDecode(rawName) : "";

    // SIP002：ss://base64(method:password)@server:port
    if (rawBody.includes("@")) {
      const at = rawBody.lastIndexOf("@");

      let auth = rawBody.slice(0, at);
      const address = rawBody.slice(at + 1);

      let decodedAuth = auth;

      if (!auth.includes(":")) {
        decodedAuth = decodeBase64(auth) || auth;
      } else {
        decodedAuth = safeDecode(auth);
      }

      const colon = decodedAuth.indexOf(":");

      if (colon < 1) return null;

      const cipher = decodedAuth.slice(0, colon);
      const password = decodedAuth.slice(colon + 1);

      const addressUrl = new URL("ss://" + address);
      const server = addressUrl.hostname;
      const port = validPort(addressUrl.port);

      if (!server || !port) return null;

      if (!name) name = server;

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
        params: {}
      };
    }

    // 旧格式：ss://base64(method:password@server:port)
    const decoded = decodeBase64(rawBody);

    if (!decoded || !decoded.includes("@")) return null;

    const at = decoded.lastIndexOf("@");
    const auth = decoded.slice(0, at);
    const address = decoded.slice(at + 1);
    const colon = auth.indexOf(":");

    if (colon < 1) return null;

    const cipher = auth.slice(0, colon);
    const password = auth.slice(colon + 1);

    const addressUrl = new URL("ss://" + address);
    const server = addressUrl.hostname;
    const port = validPort(addressUrl.port);

    if (!server || !port) return null;

    if (!name) name = server;

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
      params: {}
    };
  } catch {
    return null;
  }
}

// ======================================
// SSR 解析
// ======================================

function parseSSR(uri) {
  try {
    const raw = uri.slice("ssr://".length).split("#")[0];
    const decoded = decodeBase64(raw);

    if (!decoded) return null;

    const slashIndex = decoded.indexOf("/?");
    const main = slashIndex >= 0
      ? decoded.slice(0, slashIndex)
      : decoded;

    const queryText = slashIndex >= 0
      ? decoded.slice(slashIndex + 2)
      : "";

    const fields = main.split(":");

    if (fields.length < 6) return null;

    const server = fields[0];
    const port = validPort(fields[1]);
    const protocol = fields[2];
    const method = fields[3];
    const obfs = fields[4];
    const password = safeBase64Decode(fields.slice(5).join(":"));

    if (!server || !port || !method || !password) return null;

    const params = new URLSearchParams(queryText);

    let name = server;

    const hashIndex = uri.indexOf("#");

    if (hashIndex >= 0) {
      name = safeDecode(uri.slice(hashIndex + 1));
    } else if (params.get("remarks")) {
      name = safeBase64Decode(params.get("remarks")) ||
        safeDecode(params.get("remarks"));
    }

    const ssrData = {
      protocol,
      obfs,
      params: Object.fromEntries(params.entries())
    };

    return {
      type: "ssr",
      server,
      port,
      name,
      identity: `${method}:${password}`,
      password,
      security: obfs,
      sni: "",
      uri,
      rawProxy: null,
      ssrData,
      params: {}
    };
  } catch {
    return null;
  }
}

// ======================================
// Mieru 简单分享链接
// ======================================

function parseMierus(uri) {
  try {
    const u = new URL(uri);

    const server = u.hostname;
    if (!server) return null;

    const username = safeDecode(u.username);
    const password = safeDecode(u.password);

    const ports = u.searchParams.getAll("port");
    const protocols = u.searchParams.getAll("protocol");

    const name =
      safeDecode(u.searchParams.get("profile") || "") ||
      safeDecode(u.hash.slice(1)) ||
      server;

    const validPorts = ports
      .map(validPort)
      .filter(Boolean);

    const port = validPorts[0] || 0;

    return {
      type: "mieru",
      server,
      port,
      name,
      identity: username,
      password,
      security: "",
      sni: "",
      uri,
      rawProxy: null,
      mieruData: {
        profile: name,
        ports,
        protocols,
        transport: protocols[0] || "TCP",
        multiplexing: u.searchParams.get("multiplexing") || "",
        handshakeMode: u.searchParams.get("handshake-mode") || "",
        mtu: u.searchParams.get("mtu") || "",
        trafficPattern: u.searchParams.get("traffic-pattern") || ""
      },
      params: {}
    };
  } catch {
    return null;
  }
}

// ======================================
// 通用 URI 节点解析
// ======================================

function parseUri(uri) {
  try {
    const match = String(uri).match(/^([a-z0-9]+):\/\//i);

    if (!match) return null;

    let type = match[1].toLowerCase();

    if (!SUPPORTED.has(type)) return null;

    // Mieru 标准分享链接是 Protobuf 配置，不按普通 URL 解析
    if (type === "mieru") {
      return {
        type: "mieru",
        server: "",
        port: 0,
        name: "Mieru配置",
        identity: "",
        password: "",
        security: "",
        sni: "",
        uri,
        rawProxy: null,
        opaque: true,
        params: {}
      };
    }

    if (type === "vmess") return decodeVmess(uri);
    if (type === "ss") return parseSS(uri);
    if (type === "ssr") return parseSSR(uri);
    if (type === "mierus") return parseMierus(uri);

    type = normalizeType(type);

    const u = new URL(uri);
    const server = u.hostname;
    const port = validPort(u.port);

    if (!server || !port) return null;

    let name = server;

    if (u.hash.length > 1) {
      name = safeDecode(u.hash.slice(1));
    }

    const identity = safeDecode(u.username || "");
    const password = safeDecode(u.password || "");

    const params = Object.fromEntries(u.searchParams.entries());

    return {
      type,
      server,
      port,
      name,
      identity,
      password,
      security: params.security || "",
      sni:
        params.sni ||
        params.peer ||
        params.servername ||
        params.host ||
        "",
      uri,
      rawProxy: null,
      params
    };
  } catch {
    return null;
  }
}

// ======================================
// Clash / Mihomo YAML 节点解析
// ======================================

function proxyToNode(p) {
  if (!p || typeof p !== "object") return null;

  let type = String(p.type || "").toLowerCase();

  if (!SUPPORTED.has(type)) return null;

  type = normalizeType(type);

  const server = String(p.server || "");
  const port = validPort(p.port || 0);

  if (type !== "mieru") {
    if (!server || !port) return null;
  } else if (!server || (!port && !p["port-range"])) {
    return null;
  }

  const name = String(p.name ?? server);

  const identity = String(
    p.uuid ??
    p.username ??
    p.password ??
    p.auth ??
    ""
  );

  let password = "";

  if (type === "http" || type === "socks5") {
    password = String(p.password || "");
  }

  if (type === "mieru") {
    return {
      type,
      server,
      port,
      name,
      identity: String(p.username || ""),
      password: String(p.password || ""),
      security: "",
      sni: "",
      uri: "",
      rawProxy: p,
      mieruData: {
        portRange: p["port-range"] || "",
        transport: p.transport || "TCP",
        multiplexing: p.multiplexing || ""
      },
      params: {}
    };
  }

  if (type === "wireguard") {
    return {
      type,
      server,
      port,
      name,
      identity: String(p["private-key"] || p.privateKey || ""),
      password: "",
      security: "",
      sni: "",
      uri: "",
      rawProxy: p,
      params: {}
    };
  }

  const node = {
    type,
    server,
    port,
    name,
    identity,
    password,
    security: String(p.tls || ""),
    sni: String(p.servername || p.sni || ""),
    uri: "",
    rawProxy: p,
    params: {}
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// Sing-box JSON
// ======================================

function parseSingbox(config) {
  const result = [];

  const aliases = {
    shadowsocks: "ss",
    shadowsocksr: "ssr",
    socks: "socks5",
    hysteria2: "hysteria2",
    wireguard: "wireguard",
    mieru: "mieru"
  };

  for (const outbound of config.outbounds || []) {
    if (!outbound || typeof outbound !== "object") continue;

    const sourceType = String(outbound.type || "").toLowerCase();
    const normalized = normalizeType(aliases[sourceType] || sourceType);

    if (!SUPPORTED.has(sourceType) && !SUPPORTED.has(normalized)) {
      continue;
    }

    const server = String(outbound.server || "");
    const port = validPort(outbound.server_port || outbound.port || 0);

    // WireGuard 与 Mieru 配置字段可能不同，保留完整字段
    if (!server || (!port && normalized !== "wireguard" && normalized !== "mieru")) {
      continue;
    }

    const tls = outbound.tls || {};
    const transport = outbound.transport || {};

    let identity =
      outbound.uuid ||
      outbound.password ||
      outbound.username ||
      "";

    const name = String(outbound.tag || server || "未命名节点");

    if (normalized === "ss") {
      identity = `${outbound.method || ""}:${outbound.password || ""}`;
    }

    if (normalized === "wireguard") {
      identity = String(outbound.private_key || "");
    }

    const node = {
      type: normalized,
      server,
      port,
      name,
      identity: String(identity),
      password: String(outbound.password || ""),
      security: tls.enabled ? "tls" : "",
      sni: String(tls.server_name || ""),
      uri: "",
      rawProxy: null,
      singboxData: outbound,
      params: {
        flow: outbound.flow || "",
        network: transport.type || "",
        transport,
        tls,
        fingerprint: tls.utls?.fingerprint || "",
        packetEncoding: outbound.packet_encoding || ""
      }
    };

    if (
      normalized !== "mieru" &&
      normalized !== "wireguard"
    ) {
      node.uri = buildNodeUri(node);
    }

    result.push(node);
  }

  return result;
}

// ======================================
// CSV 分割：处理带引号的逗号
// ======================================

function splitCsv(line) {
  const result = [];
  let current = "";
  let quoted = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (quoted && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        quoted = !quoted;
      }

      continue;
    }

    if (char === "," && !quoted) {
      result.push(current.trim());
      current = "";
      continue;
    }

    current += char;
  }

  result.push(current.trim());

  return result.map(value =>
    value.replace(/^"(.*)"$/, "$1")
  );
}

// ======================================
// Surge / Loon / Quantumult X
// ======================================

function parseConfigText(text) {
  const source = String(text || "");
  const result = [];

  const map = {
    ss: "ss",
    shadowsocks: "ss",
    vmess: "vmess",
    vless: "vless",
    trojan: "trojan",
    hysteria: "hysteria",
    hysteria2: "hysteria2",
    hy2: "hysteria2",
    anytls: "anytls",
    tuic: "tuic",
    http: "http",
    socks: "socks5",
    socks5: "socks5",
    wireguard: "wireguard",
    mieru: "mieru"
  };

  let section = "";

  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (
      !line ||
      line.startsWith(";") ||
      line.startsWith("#")
    ) {
      continue;
    }

    const sectionMatch = line.match(/^\[([^\]]+)\]$/);

    if (sectionMatch) {
      section = sectionMatch[1].trim().toLowerCase();
      continue;
    }

    // Surge / Loon [Proxy]
    if (section === "proxy") {
      const parts = splitCsv(line);

      if (parts.length < 4) continue;

      const name = parts[0];
      const server = parts[1];
      const port = validPort(parts[2]);
      const type = map[String(parts[3] || "").toLowerCase()];

      if (!server || !port || !type) continue;

      const options = {};

      for (const part of parts.slice(4)) {
        const index = part.indexOf("=");

        if (index < 0) continue;

        const key = part.slice(0, index).trim().toLowerCase();
        const value = part.slice(index + 1).trim();

        options[key] = value;
      }

      const identity =
        options.password ||
        options.uuid ||
        options.username ||
        options.token ||
        "";

      const node = {
        type,
        server,
        port,
        name,
        identity,
        password: options.password || "",
        security: options.tls || "",
        sni: options.sni || options.peer || options.servername || "",
        uri: "",
        rawProxy: null,
        params: options
      };

      if (type !== "mieru" && type !== "wireguard") {
        node.uri = buildNodeUri(node);
      }

      result.push(node);
      continue;
    }

    // Quantumult X 常见格式：
    // tag=节点名, ss, server, port, method=..., password=...
    if (
      line.includes("tag=") &&
      /,\s*(ss|shadowsocks|vmess|vless|trojan|http|socks5)\s*,/i.test(line)
    ) {
      const parts = splitCsv(line);
      const tagPart = parts[0] || "";
      const name = tagPart.replace(/^tag=/i, "").trim();

      const type = map[String(parts[1] || "").toLowerCase()];
      const server = parts[2] || "";
      const port = validPort(parts[3]);

      if (!type || !server || !port) continue;

      const options = {};

      for (const part of parts.slice(4)) {
        const index = part.indexOf("=");

        if (index < 0) continue;

        options[part.slice(0, index).trim().toLowerCase()] =
          part.slice(index + 1).trim();
      }

      const node = {
        type,
        server,
        port,
        name: name || server,
        identity: options.password || options.uuid || "",
        password: options.password || "",
        security: options.tls || "",
        sni: options.sni || "",
        uri: "",
        rawProxy: null,
        params: options
      };

      node.uri = buildNodeUri(node);
      result.push(node);
    }
  }

  return result;
}

// ======================================
// URI 构造
// ======================================

function buildNodeUri(n) {
  const enc = value => encodeURIComponent(String(value ?? ""));

  const p = n.rawProxy || {};
  const params = n.params || {};

  const server = n.server;
  const port = n.port;
  const name = enc(n.name);

  if (!server || !port) return n.uri || "";

  // VMess
  if (n.type === "vmess") {
    const original = n.vmessData || {};

    const j = {
      ...original,
      v: "2",
      ps: n.name,
      add: server,
      port: String(port),
      id: n.identity,
      aid: String(original.aid ?? p.alterId ?? 0),
      scy: original.scy || p.cipher || "auto",
      net: original.net || p.network || "tcp",
      tls: original.tls || (n.security ? "tls" : ""),
      sni: original.sni || n.sni || ""
    };

    return "vmess://" + encodeBase64(JSON.stringify(j));
  }

  // SS
  if (n.type === "ss") {
    let cipher = p.cipher || "";
    let password = p.password || "";

    if (n.identity.includes(":")) {
      const index = n.identity.indexOf(":");
      cipher = n.identity.slice(0, index);
      password = n.identity.slice(index + 1);
    }

    if (!cipher || !password) return n.uri || "";

    const auth = encodeBase64(`${cipher}:${password}`);

    return `ss://${auth}@${server}:${port}#${name}`;
  }

  // HTTP / SOCKS5
  if (n.type === "http" || n.type === "socks5") {
    const username = n.identity || p.username || "";
    const password = n.password || p.password || "";

    const auth = username || password
      ? `${enc(username)}:${enc(password)}@`
      : "";

    return `${n.type}://${auth}${server}:${port}#${name}`;
  }

  // 其他常规 URI 协议
  const user =
    p.uuid ||
    p.password ||
    p.auth ||
    n.identity ||
    "";

  const auth = user ? `${enc(user)}@` : "";

  const q = new URLSearchParams();

  const allParams = {
    ...params,
    ...(p || {})
  };

  const sni =
    allParams.sni ||
    allParams.servername ||
    n.sni;

  if (sni) q.set("sni", sni);

  if (allParams.security) {
    q.set("security", allParams.security);
  }

  if (allParams.flow) q.set("flow", allParams.flow);

  if (allParams.fingerprint || allParams.fp) {
    q.set("fp", allParams.fingerprint || allParams.fp);
  }

  if (allParams.network) {
    q.set("type", allParams.network);
  }

  if (allParams.alpn) {
    q.set(
      "alpn",
      Array.isArray(allParams.alpn)
        ? allParams.alpn.join(",")
        : allParams.alpn
    );
  }

  // Reality
  if (allParams["reality-opts"] || allParams.reality) {
    const reality =
      allParams["reality-opts"] ||
      allParams.reality;

    if (reality["public-key"] || reality.publicKey) {
      q.set("pbk", reality["public-key"] || reality.publicKey);
    }

    if (reality["short-id"] || reality.shortId) {
      q.set("sid", reality["short-id"] || reality.shortId);
    }
  }

  // WebSocket
  if (allParams["ws-opts"]) {
    const ws = allParams["ws-opts"];

    if (ws.path) q.set("path", ws.path);

    if (ws.headers?.Host) {
      q.set("host", ws.headers.Host);
    }
  }

  // gRPC
  if (allParams["grpc-opts"]) {
    const grpc = allParams["grpc-opts"];

    if (grpc["grpc-service-name"]) {
      q.set("serviceName", grpc["grpc-service-name"]);
    }
  }

  if (allParams.encryption) {
    q.set("encryption", allParams.encryption);
  }

  const query = q.toString();

  return `${n.type}://${auth}${server}:${port}${query ? "?" + query : ""}#${name}`;
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
      if (key === "name") continue;
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
    return JSON.stringify(stableValue(n.rawProxy));
  }

  if (n.uri) {
    try {
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
    n.sni || "",
    n.opaque ? n.uri || "" : ""
  ].join("|");
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
  const aliases = [name, ...aliasText.split(",")].filter(Boolean);
  const item = { name, code, aliases };

  REGION_MAP.push(item);

  for (const alias of aliases) {
    REGION_BY_NAME.set(alias.toLowerCase(), item);
  }
}

const REGION_MATCHERS = REGION_MAP
  .flatMap(item => item.aliases.map(alias => ({ alias, item })))
  .sort((a, b) => b.alias.length - a.alias.length);

// ======================================
// 地区识别
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
// 订阅链接脱敏
// ======================================

function maskSubscriptionUrl(value) {
  try {
    const u = new URL(value);

    const sensitive = [
      "token",
      "key",
      "auth",
      "sign",
      "signature",
      "password",
      "secret",
      "access_token"
    ];

    for (const key of sensitive) {
      if (u.searchParams.has(key)) {
        u.searchParams.set(key, "******");
      }
    }

    return u.toString();
  } catch {
    return String(value || "");
  }
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
      let name = safeDecode(parts[parts.length - 1]);

      name = name.replace(/\.(yaml|yml|txt|json|conf)$/i, "");

      return name || u.hostname;
    }

    return u.hostname;
  } catch {
    return "未知";
  }
}

// ======================================
// 流量信息
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

  const upload = Math.max(0, Number(v.upload || 0) || 0);
  const download = Math.max(0, Number(v.download || 0) || 0);
  const total = Math.max(0, Number(v.total || 0) || 0);
  const expire = Math.max(0, Number(v.expire || 0) || 0);

  const used = upload + download;

  let expireText = "未知";

  if (expire > 0) {
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
        protocols[n.type] = (protocols[n.type] || 0) + 1;
      }

      if (!p.regionCounts) {
        const r = region(n.name);
        regions[r] = (regions[r] || 0) + 1;
      }
    }
  }

  const fingerprints = new Set(nodes.map(getFingerprint));

  const duplicateCount =
    p.duplicateCount ?? (nodes.length - fingerprints.size);

  const uniqueCount =
    p.uniqueCount ?? fingerprints.size;

  const totalCount =
    p.totalCount ?? nodes.length;

  const parsedCount =
    p.parsedCount ?? totalCount;

  const truncatedCount =
    p.truncatedCount ?? Math.max(0, parsedCount - nodes.length);

  const info = parseUserinfo(
    p.headers?.userinfo ||
    p.headers?.["subscription-userinfo"] ||
    p.headers?.["Subscription-Userinfo"]
  );

  const regionEntries = Object.entries(regions)
    .sort((a, b) => b[1] - a[1]);

  const regionText = regionEntries
    .map(([name, count]) =>
      `${flag(name)}${escapeHtml(name)}${count}`
    )
    .join(" ");

  const protocolNames = [...new Set(
    Object.keys(protocols).map(protocolLabel)
  )];

  const protocolText = protocolNames.length
    ? protocolNames.map(escapeHtml).join("、")
    : "未知";

  let subscriptionText = "未提供";

  if (p.sourceUrl) {
    try {
      const url = new URL(p.sourceUrl);

      if (
        url.protocol === "http:" ||
        url.protocol === "https:"
      ) {
        const safeUrl = maskSubscriptionUrl(url.href);

        subscriptionText =
          `<a href="${escapeHtml(safeUrl)}">点击查看原始订阅链接</a>`;
      } else {
        subscriptionText = escapeHtml(
          maskSubscriptionUrl(p.sourceUrl)
        );
      }
    } catch {
      subscriptionText = escapeHtml(
        maskSubscriptionUrl(p.sourceUrl)
      );
    }
  }

  const airportName = escapeHtml(
    getAirportName(p.sourceUrl)
  );

  const visibleNodes = nodes.slice(0, limit);

  const hiddenCachedCount = Math.max(
    0,
    nodes.length - visibleNodes.length
  );

  const nodeLines = visibleNodes.map((n, index) => {
    const r = region(n.name);
    const regionFlag = flag(r);

    let name = String(n.name || "");

    // 已识别地区时，避免备注开头重复出现相同旗帜
    if (
      r !== "未知" &&
      name.startsWith(regionFlag)
    ) {
      name = name.slice(regionFlag.length).trimStart();
    }

    const separator = r === "未知" ? "" : " ";

    return (
      `${index + 1}. ${regionFlag}` +
      `${escapeHtml(protocolLabel(n.type))}` +
      `${separator}` +
      `${escapeHtml(name)}`
    );
  });

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
    `地区数量：<b>${regionEntries.length}</b>`,
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
    .map(n => {
      if (n.uri) return n.uri;

      // 没有标准分享 URI 的原生配置不伪造链接
      return "";
    })
    .filter(Boolean)
    .join("\n");

  return text ? encodeBase64(text) : "";
}

// ======================================
// 节点转 Clash
// ======================================

function nodeToClash(n) {
  if (!n) return null;

  // 原始 Clash 配置直接保留，避免丢失高级参数
  if (n.rawProxy) {
    return {
      ...n.rawProxy,
      name: n.name
    };
  }

  // Mieru Protobuf 分享链接不能直接转换成 Clash 节点
  if (n.opaque) return null;

  // WireGuard 缺少完整参数时不生成残缺配置
  if (n.type === "wireguard") {
    if (n.singboxData) {
      return null;
    }

    return null;
  }

  const p = {
    name: n.name,
    type: n.type,
    server: n.server,
    port: n.port
  };

  const identity = n.identity || "";
  const params = n.params || {};

  if (n.type === "vless" || n.type === "vmess") {
    p.uuid = identity;
  }

  if (
    n.type === "trojan" ||
    n.type === "anytls" ||
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

  if (n.type === "ssr") {
    return null;
  }

  if (n.type === "http" || n.type === "socks5") {
    if (identity) p.username = identity;
    if (n.password) p.password = n.password;
  }

  if (n.sni) {
    p.servername = n.sni;
    p.tls = true;
  }

  if (params.flow) p.flow = params.flow;

  if (params.network || params.type) {
    p.network = params.network || params.type;
  }

  if (params.alpn) {
    p.alpn = String(params.alpn).split(",");
  }

  if (params.fp || params.fingerprint) {
    p["client-fingerprint"] = params.fp || params.fingerprint;
  }

  if (params.path) {
    p["ws-opts"] = {
      path: params.path,
      headers: params.host
        ? { Host: params.host }
        : {}
    };
  }

  if (params.serviceName) {
    p["grpc-opts"] = {
      "grpc-service-name": params.serviceName
    };
  }

  if (params.encryption) {
    p.encryption = params.encryption;
  }

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
