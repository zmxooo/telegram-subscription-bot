import YAML from "yaml";

// ======================================
// 支持的协议
// ======================================

const SUPPORTED = new Set([
  "vless", "vmess", "ss", "trojan",
  "hysteria", "hysteria2", "hy2",
  "anytls", "tuic", "http", "socks", "socks5"
]);

const PROTOCOL_ALIASES = {
  hy2: "hysteria2",
  socks: "socks5"
};

// ======================================
// 主解析入口
//
// 默认最多缓存 1000 个节点。
// 导出全部节点时：parseInput(raw, Number.MAX_SAFE_INTEGER)
// 重复节点不删除，只统计。
// ======================================

export function parseInput(input, maxNodes = 1000) {
  let text = String(input || "").trim();

  if (!text) {
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

  let nodes = [];
  const yaml = tryYaml(text);

  if (yaml && Array.isArray(yaml.proxies)) {
    nodes = yaml.proxies.map(proxyToNode).filter(Boolean);
  } else {
    const decoded = decodeBase64(text);

    if (
      decoded &&
      /(?:vless|vmess|ss|trojan|hysteria2?|hy2|anytls|tuic|http|socks5?):\/\//i.test(decoded)
    ) {
      text = decoded;
    }

    for (const line of text.split(/\r?\n/).map(x => x.trim()).filter(Boolean)) {
      if (!isSupportedUri(line)) continue;

      const node = parseUri(line);
      if (node) nodes.push(node);
    }
  }

  // ======================================
  // 全量统计：必须在节点截断之前完成
  // ======================================

  const fingerprints = nodes.map(getFingerprint);
  const uniqueCount = new Set(fingerprints).size;
  const totalCount = nodes.length;
  const duplicateCount = totalCount - uniqueCount;

  const protocolCounts = {};
  const regionCounts = {};

  for (const node of nodes) {
    protocolCounts[node.type] = (protocolCounts[node.type] || 0) + 1;

    const r = region(node.name);
    regionCounts[r] = (regionCounts[r] || 0) + 1;
  }

  // ======================================
  // 限制缓存数量
  // Infinity / MAX_SAFE_INTEGER 表示不截断
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
    truncatedCount: Math.max(0, totalCount - limitedNodes.length),
    uniqueCount,
    duplicateCount,
    protocolCounts,
    regionCounts
  };
}

// ======================================
// 重复节点指纹
//
// YAML 节点：根据完整配置生成指纹。
// URI 节点：保留完整 URI 参数，忽略备注名称。
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

function getFingerprint(n) {
  if (n.rawProxy) {
    return JSON.stringify(stableValue(n.rawProxy));
  }

  if (n.uri) {
    try {
      if (n.type === "vmess") {
        const data = n.vmessData || {};
        const normalized = { ...data };

        delete normalized.ps;

        return "vmess|" + JSON.stringify(stableValue(normalized));
      }

      const u = new URL(n.uri);

      // 去除备注名称，不影响连接参数
      u.hash = "";

      // 参数排序，避免参数顺序不同造成误判
      const params = [...u.searchParams.entries()]
        .sort((a, b) => {
          const keyCompare = a[0].localeCompare(b[0]);
          return keyCompare || a[1].localeCompare(b[1]);
        });

      u.search = "";

      for (const [key, value] of params) {
        u.searchParams.append(key, value);
      }

      return u.toString().toLowerCase();
    } catch {
      return String(n.uri).split("#")[0].toLowerCase();
    }
  }

  return [
    n.type || "",
    n.server || "",
    n.port || "",
    n.identity || "",
    n.security || "",
    n.sni || ""
  ].join("|").toLowerCase();
}

// ======================================
// URI 判断
// ======================================

function isSupportedUri(uri) {
  const match = String(uri).match(/^([a-z0-9]+):\/\//i);
  return !!match && SUPPORTED.has(match[1].toLowerCase());
}

// ======================================
// YAML 识别
// ======================================

function tryYaml(text) {
  if (!/^\s*(proxies|mixed-port|port|proxy-groups)\s*:/m.test(text)) {
    return null;
  }

  try {
    return YAML.parse(text);
  } catch {
    return null;
  }
}

// ======================================
// Base64 UTF-8 解码
// ======================================

function decodeBase64(text) {
  const clean = String(text).replace(/\s/g, "");

  if (!/^[A-Za-z0-9+/_=-]+$/.test(clean) || clean.length < 12) {
    return null;
  }

  try {
    let normalized = clean.replace(/-/g, "+").replace(/_/g, "/");
    normalized = normalized.replace(/=+$/, "");
    normalized = normalized.padEnd(
      Math.ceil(normalized.length / 4) * 4,
      "="
    );

    const binary = atob(normalized);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
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
// VMess 解码
// ======================================

function decodeVmess(uri) {
  try {
    const raw = uri.slice("vmess://".length).split("#")[0];
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
      security: String(j.tls || ""),
      sni: String(j.sni || j.host || ""),
      uri,
      vmessData: j,
      rawProxy: null
    };
  } catch {
    return null;
  }
}

// ======================================
// URI 节点解析
// ======================================

function parseUri(uri) {
  try {
    const match = uri.match(/^([a-z0-9]+):\/\//i);
    if (!match) return null;

    let type = match[1].toLowerCase();
    if (!SUPPORTED.has(type)) return null;

    if (type === "vmess") return decodeVmess(uri);

    type = PROTOCOL_ALIASES[type] || type;

    if (type === "ss" && !uri.includes("@")) {
      return parseLegacySS(uri);
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

    return {
      type,
      server,
      port,
      name,
      identity,
      security: u.searchParams.get("security") || "",
      sni:
        u.searchParams.get("sni") ||
        u.searchParams.get("peer") ||
        u.searchParams.get("servername") ||
        "",
      uri,
      rawProxy: null
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
// SS 旧格式
// ======================================

function parseLegacySS(uri) {
  try {
    const content = uri.slice(5).split("#")[0];
    const decoded = decodeBase64(content);

    if (!decoded || !decoded.includes("@")) return null;

    const at = decoded.lastIndexOf("@");
    const auth = decoded.slice(0, at);
    const address = decoded.slice(at + 1);
    const colon = auth.indexOf(":");

    if (colon < 0) return null;

    const cipher = auth.slice(0, colon);
    const password = auth.slice(colon + 1);
    const addressMatch = address.match(/^(.+):(\d+)$/);

    if (!addressMatch) return null;

    return {
      type: "ss",
      server: addressMatch[1],
      port: Number(addressMatch[2]),
      name: addressMatch[1],
      identity: `${cipher}:${password}`,
      security: "",
      sni: "",
      uri,
      rawProxy: null
    };
  } catch {
    return null;
  }
}

// ======================================
// Clash YAML 转节点
// 保留完整 rawProxy
// ======================================

function proxyToNode(p) {
  if (!p || typeof p !== "object") return null;

  let type = String(p.type || "").toLowerCase();
  if (!SUPPORTED.has(type)) return null;

  type = PROTOCOL_ALIASES[type] || type;

  const server = String(p.server || "");
  const port = Number(p.port || 0);

  if (!server || !port || port < 1 || port > 65535) {
    return null;
  }

  const name = String(p.name ?? server);

  const identity = String(
    p.uuid ??
    p.password ??
    p.auth ??
    ""
  );

  const node = {
    type,
    server,
    port,
    name,
    identity,
    security: String(p.tls || ""),
    sni: String(p.servername || p.sni || ""),
    uri: "",
    rawProxy: p
  };

  node.uri = buildNodeUri(node);

  return node;
}

// ======================================
// 节点转 URI
// ======================================

function buildNodeUri(n) {
  const enc = value => encodeURIComponent(String(value ?? ""));
  const p = n.rawProxy || {};

  const server = n.server;
  const port = n.port;
  const name = enc(n.name);

  if (n.type === "vmess") {
    const j = {
      v: "2",
      ps: n.name,
      add: server,
      port: String(port),
      id: p.uuid || n.identity,
      aid: String(p.alterId ?? 0),
      scy: p.cipher || "auto",
      net: p.network || "tcp",
      tls: p.tls ? "tls" : "",
      sni: p.servername || p.sni || ""
    };

    return "vmess://" + encodeBase64(JSON.stringify(j));
  }

  if (n.type === "ss") {
    const cipher = p.cipher || "aes-128-gcm";
    const password = p.password || "";
    const auth = encodeBase64(`${cipher}:${password}`);

    return `ss://${auth}@${server}:${port}#${name}`;
  }

  if (n.type === "http" || n.type === "socks5") {
    const auth = n.identity ? `${enc(n.identity)}@` : "";
    return `${n.type}://${auth}${server}:${port}#${name}`;
  }

  const scheme = n.type === "hysteria2" ? "hysteria2" : n.type;

  const user = p.uuid || p.password || p.auth || n.identity || "";
  const auth = user ? `${enc(user)}@` : "";

  const q = new URLSearchParams();

  if (p.sni || p.servername || n.sni) {
    q.set("sni", p.sni || p.servername || n.sni);
  }

  if (p.encryption) q.set("encryption", p.encryption);
  if (p.flow) q.set("flow", p.flow);
  if (p.fingerprint) q.set("fp", p.fingerprint);

  const query = q.toString();

  return `${scheme}://${auth}${server}:${port}${query ? "?" + query : ""}#${name}`;
}

// ======================================
// 全球国家和地区名称 / ISO 代码
// 格式：中文名称|ISO代码|别名1,别名2
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

// 优先匹配较长名称，避免短名称抢先匹配
const REGION_MATCHERS = REGION_MAP
  .flatMap(item => item.aliases.map(alias => ({ alias, item })))
  .sort((a, b) => b.alias.length - a.alias.length);

// ======================================
// 地区识别
// 只根据节点备注文字识别
// 不使用 IP / GeoIP
// ======================================

function region(name) {
  const original = String(name || "").trim();

  if (!original) return "未知";

  const s = original.toLowerCase();

  for (const entry of REGION_MATCHERS) {
    const alias = entry.alias.toLowerCase();

    if (/[a-z]/i.test(alias)) {
      const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(`(^|[^a-z])${escaped}([^a-z]|$)`, "i");

      if (re.test(s)) return entry.item.name;
    } else if (s.includes(alias)) {
      return entry.item.name;
    }
  }

  // ISO 两位代码只接受独立词
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
// 根据 ISO 两位代码自动生成
// ======================================

function flag(r) {
  const item = REGION_BY_NAME.get(String(r || "").trim().toLowerCase());

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

    if (parts.length) return safeDecode(parts[parts.length - 1]);

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
    remaining: total > 0 ? fmt(Math.max(0, total - used)) : "未知",
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
//
// renderResult(p, 20) = 展开
// renderResult(p, 2)  = 折叠
// ======================================

export function renderResult(p, nodeLimit = 20) {
  const nodes = p.nodes || [];
  const limit = Math.max(0, Math.floor(Number(nodeLimit) || 20));

  // 优先使用全量统计结果
  const protocols = p.protocolCounts || {};
  const regions = p.regionCounts || {};

  // 兼容旧缓存：没有统计字段时从缓存节点统计
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

  const uniqueCount = p.uniqueCount ?? fingerprints.size;
  const totalCount = p.totalCount ?? nodes.length;

  const parsedCount = p.parsedCount ?? totalCount;
  const truncatedCount =
    p.truncatedCount ?? Math.max(0, parsedCount - nodes.length);

  const info = parseUserinfo(
    p.headers?.userinfo ||
    p.headers?.["subscription-userinfo"] ||
    p.headers?.["Subscription-Userinfo"]
  );

  const regionNames = Object.keys(regions).filter(x => x !== "未知");

  const regionRange = [
    ...regionNames.map(r => `${flag(r)}${r}`),
    ...(regions["未知"] ? ["🌐未知"] : [])
  ].join(",");

  const airportName = getAirportName(p.sourceUrl);

  const visibleNodes = nodes.slice(0, limit);
  const hiddenCachedCount = Math.max(0, nodes.length - visibleNodes.length);

  const lines = [
    `📋 机场名称: ${escapeHtml(airportName)}`,

    p.sourceUrl
      ? `🔗 订阅链接: ${escapeHtml(p.sourceUrl)}`
      : "🔗 订阅链接: 无",

    `📊 流量详情: ${
      info
        ? `已用 ${info.used} / 总量 ${info.total} / 剩余 ${info.remaining}`
        : "未知"
    }`,

    `🗓️ 过期时间: ${info?.expire || "未知"}`,

    "",

    `协议类型: ${Object.keys(protocols).join(",") || "未知"}`,

    `节点总数: ${totalCount} | 国家/地区数: ${regionNames.length + (regions["未知"] ? 1 : 0)}`,

    `重复节点: ${duplicateCount} | 实际唯一节点: ${uniqueCount}`,

    `协议统计: ${
      Object.entries(protocols)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" | ") || "未知"
    }`,

    `节点范围: ${escapeHtml(regionRange || "🌐未知")}`,

    "",

    `节点列表 (共 ${totalCount} 个)`
  ];

  for (const n of visibleNodes) {
    const r = region(n.name);

    lines.push(
      `- ${flag(r)} ${escapeHtml(n.type)}: ${escapeHtml(n.name)}`
    );
  }

  if (hiddenCachedCount > 0) {
    lines.push(`... 还有 ${hiddenCachedCount} 个节点未显示`);
  }

  if (truncatedCount > 0) {
    lines.push(`⚠️ 另有 ${truncatedCount} 个节点未载入缓存，导出时需重新解析原始内容`);
  }

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
// URI 转 Clash YAML
// ======================================

function nodeToClash(n) {
  // YAML 原始节点优先保留完整配置
  if (n.rawProxy) {
    return {
      ...n.rawProxy,
      name: n.name
    };
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

  if (n.type === "trojan" || n.type === "anytls") {
    p.password = identity;
  }

  if (n.type === "hysteria" || n.type === "hysteria2") {
    p.password = identity;
  }

  if (n.type === "tuic") {
    p.uuid = identity;
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
  }

  if (n.sni) {
    p.servername = n.sni;
    p.tls = true;
  }

  return p;
}

// ======================================
// Clash YAML 导出
// ======================================

export function exportYaml(nodes) {
  const proxies = (nodes || []).map(nodeToClash);
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
