import YAML from "yaml";

const SUPPORTED = new Set(["vless","vmess","ss","trojan","hysteria2","hy2","anytls","tuic","hysteria"]);
export function parseInput(input, maxNodes=500) {
  let text = String(input || "").trim();
  if (!text) return { nodes: [] };
  let nodes = [];
  const yaml = tryYaml(text);
  if (yaml && Array.isArray(yaml.proxies)) {
    nodes = yaml.proxies.map(proxyToUri).filter(Boolean);
  } else {
    const decoded = decodeBase64(text);
    if (decoded && /(?:vless|vmess|ss|trojan|hysteria2?|hy2|anytls|tuic):\/\//i.test(decoded)) text = decoded;
    const lines = text.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    for (const line of lines) {
      if (/^(vless|vmess|ss|trojan|hysteria2?|hy2|anytls|tuic):\/\//i.test(line)) {
        const n = parseUri(line); if (n) nodes.push(n);
      }
    }
  }
  const seen = new Set();
  nodes = nodes.filter(n => {
    const k = [n.type,n.server,n.port,n.identity || "",n.security || "",n.sni || ""].join("|").toLowerCase();
    if (seen.has(k)) return false; seen.add(k); return true;
  }).slice(0,maxNodes);
  return { nodes };
}
function tryYaml(t) {
  if (!/^\s*(proxies|mixed-port|port|proxy-groups)\s*:/m.test(t)) return null;
  try { return YAML.parse(t); } catch { return null; }
}
function decodeBase64(s) {
  const clean=s.replace(/\s/g,"");
  if (!/^[A-Za-z0-9+/=_-]+$/.test(clean) || clean.length<12) return null;
  try { const norm=clean.replace(/-/g,"+").replace(/_/g,"/"); return atob(norm.padEnd(Math.ceil(norm.length/4)*4,"=")); } catch { return null; }
}
function parseUri(uri) {
  try {
    const type=uri.slice(0,uri.indexOf(":")).toLowerCase();
    if (type==="vmess") {
      const raw=atob(uri.split("://")[1].split("#")[0]);
      const j=JSON.parse(raw);
      return {type,server:j.add,port:Number(j.port),name:j.ps||j.add,identity:j.id,security:j.tls||"",sni:j.sni||"",uri};
    }
    const u=new URL(uri);
    const server=u.hostname, port=Number(u.port);
    if (!server || !port) return null;
    const name=decodeURIComponent(u.hash.slice(1)) || server;
    const identity=decodeURIComponent(u.username || "");
    return {type:type==="hy2"?"hysteria2":type,server,port,name,identity,security:u.searchParams.get("security")||"",sni:u.searchParams.get("sni")||u.searchParams.get("peer")||"",uri};
  } catch { return null; }
}
function proxyToUri(p) {
  if (!p || !SUPPORTED.has(String(p.type).toLowerCase())) return null;
  const type=String(p.type).toLowerCase();
  const name=String(p.name||p.server||type);
  const server=String(p.server||"");
  const port=Number(p.port||0);
  if (!server || !port) return null;
  const enc=s=>encodeURIComponent(String(s??""));
  let uri="";
  if (type==="vmess") {
    const j={v:"2",ps:name,add:server,port:String(port),id:p.uuid||p.password||"",aid:"0",scy:p.cipher||"auto",net:p.network||"tcp",tls:p.tls?"tls":"",sni:p.servername||p.sni||""};
    uri="vmess://"+btoa(unescape(encodeURIComponent(JSON.stringify(j))));
  } else if (type==="ss") {
    const user=btoa(`${p.cipher||"aes-128-gcm"}:${p.password||""}`);
    uri=`ss://${user}@${server}:${port}#${enc(name)}`;
  } else {
    const user=p.uuid||p.password||p.auth||"";
    const scheme=type==="hy2"?"hysteria2":type;
    const q=new URLSearchParams();
    if (p.sni||p.servername) q.set("sni",p.sni||p.servername);
    if (p.password) q.set("password",p.password);
    if (p.uuid) q.set("encryption","none");
    uri=`${scheme}://${enc(user)}@${server}:${port}?${q.toString()}#${enc(name)}`;
  }
  const parsed=parseUri(uri); if(parsed) parsed.rawProxy=p; return parsed;
}
export function renderResult(p) {
  const nodes=p.nodes||[];
  const protocols={}; const regions={};
  for(const n of nodes){protocols[n.type]=(protocols[n.type]||0)+1; const r=region(n.name); regions[r]=(regions[r]||0)+1;}
  const info=parseUserinfo(p.headers?.userinfo);
  const lines=[
    "📋 机场名称："+(p.sourceUrl?new URL(p.sourceUrl).hostname:"文本/文件解析"),
    "📊 流量详情："+(info?`${info.used} / ${info.total}`:"未知"),
    "🗓️ 过期时间："+(info?.expire||"未知"),
    "",
    "协议类型："+Object.keys(protocols).join("、"),
    "节点总数："+nodes.length+" | 国家/地区数："+Object.keys(regions).filter(x=>x!=="未知").length,
    "协议统计："+Object.entries(protocols).map(([k,v])=>`${k}: ${v}`).join(" | "),
    "地区统计："+Object.entries(regions).map(([k,v])=>`${k}: ${v}`).join(" | "),
    "",
    "节点列表（最多显示前 12 个）",
    ...nodes.slice(0,12).map(n=>`- ${flag(region(n.name))} ${n.type}: ${n.name}`)
  ];
  return lines.join("\n");
}
function region(name) {
  const s=String(name||"").toLowerCase();
  const rules=[["日本",/日本|东京|大阪|jp|japan/],["新加坡",/新加坡|狮城|sg|singapore/],["美国",/美国|洛杉矶|硅谷|纽约|us|united states/],["德国",/德国|法兰克福|de|germany/],["荷兰",/荷兰|阿姆斯特丹|nl|netherlands/],["香港",/香港|hk|hong kong/],["台湾",/台湾|台北|tw|taiwan/],["韩国",/韩国|首尔|kr|korea/],["英国",/英国|伦敦|uk|united kingdom/],["法国",/法国|巴黎|fr|france/]];
  return rules.find(x=>x[1].test(s))?.[0]||"未知";
}
function flag(r){return ({日本:"🇯🇵",新加坡:"🇸🇬",美国:"🇺🇸",德国:"🇩🇪",荷兰:"🇳🇱",香港:"🇭🇰",台湾:"🇹🇼",韩国:"🇰🇷",英国:"🇬🇧",法国:"🇫🇷"})[r]||"🌐";}
function parseUserinfo(s) {
  if(!s) return null;
  const v={}; for(const part of s.split(";")){const [k,val]=part.split("=");v[k.trim()]=val;}
  const total=Number(v.total||0), used=Number(v.upload||0)+Number(v.download||0);
  return {total:total?fmt(total):"未知",used:fmt(used),expire:v.expire?new Date(Number(v.expire)*1000).toISOString().slice(0,10):"未知"};
}
function fmt(n){if(!n)return "0 B";const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(2)+" "+u[i];}
export function exportBase64(nodes) {
  const text=nodes.map(n=>n.uri).join("\n");
  const bytes=new TextEncoder().encode(text); let bin=""; for(const b of bytes)bin+=String.fromCharCode(b);
  return btoa(bin);
}
export function exportYaml(nodes) {
  const proxies=nodes.map(n=>n.rawProxy || ({name:n.name,type:n.type==="hy2"?"hysteria2":n.type,server:n.server,port:n.port}));
  return YAML.stringify({ "mixed-port":7890, "allow-lan":false, mode:"rule", "log-level":"warning", proxies, "proxy-groups":[{name:"节点选择",type:"select",proxies:proxies.map(x=>x.name)}], rules:["MATCH,节点选择"]});
}
