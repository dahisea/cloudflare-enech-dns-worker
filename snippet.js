// Cloudflare Snippet — DoH Proxy (Snippets Compatible)
// 与 Worker 版的差异：
//   1. 禁用 Cache API（Snippets 不支持 caches.default）
//   2. 移除所有 env 参数（Snippets 无 Bindings）
//   3. handleRequest 改为串行，避免并发 subrequest 超限
//   4. SOA 查询改为单服务器（1.1.1.1）
//   5. 上游 DNS 只保留 1 个

// ╔══════════════════════════════════════════════════════════════╗
// ║                        Config                               ║
// ╚══════════════════════════════════════════════════════════════╝

const ALLOWED_PATH  = '/linuxdo/dns-query';
const OPTIMIZED_TTL = 3600;

const DEBUG = false;

const ECH_MODE = 'local';

const CACHE = {
  MEM_CF:        true,
  MEM_CF_TTL:    1_800_000,   // ms，30 分钟
  MEM_CF_MAX:    500,

  MEM_ECH:       true,

  // Snippets 不支持 Cache API，强制关闭
  PERSIST_CF:    false,
  PERSIST_CF_TTL:   3600,

  PERSIST_ECH:   false,
  PERSIST_ECH_TTL:  86400,
};

// Snippets 每请求只允许有限 subrequest，只保留 1 个上游
const UPSTREAM_DNS_SERVERS = [
  'https://chrome.cloudflare-dns.com/dns-query',
];

const DOMAIN_RULES = [
  { domain: 'twimg.com', forceCloudflare: true },
  { domain: 'twitter.com', forceCloudflare: true },
  { domain: 'upload.x.com', forceCloudflare: true },
  { domain: 'api.x.com', forceCloudflare: true },
  { domain: 'grok.x.com', forceCloudflare: true },
  { domain: 'x.com', forceCloudflare: true },
];

const CF_DOMAIN_LIST = ['workers.dev', 'pages.dev', 'cloudflarestatus.com'];
const CF_FIXED_IPS   = ['91.193.58.2', '91.193.58.21'];

const DNSSEC_BLOCKED = new Set([43, 46, 47, 48, 50]);

const ECH_DOMAIN   = 'cloudflare-ech.com';
const ECH_FALLBACK = 'AEX+DQBBFAAgACApLi37Py03Z3TinersGhjjAEUIL3f9fMaU+5eDjSoHAAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=';

// ── 内存缓存实例 ───────────────────────────────────────────────────
const memCfCache  = new Map();
let   memEchCache = null;

// ── 启动时预计算 ───────────────────────────────────────────────────
const TTL_BYTES = [
  (OPTIMIZED_TTL >> 24) & 0xFF,
  (OPTIMIZED_TTL >> 16) & 0xFF,
  (OPTIMIZED_TTL >> 8)  & 0xFF,
   OPTIMIZED_TTL        & 0xFF,
];
const ALPN_H3 = encodeAlpn(['h3,h2']);

// ══════════════════════════════════════════════════════════════════
// Debug
// ══════════════════════════════════════════════════════════════════

function log(...args) {
  if (DEBUG) console.log('[DoH]', ...args);
}

// ══════════════════════════════════════════════════════════════════
// Entry — 串行执行，严格控制 subrequest 数量
// 缓存命中：0 subrequest（SOA）+ 1（上游）= 1
// SOA 查询：1 subrequest（SOA）+ 1（上游）= 2
// 命中 CF  ：1 subrequest（SOA）+ 0       = 1
// ══════════════════════════════════════════════════════════════════

export default {
  fetch(request) {
    return handleRequest(request);
  }
};

async function handleRequest(request) {
  const url = new URL(request.url);
  if (url.pathname !== ALLOWED_PATH)
    return new Response('Not Found', { status: 404 });
  if (request.method !== 'GET' && request.method !== 'POST')
    return new Response('Method Not Allowed', { status: 405 });

  try {
    let dnsQuery = await extractDnsQuery(request);
    if (!dnsQuery) return new Response('Bad Request', { status: 400 });

    dnsQuery = stripDnssecFromQuery(dnsQuery);

    const { queryName, queryType } = parseDnsQuery(dnsQuery);
    log(`query name=${queryName} type=${queryType}`);

    if (DNSSEC_BLOCKED.has(queryType)) {
      log(`blocked DNSSEC type=${queryType} for ${queryName}`);
      return createEmptyDnsResponse(dnsQuery);
    }

    const rule = matchDomainRule(queryName);
    if (rule?.forceCloudflare) {
      log(`domain rule forceCloudflare matched: ${queryName}`);
      return handleCfQuery(queryType, dnsQuery, rule.a ?? null);
    }

    // 先做 CF 检测，再决定是否转发上游，避免并发超限
    const isCf = await checkIfCloudflare(queryName);
    log(`CF detection for ${queryName}: isCf=${isCf}`);

    if (isCf) {
      log(`serving CF response for ${queryName} type=${queryType}`);
      return handleCfQuery(queryType, dnsQuery, null);
    }

    log(`forwarding to upstream for ${queryName} type=${queryType}`);
    return filterDnssecFromResponse(await forwardToUpstream(dnsQuery));

  } catch (err) {
    log(`handleRequest error: ${err?.message}`);
    return new Response('Internal Server Error', { status: 500 });
  }
}

// ══════════════════════════════════════════════════════════════════
// CF Query Handler
// ══════════════════════════════════════════════════════════════════

async function handleCfQuery(queryType, originalQuery, customIPs) {
  const ips = customIPs ?? CF_FIXED_IPS;
  if (queryType === 28) return createEmptyDnsResponse(originalQuery);
  if (queryType === 1)  return createARecordResponse(originalQuery, ips);
  if (queryType === 5)  return createEmptyDnsResponse(originalQuery);
  if (queryType === 65) {
    const ech = await getEchConfig();
    return createCfHttpsResponse(originalQuery, ips, ech);
  }
  return filterDnssecFromResponse(await forwardToUpstream(originalQuery));
}

// ══════════════════════════════════════════════════════════════════
// Domain Rules
// ══════════════════════════════════════════════════════════════════

function matchDomainRule(queryName) {
  const name = queryName.toLowerCase();
  for (const rule of DOMAIN_RULES) {
    const pat = rule.domain.toLowerCase();
    if (name === pat) return rule;
    if (pat.startsWith('*.')) {
      const suffix = pat.slice(2);
      if (name === suffix || name.endsWith('.' + suffix)) return rule;
    }
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════
// CF Detection（内存缓存 + 静态白名单 + SOA 查询）
// ══════════════════════════════════════════════════════════════════

async function checkIfCloudflare(domain) {
  const key = domain.toLowerCase();
  const now = Date.now();

  // 1. 内存缓存
  if (CACHE.MEM_CF) {
    const hit = memCfCache.get(key);
    if (hit && now - hit.ts < CACHE.MEM_CF_TTL) {
      log(`CF mem-cache hit: ${domain} isCf=${hit.isCf}`);
      return hit.isCf;
    }
  }

  // 2. 静态白名单
  if (CF_DOMAIN_LIST.some(d => domain === d || domain.endsWith('.' + d))) {
    log(`CF domain list hit: ${domain}`);
    writeCfCache(key, true, now);
    return true;
  }

  // 3. SOA 查询（单服务器，节省 subrequest 配额）
  let isCf = false;
  try { isCf = await querySoaIsCloudflare(domain); } catch {}
  log(`SOA result for ${domain}: isCf=${isCf}`);

  writeCfCache(key, isCf, now);
  return isCf;
}

function writeCfCache(key, isCf, now) {
  if (!CACHE.MEM_CF) return;
  memCfCache.set(key, { isCf, ts: now });
  if (memCfCache.size > CACHE.MEM_CF_MAX && Math.random() < 0.05) {
    const cutoff = now - CACHE.MEM_CF_TTL;
    for (const [k, v] of memCfCache) if (v.ts < cutoff) memCfCache.delete(k);
  }
}

// ══════════════════════════════════════════════════════════════════
// 持久化缓存 — Snippets 不支持，降级为空操作
// ══════════════════════════════════════════════════════════════════

async function persistGet(_key)             { return null; }
async function persistSet(_key, _val, _ttl) { }

// ══════════════════════════════════════════════════════════════════
// SOA via DoH JSON API — 单服务器，节省 subrequest 配额
// 选 1.1.1.1：CF 自有节点，延迟最低且最可靠
// ══════════════════════════════════════════════════════════════════

async function querySoaIsCloudflare(domain) {
  const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=SOA`;
  try {
    const r = await fetch(url, { headers: { accept: 'application/dns-json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    log(`SOA raw [${domain}]: ${JSON.stringify(data).slice(0, 400)}`);
    for (const section of [data.Answer, data.Authority]) {
      if (!Array.isArray(section)) continue;
      for (const rr of section) {
        if (rr.type === 6) {
          const matched = rr.data.toLowerCase().includes('cloudflare.com');
          log(`SOA RR data="${rr.data}" → cloudflare=${matched}`);
          return matched;
        }
      }
    }
  } catch (e) {
    log(`SOA fetch failed: ${e?.message}`);
  }
  log(`SOA no type-6 record found for ${domain}`);
  return false;
}

// ══════════════════════════════════════════════════════════════════
// ECH Config
// ══════════════════════════════════════════════════════════════════

async function getEchConfig() {
  if (ECH_MODE === 'local') {
    if (!memEchCache) memEchCache = base64UrlDecode(ECH_FALLBACK);
    return memEchCache;
  }

  if (CACHE.MEM_ECH && memEchCache) {
    log('ECH mem-cache hit');
    return memEchCache;
  }

  try {
    const q    = stripDnssecFromQuery(buildDnsQuery(ECH_DOMAIN, 65));
    const resp = await forwardToUpstream(q);
    const ech  = extractEchFromHttpsResponse(new Uint8Array(await resp.arrayBuffer()));
    if (ech?.length) {
      log('ECH fetched from upstream');
      if (CACHE.MEM_ECH) memEchCache = ech;
      return ech;
    }
  } catch {}

  log('ECH using fallback');
  const fallback = base64UrlDecode(ECH_FALLBACK);
  if (CACHE.MEM_ECH) memEchCache = fallback;
  return fallback;
}

function extractEchFromHttpsResponse(data) {
  let off = 12;
  const qdCount = (data[4] << 8) | data[5];
  for (let i = 0; i < qdCount && off < data.length; i++) { off = skipName(data, off); off += 4; }
  const anCount = (data[6] << 8) | data[7];
  for (let i = 0; i < anCount && off < data.length; i++) {
    off = skipName(data, off);
    const type = (data[off] << 8) | data[off + 1];
    off += 8;
    const rdl = (data[off] << 8) | data[off + 1]; off += 2;
    const end  = off + rdl;
    if (type === 65) {
      off += 3;
      while (off < end - 4) {
        const key = (data[off] << 8) | data[off + 1];
        const len = (data[off + 2] << 8) | data[off + 3]; off += 4;
        if (key === 5) return data.slice(off, off + len);
        off += len;
      }
    }
    off = end;
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════
// Upstream Forwarding — 单服务器
// ══════════════════════════════════════════════════════════════════

async function forwardToUpstream(dnsQuery, signal) {
  const b64 = base64UrlEncode(dnsQuery);
  log(`forwardToUpstream → ${UPSTREAM_DNS_SERVERS[0]}`);
  try {
    const r = await fetch(
      `${UPSTREAM_DNS_SERVERS[0]}?dns=${b64}`,
      { headers: { accept: 'application/dns-message' }, signal }
    );
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    log('upstream responded ok');
    return new Response(r.body, { headers: { 'content-type': 'application/dns-message' } });
  } catch (e) {
    if (signal?.aborted) return new Response('Aborted', { status: 499 });
    throw e;
  }
}

// ══════════════════════════════════════════════════════════════════
// DNS Response Builders
// ══════════════════════════════════════════════════════════════════

function createCfHttpsResponse(originalQuery, ips, ech) {
  const data = [0x00, 0x01, 0x00];
  data.push(0x00, 0x01, (ALPN_H3.length >> 8) & 0xFF, ALPN_H3.length & 0xFF, ...ALPN_H3);
  const ipBytes = ips.flatMap(ip => ip.split('.').map(Number));
  data.push(0x00, 0x04, (ipBytes.length >> 8) & 0xFF, ipBytes.length & 0xFF, ...ipBytes);
  if (ech?.length)
    data.push(0x00, 0x05, (ech.length >> 8) & 0xFF, ech.length & 0xFF, ...ech);
  return buildRRResponse(originalQuery, 65, new Uint8Array(data));
}

function buildRRResponse(originalQuery, rrType, rdata) {
  const hdr = new Uint8Array(originalQuery);
  hdr[2] = 0x81; hdr[3] = 0x80;
  hdr[6] = 0x00; hdr[7] = 0x01;

  const ans = new Uint8Array(12 + rdata.length);
  ans[0] = 0xC0; ans[1] = 0x0C;
  ans[2] = (rrType >> 8) & 0xFF; ans[3] = rrType & 0xFF;
  ans[4] = 0x00; ans[5] = 0x01;
  ans[6] = TTL_BYTES[0]; ans[7] = TTL_BYTES[1];
  ans[8] = TTL_BYTES[2]; ans[9] = TTL_BYTES[3];
  ans[10] = (rdata.length >> 8) & 0xFF; ans[11] = rdata.length & 0xFF;
  ans.set(rdata, 12);

  const out = new Uint8Array(hdr.length + ans.length);
  out.set(hdr);
  out.set(ans, hdr.length);
  return new Response(out, { headers: { 'content-type': 'application/dns-message' } });
}

function createARecordResponse(originalQuery, ips) {
  const hdr = new Uint8Array(originalQuery);
  hdr[2] = 0x81; hdr[3] = 0x80;
  hdr[6] = 0x00; hdr[7] = ips.length;

  const ans = new Uint8Array(ips.length * 16);
  let pos = 0;
  for (const ip of ips) {
    ans[pos++] = 0xC0; ans[pos++] = 0x0C;
    ans[pos++] = 0x00; ans[pos++] = 0x01;
    ans[pos++] = 0x00; ans[pos++] = 0x01;
    ans[pos++] = TTL_BYTES[0]; ans[pos++] = TTL_BYTES[1];
    ans[pos++] = TTL_BYTES[2]; ans[pos++] = TTL_BYTES[3];
    ans[pos++] = 0x00; ans[pos++] = 0x04;
    for (const octet of ip.split('.')) ans[pos++] = Number(octet);
  }

  const out = new Uint8Array(hdr.length + ans.length);
  out.set(hdr);
  out.set(ans, hdr.length);
  return new Response(out, { headers: { 'content-type': 'application/dns-message' } });
}

function createEmptyDnsResponse(originalQuery) {
  const r = new Uint8Array(originalQuery);
  r[2] = 0x81; r[3] = 0x80;
  r[6] = 0x00; r[7] = 0x00;
  return new Response(r, { headers: { 'content-type': 'application/dns-message' } });
}

// ══════════════════════════════════════════════════════════════════
// ALPN Encoding
// ══════════════════════════════════════════════════════════════════

function encodeAlpn(list) {
  const out = [];
  for (const s of list) out.push(s.length, ...s.split('').map(c => c.charCodeAt(0)));
  return new Uint8Array(out);
}

// ══════════════════════════════════════════════════════════════════
// DNS Name Helpers
// ══════════════════════════════════════════════════════════════════

function skipName(data, off) {
  while (off < data.length) {
    const len = data[off];
    if ((len & 0xC0) === 0xC0) return off + 2;
    if (len === 0) return off + 1;
    off += len + 1;
  }
  return off;
}

// ══════════════════════════════════════════════════════════════════
// DNSSEC Strip (Outgoing Query)
// ══════════════════════════════════════════════════════════════════

function stripDnssecFromQuery(dnsQuery) {
  const q = new Uint8Array(dnsQuery);
  q[2] = q[2] & 0xDF;

  if (((q[10] << 8) | q[11]) === 0) return q;

  let off = 12;
  const qdCount = (q[4] << 8) | q[5];
  for (let i = 0; i < qdCount && off < q.length; i++) { off = skipName(q, off); off += 4; }
  off = skipRRSection(q, off, (q[6] << 8) | q[7]);
  off = skipRRSection(q, off, (q[8] << 8) | q[9]);

  const arCount = (q[10] << 8) | q[11];
  for (let i = 0; i < arCount && off < q.length; i++) {
    const rrStart = off;
    off = skipName(q, off);
    const type = (q[off] << 8) | q[off + 1];
    off += 8;
    const rdl = (q[off] << 8) | q[off + 1]; off += 2 + rdl;
    if (type === 41) {
      const out = q.slice(0, rrStart);
      out[10] = 0; out[11] = 0;
      return out;
    }
  }
  return q;
}

function skipRRSection(buf, off, count) {
  for (let i = 0; i < count && off < buf.length; i++) {
    off = skipName(buf, off);
    off += 8;
    const rdl = (buf[off] << 8) | buf[off + 1]; off += 2 + rdl;
  }
  return off;
}

// ══════════════════════════════════════════════════════════════════
// DNSSEC Filter (Incoming Response)
// ══════════════════════════════════════════════════════════════════

async function filterDnssecFromResponse(response) {
  const data = new Uint8Array(await response.arrayBuffer());
  data[2] = data[2] & 0xDF;
  return new Response(filterDnssecRecords(data), {
    headers: { 'content-type': 'application/dns-message' },
  });
}

function filterDnssecRecords(resp) {
  let off = 12;
  const qdCount = (resp[4] << 8) | resp[5];
  for (let i = 0; i < qdCount && off < resp.length; i++) { off = skipName(resp, off); off += 4; }
  const sectStart = off;

  const anCount = (resp[6] << 8) | resp[7];
  const nsCount = (resp[8] << 8) | resp[9];
  const arCount = (resp[10] << 8) | resp[11];

  let needsFilter = false;
  let scan = sectStart;
  for (let i = 0; i < anCount + nsCount + arCount && scan < resp.length; i++) {
    scan = skipName(resp, scan);
    if (scan + 10 > resp.length) break;
    const type = (resp[scan] << 8) | resp[scan + 1];
    if (DNSSEC_BLOCKED.has(type)) { needsFilter = true; break; }
    scan += 8;
    const rdl = (resp[scan] << 8) | resp[scan + 1]; scan += 2 + rdl;
  }
  if (!needsFilter) return resp;

  const [anRecs, newAn, off2] = filterSection(resp, sectStart, anCount);
  const [nsRecs, newNs, off3] = filterSection(resp, off2,      nsCount);
  const [arRecs, newAr]       = filterSection(resp, off3,      arCount);

  const header = resp.slice(0, sectStart);
  const all    = [...anRecs, ...nsRecs, ...arRecs];
  const out    = new Uint8Array(header.length + all.reduce((s, r) => s + r.length, 0));

  let pos = 0;
  out.set(header, pos); pos += header.length;
  for (const r of all) { out.set(r, pos); pos += r.length; }

  out[6]  = (newAn >> 8) & 0xFF; out[7]  = newAn & 0xFF;
  out[8]  = (newNs >> 8) & 0xFF; out[9]  = newNs & 0xFF;
  out[10] = (newAr >> 8) & 0xFF; out[11] = newAr & 0xFF;
  return out;
}

function filterSection(buf, off, count) {
  const recs = []; let kept = 0;
  for (let i = 0; i < count && off < buf.length; i++) {
    const start = off;
    off = skipName(buf, off);
    if (off + 10 > buf.length) break;
    const type = (buf[off] << 8) | buf[off + 1];
    off += 8;
    const rdl = (buf[off] << 8) | buf[off + 1]; off += 2 + rdl;
    if (!DNSSEC_BLOCKED.has(type)) { recs.push(buf.slice(start, off)); kept++; }
  }
  return [recs, kept, off];
}

// ══════════════════════════════════════════════════════════════════
// DNS Utilities
// ══════════════════════════════════════════════════════════════════

async function extractDnsQuery(request) {
  if (request.method === 'GET') {
    const p = new URL(request.url).searchParams.get('dns');
    return p ? base64UrlDecode(p) : null;
  }
  if (request.headers.get('content-type')?.includes('application/dns-message'))
    return new Uint8Array(await request.arrayBuffer());
  return null;
}

function parseDnsQuery(q) {
  let off = 12, name = '';
  while (off < q.length && q[off]) {
    const len = q[off];
    if (name) name += '.';
    name += String.fromCharCode(...q.slice(off + 1, off + 1 + len));
    off += len + 1;
  }
  off++;
  return {
    queryName: name.toLowerCase(),
    queryType: off + 1 < q.length ? (q[off] << 8) | q[off + 1] : 0,
  };
}

function buildDnsQuery(domain, type) {
  const q = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
  for (const label of domain.split('.'))
    q.push(label.length, ...label.split('').map(c => c.charCodeAt(0)));
  q.push(0x00, 0x00, type, 0x00, 0x01);
  return new Uint8Array(q);
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  str += '='.repeat((4 - str.length % 4) % 4);
  const bin = atob(str);
  return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
}

function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
