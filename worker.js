// Cloudflare Worker — DoH Proxy (Unified)
// 支持一键切换 Worker / Snippets 兼容模式

// ╔══════════════════════════════════════════════════════════════╗
// ║                        Config                               ║
// ║              所有开关集中在这里，按需修改                        ║
// ╚══════════════════════════════════════════════════════════════╝

// ── 模式切换 ──────────────────────────────────────────────────────
// false → Worker 模式（并行竞速、多源冗余、Cache API 持久化）
// true  → Snippets 模式（串行执行、单源、仅内存缓存）
const SNIPPETS_MODE = true;

const ALLOWED_PATH  = '/linuxdo/dns-query';
const OPTIMIZED_TTL = 1;

// ── 调试日志 ─────────────────────────────────────────────────────
const DEBUG = false;

// ── IP 地址列表 ───────────────────────────────────────────────────
// 每个列表名对应一组逗号分隔的地址或域名
//
// ipListV4 解析规则：
//   若某项含字母（非纯 digits+dots）→ 视为域名，自动解析为 A 记录，
//   结果 IPs 用于 A 记录回答 & HTTPS ipv4hint。
//   纯 IP 项直接使用。
//
// ipListV6 解析规则：
//   若某项不含 ":" → 视为域名，自动解析为 AAAA 记录，
//   结果 IPs 用于 AAAA 记录回答 & HTTPS ipv6hint。
//   含 ":" 的项视为 IPv6 地址直接使用。
const ipListV4 = {
  'cf': '91.193.58.2,91.193.58.21',
  // 示例：含域名项，会被自动解析
  // 'mylist': '1.2.3.4,example.com,5.6.7.8',
};

const ipListV6 = {
  // 示例：
  // 'cf6': '2606:4700::6810:f8f8,2606:4700::6810:f9f8',
  // 'mylist6': '::1,ipv6.example.com',   ← 不含 ":" 的项会被 AAAA 解析
};

// ── ECH 类型配置 ───────────────────────────────────────────────────
// 每个代号对应一套 ECH 参数，可在 DOMAIN_RULES 中按代号引用
//
// 字段说明：
//   sourceDomain    — 拉取 ECH 数据时使用的源域名（仅 mode:'fetch' 时发起网络请求）
//   mode            — 'local' : 始终使用 localData，零网络请求（推荐）
//                    'fetch' : 优先从上游拉取，失败自动回退 localData
//   localData       — Base64 编码的 ECH 配置（mode:'local' 必填；'fetch' 作为回退）
//   soaKeyword      — SOA 记录中包含此关键字时，判定该域名属于此 ECH 类型
//                     用于未命中 DOMAIN_RULES 的域名自动检测
//   staticDomains   — 静态白名单：直接命中，跳过 SOA 查询
//   defaultIpListV4 — 自动检测匹配后使用的默认 ipListV4 列表名（null = 不处理）
//   defaultIpListV6 — 自动检测匹配后使用的默认 ipListV6 列表名（null = 不处理）
const ECH_TYPES = {
  'cf': {
    sourceDomain:    'cloudflare-ech.com',
    mode:            'local',
    localData:       'AEX+DQBBFAAgACApLi37Py03Z3TinersGhjjAEUIL3f9fMaU+5eDjSoHAAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=',
    soaKeyword:      'cloudflare.com',
    staticDomains:   ['workers.dev', 'pages.dev', 'cloudflarestatus.com'],
    defaultIpListV4: 'cf',
    defaultIpListV6: null,
  },
  // 示例：其他 CDN 类型
  // 'fastly': {
  //   sourceDomain:    'fastly-ech.example.com',
  //   mode:            'fetch',
  //   localData:       '<base64>',
  //   soaKeyword:      'fastly.com',
  //   staticDomains:   [],
  //   defaultIpListV4: 'fastly4',
  //   defaultIpListV6: null,
  // },
};

// ── 域名规则 ──────────────────────────────────────────────────────
// domain 匹配模式（优先级从上到下，首次命中即生效）：
//   精确匹配   — 'example.com'
//   一级子域名 — '*.example.com'    仅匹配 foo.example.com（不含 a.b.example.com）
//   无限子域名 — '^*.example.com'   匹配所有深度子域名（含精确值本身）
//
// 字段说明：
//   ipListV4 — 引用 ipListV4 对象中的列表名（null 或省略 = 不处理 A/ipv4hint）
//   ipListV6 — 引用 ipListV6 对象中的列表名（null 或省略 = 不处理 AAAA/ipv6hint）
//   echType  — 引用 ECH_TYPES 中的代号（null 或省略 = HTTPS 记录不含 ECH）
const DOMAIN_RULES = [
  { domain: '*.twimg.com',    ipListV4: 'cf', echType: 'cf' },
  { domain: 'twitter.com',    ipListV4: 'cf', echType: 'cf' },
  { domain: '*.twitter.com',  ipListV4: 'cf', echType: 'cf' },
  { domain: 'x.com',          ipListV4: 'cf', echType: 'cf' },
  { domain: '*.x.com',        ipListV4: 'cf', echType: 'cf' },
];

// ── 上游 DNS ──────────────────────────────────────────────────────
// Snippets 模式下只使用第一个（subrequest 配额限制）
const UPSTREAM_DNS_SERVERS = [
  'https://chrome.cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.quad9.net/dns-query',
];

// ── 缓存开关 ──────────────────────────────────────────────────────
const CACHE = {
  // ECH 类型检测结果 — 内存缓存（isolate 级别，0 延迟）
  MEM_CF:         true,
  MEM_CF_TTL:     1_800_000,   // ms，30 分钟
  MEM_CF_MAX:     500,

  // ECH 配置 — 内存缓存
  MEM_ECH:        true,

  // IP 列表解析结果 — 内存缓存（避免重复 DNS 解析域名型 IP 条目）
  MEM_IP:         true,
  MEM_IP_TTL:     300_000,     // ms，5 分钟

  // ECH 类型检测结果 — 持久化缓存（CF Cache API，跨 isolate）
  // Snippets 不支持 Cache API，SNIPPETS_MODE=true 时自动禁用
  PERSIST_CF:     true,
  PERSIST_CF_TTL: 3600,        // 秒，1 小时

  // ECH 配置 — 持久化缓存（仅在 mode:'fetch' 时有意义）
  PERSIST_ECH:    true,
  PERSIST_ECH_TTL: 86400,      // 秒，24 小时
};

const DNSSEC_BLOCKED = new Set([43, 46, 47, 48, 50]);

// ── 运行时派生配置（根据 SNIPPETS_MODE 自动计算，无需手动修改）────
const _PERSIST_CF  = CACHE.PERSIST_CF  && !SNIPPETS_MODE;
const _PERSIST_ECH = CACHE.PERSIST_ECH && !SNIPPETS_MODE;
const _ALPN_PROTOS = SNIPPETS_MODE ? ['h3', 'h2'] : ['h3'];

// ── 内存缓存实例 ───────────────────────────────────────────────────
// domain → { echType: string|null, ts: number }
const memCfCache   = new Map();
// typeName → Uint8Array
const memEchCaches = Object.create(null);
// 'v4:listName' | 'v6:listName' → { ips: string[], ts: number }
const memIpCache   = new Map();

// ── 启动时预计算 ───────────────────────────────────────────────────
const TTL_BYTES = [
  (OPTIMIZED_TTL >> 24) & 0xFF,
  (OPTIMIZED_TTL >> 16) & 0xFF,
  (OPTIMIZED_TTL >> 8)  & 0xFF,
   OPTIMIZED_TTL        & 0xFF,
];
const ALPN_H3 = encodeAlpn(_ALPN_PROTOS);

// ══════════════════════════════════════════════════════════════════
// Debug
// ══════════════════════════════════════════════════════════════════

function log(...args) {
  if (DEBUG) console.log('[DoH]', ...args);
}

// ══════════════════════════════════════════════════════════════════
// Entry
// ══════════════════════════════════════════════════════════════════

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  }
};

async function handleRequest(request, env) {
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

    // ── 显式域名规则优先 ────────────────────────────────────────
    const rule = matchDomainRule(queryName);
    if (rule) {
      log(`domain rule matched: ${queryName}`);
      return handleRuleQuery(queryType, dnsQuery, rule, env);
    }

    // ── 自动 ECH 类型检测 ────────────────────────────────────────
    if (SNIPPETS_MODE) {
      const echType = await detectDomainEchType(queryName, env);
      log(`ECH type for ${queryName}: ${echType}`);
      if (echType) {
        return handleRuleQuery(queryType, dnsQuery, createSyntheticRule(echType), env);
      }
      return filterDnssecFromResponse(await forwardToUpstream(dnsQuery));
    } else {
      // Worker 模式：并行竞速，检测完成后 abort 上游节省带宽
      const abort           = new AbortController();
      const upstreamPromise = forwardToUpstream(dnsQuery, abort.signal);
      const echType         = await detectDomainEchType(queryName, env);
      log(`ECH type for ${queryName}: ${echType}`);
      if (echType) {
        abort.abort();
        return handleRuleQuery(queryType, dnsQuery, createSyntheticRule(echType), env);
      }
      return filterDnssecFromResponse(await upstreamPromise);
    }

  } catch (err) {
    log(`handleRequest error: ${err?.message}`);
    return new Response('Internal Server Error', { status: 500 });
  }
}

// ══════════════════════════════════════════════════════════════════
// Rule Query Handler
// 根据匹配到的规则（或自动检测生成的合成规则）构造 DNS 响应
// ══════════════════════════════════════════════════════════════════

async function handleRuleQuery(queryType, originalQuery, rule, env) {
  // 解析规则引用的 IP 列表（含域名型条目自动解析，带内存缓存）
  // 注意：Snippets 模式下域名型条目解析会消耗 subrequest 配额
  const [ipv4s, ipv6s] = await Promise.all([
    resolveIpList(rule.ipListV4 ?? null, 4),
    resolveIpList(rule.ipListV6 ?? null, 6),
  ]);

  log(`handleRuleQuery type=${queryType} ipv4s=[${ipv4s}] ipv6s=[${ipv6s}] ech=${rule.echType}`);

  if (queryType === 1) {    // A
    return ipv4s.length
      ? createARecordResponse(originalQuery, ipv4s)
      : createEmptyDnsResponse(originalQuery);
  }

  if (queryType === 28) {   // AAAA
    return ipv6s.length
      ? createAAAAResponse(originalQuery, ipv6s)
      : createEmptyDnsResponse(originalQuery);
  }

  if (queryType === 5)      // CNAME
    return createEmptyDnsResponse(originalQuery);

  if (queryType === 65) {   // HTTPS (SVCB)
    const ech = rule.echType ? await getEchConfig(rule.echType, env) : null;
    return createHttpsResponse(originalQuery, ipv4s, ipv6s, ech);
  }

  // 其余类型转发上游
  return filterDnssecFromResponse(await forwardToUpstream(originalQuery));
}

// ══════════════════════════════════════════════════════════════════
// Domain Rule Matching
// 匹配顺序：精确 > 一级通配 (*.x) > 无限通配 (^*.x)
// ══════════════════════════════════════════════════════════════════

function matchDomainRule(queryName) {
  const name = queryName.toLowerCase();
  for (const rule of DOMAIN_RULES) {
    const pat = rule.domain.toLowerCase();

    if (pat.startsWith('^*.')) {
      // 无限级子域名：^*.abc.gov.cn 匹配 foo.abc.gov.cn、a.b.abc.gov.cn …
      const suffix = pat.slice(3);
      if (name === suffix || name.endsWith('.' + suffix)) return rule;

    } else if (pat.startsWith('*.')) {
      // 仅一级子域名：*.abc.gov.cn 只匹配 foo.abc.gov.cn
      const suffix = pat.slice(2);
      if (name.endsWith('.' + suffix)) {
        const sub = name.slice(0, name.length - suffix.length - 1);
        if (!sub.includes('.')) return rule;
      }

    } else {
      // 精确匹配
      if (name === pat) return rule;
    }
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════
// IP List Resolution
// 将列表名解析为实际 IP 数组，域名型条目自动通过 DoH JSON API 解析
// 结果带内存缓存，TTL = CACHE.MEM_IP_TTL
// ══════════════════════════════════════════════════════════════════

async function resolveIpList(listName, version) {
  if (!listName) return [];

  const cacheKey = `v${version}:${listName}`;
  const now = Date.now();

  if (CACHE.MEM_IP) {
    const hit = memIpCache.get(cacheKey);
    if (hit && now - hit.ts < CACHE.MEM_IP_TTL) {
      log(`IP list cache hit: ${cacheKey} ips=[${hit.ips}]`);
      return hit.ips;
    }
  }

  const rawList = version === 4 ? (ipListV4[listName] ?? '') : (ipListV6[listName] ?? '');
  const items   = rawList.split(',').map(s => s.trim()).filter(Boolean);
  const ips     = [];

  for (const item of items) {
    // ipListV4: 含字母 → 域名；否则 → IPv4 地址
    // ipListV6: 不含 ":" → 域名；否则 → IPv6 地址
    const isDomain = version === 4 ? /[a-zA-Z]/.test(item) : !item.includes(':');

    if (isDomain) {
      const resolved = version === 4
        ? await resolveViaDoH(item, 1)    // A record
        : await resolveViaDoH(item, 28);  // AAAA record
      log(`resolved ${item} (v${version}): [${resolved}]`);
      ips.push(...resolved);
    } else {
      ips.push(item);
    }
  }

  if (CACHE.MEM_IP) memIpCache.set(cacheKey, { ips, ts: now });
  return ips;
}

// DoH JSON API 解析辅助（1.1.1.1）
async function resolveViaDoH(domain, rrType) {
  const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${rrType}`;
  try {
    const r = await fetch(url, { headers: { accept: 'application/dns-json' } });
    if (!r.ok) return [];
    const data = await r.json();
    return (data.Answer ?? []).filter(rr => rr.type === rrType).map(rr => rr.data);
  } catch { return []; }
}

// ══════════════════════════════════════════════════════════════════
// Synthetic Rule (auto-detected domains)
// 将 ECH 类型的默认 IP 列表封装成与 DOMAIN_RULES 同结构的规则对象
// ══════════════════════════════════════════════════════════════════

function createSyntheticRule(echTypeName) {
  const cfg = ECH_TYPES[echTypeName];
  return {
    ipListV4: cfg?.defaultIpListV4 ?? null,
    ipListV6: cfg?.defaultIpListV6 ?? null,
    echType:  echTypeName,
  };
}

// ══════════════════════════════════════════════════════════════════
// ECH Type Detection
// 查找顺序：内存缓存 → ECH 类型静态白名单 → 持久化缓存 → SOA 查询
// ══════════════════════════════════════════════════════════════════

async function detectDomainEchType(domain, env) {
  const key = domain.toLowerCase();
  const now = Date.now();

  // 1. 内存缓存
  if (CACHE.MEM_CF) {
    const hit = memCfCache.get(key);
    if (hit && now - hit.ts < CACHE.MEM_CF_TTL) {
      log(`ECH type mem-cache hit: ${domain} type=${hit.echType}`);
      return hit.echType;
    }
  }

  // 2. ECH 类型静态白名单
  for (const [typeName, cfg] of Object.entries(ECH_TYPES)) {
    if (cfg.staticDomains?.some(d => domain === d || domain.endsWith('.' + d))) {
      log(`ECH type static list hit: ${domain} → ${typeName}`);
      writeEchTypeCache(key, typeName, now, env);
      return typeName;
    }
  }

  // 3. 持久化缓存（Worker 模式）
  if (_PERSIST_CF) {
    const cached = await persistGet('echtype:' + key);
    if (cached !== null) {
      const echType = cached || null;
      log(`ECH type persist-cache hit: ${domain} → ${echType}`);
      if (CACHE.MEM_CF) memCfCache.set(key, { echType, ts: now });
      return echType;
    }
  }

  // 4. SOA 查询 — 检查各 ECH 类型的 soaKeyword
  let detectedType = null;
  try {
    const soaData = await querySoaData(domain);
    log(`SOA data for ${domain}: ${soaData.slice(0, 200)}`);
    for (const [typeName, cfg] of Object.entries(ECH_TYPES)) {
      if (cfg.soaKeyword && soaData.includes(cfg.soaKeyword.toLowerCase())) {
        detectedType = typeName;
        break;
      }
    }
  } catch {}

  log(`ECH type SOA result for ${domain}: ${detectedType}`);
  writeEchTypeCache(key, detectedType, now, env);
  return detectedType;
}

function writeEchTypeCache(key, echType, now, env) {
  if (CACHE.MEM_CF) {
    memCfCache.set(key, { echType, ts: now });
    if (memCfCache.size > CACHE.MEM_CF_MAX && Math.random() < 0.05) {
      const cutoff = now - CACHE.MEM_CF_TTL;
      for (const [k, v] of memCfCache) if (v.ts < cutoff) memCfCache.delete(k);
    }
  }
  if (_PERSIST_CF)
    persistSet('echtype:' + key, echType ?? '', CACHE.PERSIST_CF_TTL).catch(() => {});
}

// ══════════════════════════════════════════════════════════════════
// SOA Query
// Worker 模式：两服务器并行竞速；Snippets 模式：仅 1.1.1.1
// 返回 lowercase SOA rdata 字符串，未找到则返回 ''
// ══════════════════════════════════════════════════════════════════

async function querySoaData(domain) {
  if (SNIPPETS_MODE) {
    return querySoaDataSingle(domain, 'https://1.1.1.1/dns-query');
  }
  const results = await Promise.allSettled([
    querySoaDataSingle(domain, 'https://1.1.1.1/dns-query'),
    querySoaDataSingle(domain, 'https://dns.google/resolve'),
  ]);
  for (const r of results) if (r.status === 'fulfilled' && r.value) return r.value;
  return '';
}

async function querySoaDataSingle(domain, baseUrl) {
  const url = `${baseUrl}?name=${encodeURIComponent(domain)}&type=SOA`;
  const r = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const data = await r.json();
  log(`SOA raw [${domain}] from ${baseUrl}: ${JSON.stringify(data).slice(0, 400)}`);
  for (const section of [data.Answer, data.Authority]) {
    if (!Array.isArray(section)) continue;
    for (const rr of section) {
      if (rr.type === 6) return rr.data.toLowerCase();
    }
  }
  return '';
}

// ══════════════════════════════════════════════════════════════════
// ECH Config
// 支持多 ECH 类型，各自独立缓存
// ══════════════════════════════════════════════════════════════════

async function getEchConfig(typeName, env) {
  const cfg = ECH_TYPES[typeName];
  if (!cfg) return null;

  // 'local' 模式：直接使用内置数据，零网络请求
  if (cfg.mode === 'local') {
    if (!memEchCaches[typeName])
      memEchCaches[typeName] = base64UrlDecode(cfg.localData);
    return memEchCaches[typeName];
  }

  // 'fetch' 模式：优先内存缓存 → 持久化缓存 → 上游拉取 → 回退本地
  if (CACHE.MEM_ECH && memEchCaches[typeName]) {
    log(`ECH mem-cache hit: ${typeName}`);
    return memEchCaches[typeName];
  }

  if (_PERSIST_ECH) {
    const cached = await persistGet(`ech:${typeName}`);
    if (cached) {
      log(`ECH persist-cache hit: ${typeName}`);
      const ech = base64UrlDecode(cached);
      if (CACHE.MEM_ECH) memEchCaches[typeName] = ech;
      return ech;
    }
  }

  try {
    const q    = stripDnssecFromQuery(buildDnsQuery(cfg.sourceDomain, 65));
    const resp = await forwardToUpstream(q);
    const ech  = extractEchFromHttpsResponse(new Uint8Array(await resp.arrayBuffer()));
    if (ech?.length) {
      log(`ECH fetched from upstream: ${typeName}`);
      if (CACHE.MEM_ECH) memEchCaches[typeName] = ech;
      if (_PERSIST_ECH)
        persistSet(`ech:${typeName}`, base64UrlEncode(ech), CACHE.PERSIST_ECH_TTL).catch(() => {});
      return ech;
    }
  } catch {}

  log(`ECH using local fallback: ${typeName}`);
  const fallback = base64UrlDecode(cfg.localData);
  if (CACHE.MEM_ECH) memEchCaches[typeName] = fallback;
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
      off += 3; // skip priority + target root label
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
// Persistent Cache (Worker 模式：CF Cache API；Snippets 模式：空操作)
// ══════════════════════════════════════════════════════════════════

const PERSIST_NS = 'https://doh-internal.cache/';

async function persistGet(key) {
  if (SNIPPETS_MODE) return null;
  try {
    const res = await caches.default.match(new Request(PERSIST_NS + key));
    if (!res) return null;
    return await res.text();
  } catch { return null; }
}

async function persistSet(key, value, ttlSec) {
  if (SNIPPETS_MODE) return;
  try {
    await caches.default.put(
      new Request(PERSIST_NS + key),
      new Response(value, {
        headers: {
          'Cache-Control': `public, max-age=${ttlSec}`,
          'Content-Type':  'text/plain',
        },
      })
    );
  } catch {}
}

// ══════════════════════════════════════════════════════════════════
// Upstream Forwarding
// Worker 模式：多源并行竞速（Promise.any），支持 abort
// Snippets 模式：仅第一个服务器（严格控制 subrequest）
// ══════════════════════════════════════════════════════════════════

async function forwardToUpstream(dnsQuery, signal) {
  const b64        = base64UrlEncode(dnsQuery);
  const fetch_opts = { headers: { accept: 'application/dns-message' }, signal };

  if (SNIPPETS_MODE) {
    log(`forwardToUpstream → ${UPSTREAM_DNS_SERVERS[0]}`);
    try {
      const r = await fetch(`${UPSTREAM_DNS_SERVERS[0]}?dns=${b64}`, fetch_opts);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      log('upstream responded ok');
      return new Response(r.body, { headers: { 'content-type': 'application/dns-message' } });
    } catch (e) {
      if (signal?.aborted) return new Response('Aborted', { status: 499 });
      throw e;
    }
  }

  log(`forwardToUpstream racing ${UPSTREAM_DNS_SERVERS.length} servers`);
  const races = UPSTREAM_DNS_SERVERS.map(s =>
    fetch(`${s}?dns=${b64}`, fetch_opts).then(r =>
      r.ok ? r : Promise.reject(new Error(String(r.status)))
    )
  );

  try {
    const r = await Promise.any(races);
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

// HTTPS (type 65) SVCB 记录
// SvcParams 按 key 升序排列（RFC 9460 要求）：alpn(1) < ipv4hint(4) < ech(5) < ipv6hint(6)
function createHttpsResponse(originalQuery, ipv4s, ipv6s, ech) {
  const data = [0x00, 0x01, 0x00]; // SvcPriority=1, TargetName="." (root label)

  // key 1: alpn
  data.push(0x00, 0x01,
    (ALPN_H3.length >> 8) & 0xFF, ALPN_H3.length & 0xFF,
    ...ALPN_H3);

  // key 4: ipv4hint
  if (ipv4s.length) {
    const bytes = ipv4s.flatMap(ip => ip.split('.').map(Number));
    data.push(0x00, 0x04, (bytes.length >> 8) & 0xFF, bytes.length & 0xFF, ...bytes);
  }

  // key 5: ech
  if (ech?.length)
    data.push(0x00, 0x05, (ech.length >> 8) & 0xFF, ech.length & 0xFF, ...ech);

  // key 6: ipv6hint
  if (ipv6s.length) {
    const bytes = ipv6s.flatMap(ip => Array.from(parseIPv6(ip)));
    data.push(0x00, 0x06, (bytes.length >> 8) & 0xFF, bytes.length & 0xFF, ...bytes);
  }

  return buildRRResponse(originalQuery, 65, new Uint8Array(data));
}

// A 记录响应（多 IP）
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

// AAAA 记录响应（多 IP）
function createAAAAResponse(originalQuery, ips) {
  const hdr = new Uint8Array(originalQuery);
  hdr[2] = 0x81; hdr[3] = 0x80;
  hdr[6] = 0x00; hdr[7] = ips.length;

  const chunks = [];
  for (const ip of ips) {
    const rdata = parseIPv6(ip);
    chunks.push(
      0xC0, 0x0C,         // name pointer
      0x00, 0x1C,         // type AAAA
      0x00, 0x01,         // class IN
      TTL_BYTES[0], TTL_BYTES[1], TTL_BYTES[2], TTL_BYTES[3],
      0x00, 0x10,         // rdlength = 16
      ...rdata
    );
  }

  const ans = new Uint8Array(chunks);
  const out = new Uint8Array(hdr.length + ans.length);
  out.set(hdr);
  out.set(ans, hdr.length);
  return new Response(out, { headers: { 'content-type': 'application/dns-message' } });
}

// 空响应（NOERROR, ANCOUNT=0）
function createEmptyDnsResponse(originalQuery) {
  const r = new Uint8Array(originalQuery);
  r[2] = 0x81; r[3] = 0x80;
  r[6] = 0x00; r[7] = 0x00;
  return new Response(r, { headers: { 'content-type': 'application/dns-message' } });
}

// 通用单 RR 响应构造器（用于 HTTPS 等）
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

// ══════════════════════════════════════════════════════════════════
// IPv6 Parsing
// ══════════════════════════════════════════════════════════════════

function parseIPv6(ip) {
  const bytes = new Uint8Array(16);
  const halves = ip.split('::');

  if (halves.length === 2) {
    const left  = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    let p = 0;
    for (const g of left) {
      const v = parseInt(g, 16);
      bytes[p++] = (v >> 8) & 0xFF;
      bytes[p++] = v & 0xFF;
    }
    p = 16 - right.length * 2;
    for (const g of right) {
      const v = parseInt(g, 16);
      bytes[p++] = (v >> 8) & 0xFF;
      bytes[p++] = v & 0xFF;
    }
  } else {
    let p = 0;
    for (const g of ip.split(':')) {
      const v = parseInt(g, 16);
      bytes[p++] = (v >> 8) & 0xFF;
      bytes[p++] = v & 0xFF;
    }
  }

  return bytes;
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

  const anCount = (resp[6]  << 8) | resp[7];
  const nsCount = (resp[8]  << 8) | resp[9];
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
