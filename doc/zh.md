# DoH Proxy Worker

基于 Cloudflare Workers / Snippets 的 DNS-over-HTTPS 代理，支持：

- 多 CDN ECH（Encrypted Client Hello）自动检测与注入
- 灵活的域名规则与 IP 列表覆写
- EDNS Client Subnet（ECS）强制指定
- DNSSEC 记录过滤
- 内存 + 持久化多级缓存（Worker 模式）

---

## 目录

- [快速开始](#快速开始)
- [部署方式](#部署方式)
  - [Cloudflare Workers](#cloudflare-workers)
  - [Cloudflare Snippets](#cloudflare-snippets)
- [配置参考](#配置参考)
  - [基础开关](#基础开关)
  - [ECS 配置](#ecs-配置)
  - [IP 地址列表](#ip-地址列表)
  - [ECH 类型配置](#ech-类型配置)
  - [域名规则](#域名规则)
  - [上游 DNS](#上游-dns)
  - [缓存开关](#缓存开关)
- [域名匹配语法](#域名匹配语法)
- [IP 列表解析规则](#ip-列表解析规则)
- [工作流程说明](#工作流程说明)
- [常见问题](#常见问题)

---

## 快速开始

1. 将 `worker.js` 复制到 Cloudflare Workers 编辑器（或 Snippets）。
2. 根据需求修改顶部 Config 区域。
3. 部署后，将 DoH 地址设置为：

```
https://<your-worker-domain>/linuxdo/dns-query
```

支持 RFC 8484 的 GET（`?dns=<base64url>`）和 POST（`Content-Type: application/dns-message`）请求。

---

## 部署方式

### Cloudflare Workers

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)。
2. 进入 **Workers & Pages → Create Worker**。
3. 粘贴 `worker.js` 内容，点击 **Deploy**。
4. 将顶部 `SNIPPETS_MODE` 设为 `false`（启用并行竞速、持久化缓存）。

> **注意**：Worker 模式支持并行竞速多上游、CF Cache API 持久化缓存，适合高频使用场景。

### Cloudflare Snippets

1. 进入 **Websites → 你的域名 → Snippets**。
2. 新建 Snippet，粘贴 `worker.js`，配置路由规则匹配 `/linuxdo/dns-query`。
3. 保持顶部 `SNIPPETS_MODE = true`（串行执行，严格控制 subrequest 配额）。

> **注意**：Snippets 免费版每次请求 subrequest 配额有限，模式下每次查询最多消耗约 2 个（SOA + 上游）。

---

## 配置参考

所有配置项均集中在文件顶部 `Config` 区域，按需修改。

### 基础开关

```js
const SNIPPETS_MODE = true;   // true → Snippets 模式；false → Worker 模式
const ALLOWED_PATH  = '/linuxdo/dns-query';  // DoH 监听路径
const OPTIMIZED_TTL = 1;      // 所有自构造 DNS 响应的 TTL（秒）
const DEBUG         = false;  // 调试日志（输出到 console.log）
```

---

### ECS 配置

```js
const ECS_IP = '1.2.4.8';  // 强制附带的 EDNS Client Subnet（使用 /24 前缀）
                            // 设为 null 或 '' 禁用 ECS
```

Worker 会在所有转发至上游的查询中追加 OPT 附加记录（RFC 7871），指定 ECS 为 `1.2.4.8/24`。这会引导上游服务器返回针对该 IP 段优化的解析结果（例如 CDN 就近节点）。

> ECS 仅附加在转发至上游的查询中。由域名规则或 ECH 类型命中、在本地构造响应的查询不发送 ECS。

---

### IP 地址列表

```js
const ipListV4 = {
  'cf': '91.193.58.2,91.193.58.21',
  // 'mylist': '1.2.3.4,cdn.example.com,5.6.7.8',
};

const ipListV6 = {
  // 'cf6': '2606:4700::6810:f8f8,2606:4700::6810:f9f8',
  // 'mylist6': '::1,ipv6cdn.example.com',
};
```

- 列表名（如 `'cf'`）作为 Key，在 `DOMAIN_RULES` 和 `ECH_TYPES` 中引用。
- 每个 Value 是逗号分隔的 IP 或域名字符串。
- 解析规则见下方 [IP 列表解析规则](#ip-列表解析规则)。

---

### ECH 类型配置

```js
const ECH_TYPES = {
  'cf': {
    sourceDomain:    'cloudflare-ech.com',   // 拉取 ECH 时查询的源域名
    mode:            'local',                // 'local' | 'fetch'
    localData:       '<Base64 编码的 ECH>',  // 本地数据 / fetch 回退数据
    soaKeyword:      'cloudflare.com',       // SOA 记录中含此关键字 → 命中此类型
    staticDomains:   ['workers.dev', 'pages.dev', 'cloudflarestatus.com'],
    defaultIpListV4: 'cf',                   // 自动检测命中后使用的 ipListV4
    defaultIpListV6: null,                   // 自动检测命中后使用的 ipListV6
  },
};
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `sourceDomain` | `string` | 仅 `mode:'fetch'` 时有意义，用于从上游拉取 ECH 配置 |
| `mode` | `'local'` \| `'fetch'` | `local`：始终用内置数据，零网络请求（推荐）；`fetch`：优先拉取，失败回退 `localData` |
| `localData` | `string` | Base64（标准或 URL-safe）编码的 ECH 二进制数据 |
| `soaKeyword` | `string` | SOA 记录 rdata 中包含该字符串时，判定该域名归属此类型 |
| `staticDomains` | `string[]` | 直接命中的域名列表（含子域名），跳过 SOA 查询 |
| `defaultIpListV4` | `string \| null` | 自动检测命中后，使用的 `ipListV4` 列表名 |
| `defaultIpListV6` | `string \| null` | 自动检测命中后，使用的 `ipListV6` 列表名 |

可以配置多个 ECH 类型，SOA 检测时遍历所有类型的 `soaKeyword`，首次命中即生效。

---

### 域名规则

```js
const DOMAIN_RULES = [
  { domain: '#twimg.com',   ipListV4: 'cf', echType: 'cf' },
  { domain: '#twitter.com', ipListV4: 'cf', echType: 'cf' },
  { domain: '#x.com',       ipListV4: 'cf', echType: 'cf' },
];
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `domain` | `string` | 匹配模式，语法见下方 [域名匹配语法](#域名匹配语法) |
| `ipListV4` | `string \| null` | 引用 `ipListV4` 中的列表名；`null` 或省略表示不处理 A 记录和 ipv4hint |
| `ipListV6` | `string \| null` | 引用 `ipListV6` 中的列表名；`null` 或省略表示不处理 AAAA 记录和 ipv6hint |
| `echType` | `string \| null` | 引用 `ECH_TYPES` 中的代号；`null` 或省略表示 HTTPS 记录不含 ECH 字段 |

规则按数组顺序匹配，首次命中即生效。

---

### 上游 DNS

```js
const UPSTREAM_DNS_SERVERS = [
  'https://dns.google/dns-query',
  'https://dns.alidns.com/dns-query',
];
```

- **Worker 模式**：所有服务器并行竞速（`Promise.any`），最快响应者胜出。
- **Snippets 模式**：仅使用列表中第一个服务器（严格控制 subrequest 配额）。

---

### 缓存开关

```js
const CACHE = {
  MEM_CF:          true,        // ECH 类型检测结果 — 内存缓存
  MEM_CF_TTL:      1_800_000,   // 内存缓存有效期（ms，默认 30 分钟）
  MEM_CF_MAX:      500,         // 内存缓存最大条目数（LRU 概率淘汰）

  MEM_ECH:         true,        // ECH 配置 — 内存缓存

  MEM_IP:          true,        // IP 列表解析结果 — 内存缓存
  MEM_IP_TTL:      300_000,     // IP 列表内存缓存有效期（ms，默认 5 分钟）

  PERSIST_CF:      true,        // ECH 类型检测结果 — 持久化缓存（CF Cache API）
  PERSIST_CF_TTL:  3600,        // 持久化缓存有效期（秒，默认 1 小时）

  PERSIST_ECH:     true,        // ECH 配置 — 持久化缓存（仅 mode:'fetch' 时有意义）
  PERSIST_ECH_TTL: 86400,       // ECH 持久化缓存有效期（秒，默认 24 小时）
};
```

> `PERSIST_CF` 和 `PERSIST_ECH` 在 `SNIPPETS_MODE=true` 时自动禁用（Snippets 不支持 Cache API）。

---

## 域名匹配语法

| 语法 | 示例 | 命中 | 不命中 |
|------|------|------|--------|
| 精确匹配 | `'example.com'` | `example.com` | `foo.example.com` |
| 一级子域名 | `'*.example.com'` | `foo.example.com` | `example.com`、`a.b.example.com` |
| 无限级子域名 | `'^*.example.com'` | `foo.example.com`、`a.b.example.com` | `example.com` |
| 全域名 | `'#example.com'` | `example.com`、`foo.example.com`、`a.b.example.com` | — |

匹配顺序为 DOMAIN_RULES 数组顺序，**首次命中即生效，后续规则不再检查**。

---

## IP 列表解析规则

### ipListV4

逗号分隔的条目，每项独立判断：

- **含字母** → 视为域名，自动对其发起 **A 记录查询**，查询结果（可能是多个 IP）展开并合并进列表。
- **纯点分十进制** → 直接作为 IPv4 地址使用。

解析后的完整 IP 列表：
- 用于回答 **A（type 1）** 查询
- 用于 HTTPS（type 65）记录的 **ipv4hint** SvcParam

### ipListV6

逗号分隔的条目，每项独立判断：

- **不含 `:`** → 视为域名，自动对其发起 **AAAA 记录查询**，结果展开并合并进列表。
- **含 `:`** → 直接作为 IPv6 地址使用。

解析后的完整 IP 列表：
- 用于回答 **AAAA（type 28）** 查询
- 用于 HTTPS（type 65）记录的 **ipv6hint** SvcParam

IP 列表解析结果带内存缓存（`CACHE.MEM_IP_TTL`），TTL 内不重复发起 DNS 解析请求。

---

## 工作流程说明

### 请求处理流程

```
收到 DNS 查询
    │
    ├─ 是否为 DNSSEC 记录类型（DS/RRSIG/NSEC/NSEC3/CDS）？
    │       是 → 返回空响应（NOERROR, ANCOUNT=0）
    │
    ├─ 命中 DOMAIN_RULES？
    │       是 → 按规则构造响应（A/AAAA/HTTPS/转发）
    │
    └─ 自动 ECH 类型检测
            ├─ 内存缓存命中 → 按 ECH 类型默认规则构造响应
            ├─ 静态白名单命中 → 同上
            ├─ 持久化缓存命中（Worker 模式）→ 同上
            ├─ SOA 查询 → 匹配 soaKeyword → 同上
            └─ 无匹配 → 查询附带 ECS，转发至上游
```

### 响应构造逻辑（命中规则后）

| 查询类型 | 有 ipListV4 | 无 ipListV4 | 有 ipListV6 | 无 ipListV6 |
|----------|-------------|-------------|-------------|-------------|
| A (1) | 返回 A 记录 | 返回空响应 | — | — |
| AAAA (28) | — | — | 返回 AAAA 记录 | 返回空响应 |
| CNAME (5) | 返回空响应（屏蔽） | — | — | — |
| HTTPS (65) | ipv4hint 填入 | ipv4hint 省略 | ipv6hint 填入 | ipv6hint 省略 |
| 其他 | 查询附带 ECS，转发至上游 | — | — | — |

HTTPS 记录 SvcParams 严格按 RFC 9460 升序排列：`alpn(1) < ipv4hint(4) < ech(5) < ipv6hint(6)`。

### ECH 类型检测缓存层级

```
内存缓存（0ms，isolate 级别）
    ↓ miss
ECH_TYPES.staticDomains 静态白名单
    ↓ miss
CF Cache API 持久化缓存（Worker 模式，跨 isolate）
    ↓ miss
SOA 查询 → 匹配各 ECH 类型的 soaKeyword
    ↓ 结果写入内存 + 持久化缓存
```

---

## 常见问题

**Q：为什么命中规则的域名的 AAAA 返回空响应？**

A：规则中未配置 `ipListV6`，或配置了空列表。如需返回 AAAA 记录，在 `ipListV6` 中添加对应列表并在规则中引用。

---

**Q：Snippets 模式下 subrequest 会超限吗？**

A：正常情况下每次查询最多消耗：

- 缓存命中时：0（SOA）+ 1（上游）= **1 个**
- 未命中时：1（SOA）+ 1（上游）= **2 个**
- IP 列表含域名型条目：额外 +1 个（每个域名条目各一次，有内存缓存保护）

---

**Q：`'*.example.com'` 和 `'^*.example.com'` 有什么区别？**

A：

- `'*.example.com'` 只命中 **一级**子域名，如 `foo.example.com`，不命中 `a.b.example.com`。
- `'^*.example.com'` 命中所有深度子域名，如 `foo.example.com`、`a.b.example.com`，但 **不命中 `example.com` 本身**。
- 如果需要同时命中本身及所有子域名，使用 `'#example.com'`。

---

**Q：如何为不同 CDN 配置独立的 ECH 和 IP 列表？**

A：在 `ECH_TYPES` 中新增类型，在 `ipListV4` / `ipListV6` 中新增列表，然后在 `DOMAIN_RULES` 中引用：

```js
const ipListV4 = {
  'cf':     '91.193.58.2,91.193.58.21',
  'fastly': '151.101.1.1,151.101.65.1',
};

const ECH_TYPES = {
  'cf': { /* ... */ },
  'fastly': {
    sourceDomain:    'fastly-ech.example.com',
    mode:            'fetch',
    localData:       '<base64 回退数据>',
    soaKeyword:      'fastly.com',
    staticDomains:   [],
    defaultIpListV4: 'fastly',
    defaultIpListV6: null,
  },
};

const DOMAIN_RULES = [
  { domain: '#fastly-site.com', ipListV4: 'fastly', echType: 'fastly' },
  { domain: '#x.com',           ipListV4: 'cf',     echType: 'cf'     },
];
```

---

**Q：ECS 会影响隐私吗？**

A：ECS 会将客户端 IP 前缀（本配置中固定为 `1.2.4.8/24`）发送给上游 DNS 服务器，属于公开 IP。由于此处填写的是固定 IP（非真实客户端 IP），不会泄露真实用户位置。若有隐私需求，可将 `ECS_IP` 设为 `null` 禁用 ECS。

---

**Q：`OPTIMIZED_TTL` 设得很低会有问题吗？**

A：`OPTIMIZED_TTL` 仅影响 Worker **本地构造**的 DNS 响应（A/AAAA/HTTPS 记录），不影响从上游透传的响应。设为 `1` 秒意味着客户端每次查询都会重新访问 Worker，但由于 Worker 本身有内存缓存，实际性能影响极小。

---

## License

MIT
