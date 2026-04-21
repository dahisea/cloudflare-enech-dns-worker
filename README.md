# 给 CloudFlare (以及其它) CDN 网站强制开启 ECH 的 DNS

# cloudflare-enech-dns-worker
A dns server that enable ech for all cf hosted domains.

# 特性
0. 其实最初的初衷只是搞点优选ip
1. 优选ip至~~菠菜专用的~~企业版BYOIP，主打高速高包容性
2. 去除了部分与安全相关的记录的查询（DNSSEC），不然没法优选改ip
3. 可本地锁死ech，也可诺言查询并挪用其它域名作上游，ech数据有的域名不同，但反正cf的outSNI都是cloudflare-ech.com
4. 仅用于尝鲜体验ech特性，并不能长期使用，只是说暂时能用，cf会怎样采取措施封堵也不确定
5. 本项目通过查询SOA记录来确定是否接入cf的服务，之前是用的psl+ns推演感觉不太好用就作罢了，实际上还可以简单粗暴用a/aaaa检测加as全段~~但是太笨重了~~。其实只要接入cf.的ns，不用开小橙云，强制指定就能走cf的cdn代理.
6. 强制指定默认没有通配符
7. 并不只有cf有ech，据说一些试验性的ech可以tls嗅探出来获取配置玩。拿到配置之后在dns代码中自行配置即可
