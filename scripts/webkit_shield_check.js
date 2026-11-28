/**
 * iOS WebKit 水坑与漏洞链防护 · 手动自检与安全 DoH 测速脚本
 * - 零后台常驻：仅在用户在 Loon 插件详情页点击「立即自检防护与安全DoH延迟」时单次运行
 * - 零外联风险：探针域名使用 IETF RFC 2606 保留域 canary.webkit-shield.invalid，即使 VPN 未开也绝不会触达任何真实外部服务器
 */

const CANARY_URL = "http://canary.webkit-shield.invalid/details/show.html";
// 标准 RFC 8484 Wireformat 查询 apple.com A 记录（ID=0x0000，端口 443，与 Loon doh-server 协议完全一致）
const DNS_WIRE_APPLE_A = "AAABAAABAAAAAAAABWFwcGxlA2NvbQAAAQAB";
const DOH_ENDPOINTS = [
  {
    name: "Cloudflare Security (1.1.1.2)",
    url: `https://security.cloudflare-dns.com/dns-query?dns=${DNS_WIRE_APPLE_A}`,
    headers: { Accept: "application/dns-message" },
  },
  {
    name: "Quad9 Malware Block (9.9.9.9)",
    url: `https://dns.quad9.net/dns-query?dns=${DNS_WIRE_APPLE_A}`,
    headers: { Accept: "application/dns-message" },
  },
];

function parseCheckConfig(rawArg) {
  let checkDoh = true;
  if (Array.isArray(rawArg) && rawArg.length > 0) {
    checkDoh = rawArg[0] !== false && rawArg[0] !== "false";
  } else if (rawArg && typeof rawArg === "object") {
    if ("check_doh" in rawArg) {
      checkDoh = rawArg.check_doh !== false && rawArg.check_doh !== "false";
    }
  } else if (typeof rawArg === "string" && rawArg.trim() !== "") {
    checkDoh = !/^false$/i.test(rawArg.trim());
  }
  return { checkDoh };
}

function httpGet(opts) {
  return new Promise((resolve) => {
    const start = Date.now();
    if (typeof $httpClient === "undefined" || !$httpClient || typeof $httpClient.get !== "function") {
      resolve({ ok: false, error: "no_http_client", elapsedMs: 0, status: 0 });
      return;
    }
    $httpClient.get(
      {
        url: opts.url,
        headers: opts.headers || {},
        timeout: opts.timeout || 4,
      },
      (err, resp, data) => {
        const elapsedMs = Math.max(1, Date.now() - start);
        const status = resp && (resp.status || resp.statusCode) ? Number(resp.status || resp.statusCode) : 0;
        if (err) {
          resolve({ ok: false, error: String(err), elapsedMs, status, data: "" });
        } else {
          resolve({ ok: status >= 200 && status < 400, error: "", elapsedMs, status, data: data || "" });
        }
      }
    );
  });
}

async function runSelfCheck(rawArg) {
  const cfg = parseCheckConfig(rawArg);

  // 1. 验证本机 REJECT 规则已拦截无害探针（正常应快速报错拒绝，status === 0 或非 2xx）
  const canaryRes = await httpGet({ url: CANARY_URL, timeout: 3 });
  const canaryBlocked = !canaryRes.ok;

  const lines = [];
  if (canaryBlocked) {
    lines.push(`✅ IOC 拦截规则已生效（探针 ${canaryRes.elapsedMs}ms 内被阻断）`);
  } else {
    lines.push("⚠️ 探针未被 REJECT，请确认 Loon 全局开关与本插件均已开启");
  }

  // 2. 可选测试安全 DoH 延迟，帮助决定是否开启 ios_security_doh.lpx
  if (cfg.checkDoh) {
    const dohResults = await Promise.all(
      DOH_ENDPOINTS.map(async (ep) => {
        const r = await httpGet({ url: ep.url, headers: ep.headers, timeout: 4 });
        return { name: ep.name, ok: r.ok, ms: r.elapsedMs, status: r.status };
      })
    );

    const fastOnes = [];
    for (const item of dohResults) {
      if (item.ok) {
        lines.push(`🌐 ${item.name}: 可用 (${item.ms}ms)`);
        if (item.ms <= 350) fastOnes.push(item.name);
      } else {
        lines.push(`⏱️ ${item.name}: 当前网络直连超时/受阻`);
      }
    }

    if (fastOnes.length > 0) {
      lines.push("💡 当前网络访问安全 DoH 流畅，可放心开启「可选安全 DoH 插件」");
    } else {
      lines.push("💡 当前网络直连海外安全 DoH 较慢，建议保持关闭安全 DoH 插件，仅用本核心 IOC 插件即可零延迟防护");
    }
  }

  const title = canaryBlocked ? "🛡️ iOS WebKit 水坑防护自检通过" : "⚠️ iOS WebKit 水坑防护未完全生效";
  const subtitle = "Coruna / DarkSword / OPTIMJACK 供应链防线";
  const body = lines.join("\n");

  if (typeof $notification !== "undefined" && $notification && typeof $notification.post === "function") {
    $notification.post(title, subtitle, body);
  }
  return { canaryBlocked, lines, title, subtitle, body };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    CANARY_URL,
    DNS_WIRE_APPLE_A,
    DOH_ENDPOINTS,
    parseCheckConfig,
    runSelfCheck,
  };
} else {
  const rawArg = typeof $argument !== "undefined" ? $argument : undefined;
  runSelfCheck(rawArg).finally(() => {
    if (typeof $done === "function") $done();
  });
}
