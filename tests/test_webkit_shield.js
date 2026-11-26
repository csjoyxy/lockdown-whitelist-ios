const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const checker = require("../scripts/webkit_shield_check.js");

const ROOT = path.resolve(__dirname, "..");
const REPO_SLUG = "csjoyxy/lockdown-whitelist-ios";

function sha256(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

function parseLpxSections(content) {
  const meta = {};
  const sections = {};
  let curSection = null;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#!")) {
      const idx = line.indexOf("=");
      if (idx > 0) {
        const k = line.slice(2, idx).trim();
        const v = line.slice(idx + 1).trim();
        meta[k] = v;
      }
      continue;
    }
    if (line.startsWith("#")) continue;
    const secMatch = line.match(/^\[([^\]]+)\]$/);
    if (secMatch) {
      curSection = secMatch[1];
      if (!sections[curSection]) sections[curSection] = [];
      continue;
    }
    if (curSection) {
      sections[curSection].push(line);
    }
  }
  return { meta, sections };
}

function compileRuleMatchers(ruleLines) {
  const domainSuffixes = [];
  const exactDomains = [];
  const urlRegexes = [];
  const ipCidrs = [];
  const userAgents = [];

  for (const line of ruleLines) {
    const parts = line.split(",");
    const type = parts[0].trim();
    if (type === "DOMAIN-SUFFIX") {
      assert.strictEqual(parts[2].trim(), "REJECT", `Expected REJECT in: ${line}`);
      domainSuffixes.push(parts[1].trim().toLowerCase());
    } else if (type === "DOMAIN") {
      assert.strictEqual(parts[2].trim(), "REJECT", `Expected REJECT in: ${line}`);
      exactDomains.push(parts[1].trim().toLowerCase());
    } else if (type === "URL-REGEX") {
      const action = parts[parts.length - 1].trim();
      assert.strictEqual(action, "REJECT", `Expected REJECT in: ${line}`);
      const pattern = parts.slice(1, -1).join(",");
      urlRegexes.push(new RegExp(pattern));
    } else if (type === "IP-CIDR") {
      assert.strictEqual(parts[2].trim(), "REJECT", `Expected REJECT in: ${line}`);
      ipCidrs.push(parts[1].trim());
    } else if (type === "USER-AGENT") {
      assert.strictEqual(parts[2].trim(), "REJECT", `Expected REJECT in: ${line}`);
      userAgents.push(parts[1].trim());
    } else {
      assert.fail(`Unexpected rule type in WebKit shield: ${line}`);
    }
  }

  function matchesUrl(testUrl) {
    const u = new URL(testUrl);
    const host = u.hostname.toLowerCase();
    if (exactDomains.includes(host)) return true;
    if (domainSuffixes.some((suf) => host === suf || host.endsWith("." + suf))) return true;
    if (urlRegexes.some((re) => re.test(testUrl))) return true;
    return false;
  }

  return { domainSuffixes, exactDomains, urlRegexes, ipCidrs, userAgents, matchesUrl };
}

async function runTests() {
  // 1. 校验两个 .lpx 的 #!homepage 与 #!source SHA-256 与专用仓库 GitHub raw 地址完全一致
  for (const fileName of ["ios_webkit_shield.lpx", "ios_security_doh.lpx"]) {
    const content = fs.readFileSync(path.join(ROOT, fileName), "utf8");
    const { meta } = parseLpxSections(content);
    assert(meta.name, `${fileName} missing #!name`);
    assert.strictEqual(meta.homepage, `https://github.com/${REPO_SLUG}`, `${fileName} unexpected #!homepage`);
    assert(meta.source, `${fileName} missing #!source`);
    const sources = meta.source.split(",").map((s) => s.trim());
    const expectedMain = sha256(`https://raw.githubusercontent.com/${REPO_SLUG}/main/${fileName}`);
    const expectedRefs = sha256(`https://raw.githubusercontent.com/${REPO_SLUG}/refs/heads/main/${fileName}`);
    assert(sources.includes(expectedMain), `${fileName} #!source missing main raw hash`);
    assert(sources.includes(expectedRefs), `${fileName} #!source missing refs/heads/main raw hash`);
  }
  console.log("✓ Loon #!source SHA-256 & #!homepage verification passed");

  // 2. 校验核心插件不改全局 DNS、不开启 MitM，且脚本指向本仓库
  const shieldContent = fs.readFileSync(path.join(ROOT, "ios_webkit_shield.lpx"), "utf8");
  const shield = parseLpxSections(shieldContent);
  assert(!shield.sections.General, "ios_webkit_shield.lpx must NOT override [General] DNS");
  assert(!shield.sections.Mitm, "ios_webkit_shield.lpx must NOT enable [Mitm]");
  assert(
    shield.sections.Script &&
      shield.sections.Script[0].includes(
        `https://raw.githubusercontent.com/${REPO_SLUG}/main/scripts/webkit_shield_check.js`
      ),
    "ios_webkit_shield.lpx [Script] must point to lockdown-whitelist-ios raw script URL"
  );

  const dohContent = fs.readFileSync(path.join(ROOT, "ios_security_doh.lpx"), "utf8");
  const doh = parseLpxSections(dohContent);
  assert(doh.sections.General && doh.sections.General[0].includes("security.cloudflare-dns.com/dns-query"));
  assert(doh.sections.General[0].includes("dns.quad9.net/dns-query"));
  assert(doh.sections.Host && doh.sections.Host.length === 2);
  console.log("✓ Plugin separation (core IOC zero-DNS vs optional Security DoH) passed");

  // 3. 验证 RFC 8484 Wireformat apple.com A 记录报文合法性
  const wireBuf = Buffer.from(checker.DNS_WIRE_APPLE_A, "base64url");
  assert.strictEqual(wireBuf.readUInt16BE(0), 0x0000, "RFC 8484 DNS ID should be 0");
  assert(wireBuf.includes(Buffer.from("\x05apple\x03com\x00")), "DNS wire query must encode apple.com");

  // 4. 验证恶意水坑 URL 100% 命中拦截 & 正常国内外高频网站 0 误杀
  const matcher = compileRuleMatchers(shield.sections.Rule);
  const listLines = fs
    .readFileSync(path.join(ROOT, "rules/ios_webkit_ioc.list"), "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  const listMatcher = compileRuleMatchers(listLines);

  const maliciousSamples = [
    "https://mxbc-v2.tjbjdod.cn/static/analytics.html",
    "https://cdn.uacounter.com/stat.html",
    "http://aidm8it5hf1jmtj.xyz/details/show.html",
    "https://uawwydy3qas6ykv.xyz/ping",
    "http://198.51.100.42/details/new.js",
    "http://malicious-host.example/details/a1lib.js",
    "http://malicious-host.example/details/t20lib.js?v=1",
    "http://malicious-host.example/details/helion.js",
    "https://compromised-shop.example/assets/890fff603542c4b4de6508dcee41f73d8875a40f.js",
    "https://compromised-shop.example/js/73b26374b1c8df29c163775c2cd1f735ff6acd56.min.js",
    "http://k8m2p9x4q1w7z3r.xyz/check",
    "https://static.cdncounter.net/widgets.js?uhfiu27fajf2948fjfefaa42",
    "https://chainmate.top/",
    "https://backuprabbit.com/stage2",
    "https://tagclick-cdn.com/loader.js",
  ];
  for (const badUrl of maliciousSamples) {
    assert(matcher.matchesUrl(badUrl), `Plugin failed to block malicious URL: ${badUrl}`);
    assert(listMatcher.matchesUrl(badUrl), `Rule list failed to block malicious URL: ${badUrl}`);
  }

  const benignSamples = [
    "https://h5.m.taobao.com/mlapp/olist.html",
    "https://h5api.m.taobao.com/h5/mtop.cnwireless.cnlogistices.wap.query/1.0/",
    "https://www.apple.com/cn/",
    "https://www.bilibili.com/video/BV1xx411c7mD",
    "https://github.com/csjoyxy/lockdown-whitelist-ios",
    "https://chatgpt.com/",
    "https://claude.ai/new",
    "https://mp.weixin.qq.com/s/abcdefg123456",
    "https://example.xyz/index.html",
    "https://abcd1234efgh567.xyz/app",
    "https://cdn.example.com/details/product.html",
  ];
  for (const goodUrl of benignSamples) {
    assert(!matcher.matchesUrl(goodUrl), `False positive on benign URL: ${goodUrl}`);
    assert(!listMatcher.matchesUrl(goodUrl), `False positive in list on benign URL: ${goodUrl}`);
  }
  console.log("✓ Malicious exploit kit IOCs blocked (15/15) & benign sites untouched (0 false positives)");

  // 5. 自检脚本模拟运行测试（探针被阻断 + DoH 测速通知）
  const posted = [];
  global.$notification = {
    post: (title, subtitle, body) => posted.push({ title, subtitle, body }),
  };
  global.$httpClient = {
    get: (opts, cb) => {
      if (opts.url.includes("canary.webkit-shield.invalid")) {
        cb(new Error("Connection refused by Loon REJECT rule"), null, "");
      } else {
        cb(null, { status: 200 }, "dns-ok");
      }
    },
  };
  const res = await checker.runSelfCheck([true]);
  assert.strictEqual(res.canaryBlocked, true);
  assert.strictEqual(posted.length, 1);
  assert(posted[0].title.includes("自检通过"));
  assert(posted[0].body.includes("Cloudflare Security"));
  console.log("✓ Self-check script simulation passed");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
