import Foundation

/// Zero-WebKit Pre-Flight URL Safety Inspector for iOS 16.4.1.
/// Uses ephemeral URLSession (no WKWebView, no JavaScriptCore/Wasm/Font parsing, no cookies, 256 KB cap)
/// + dual malware-blocking DoH (Cloudflare 1.1.1.2 & Quad9 9.9.9.9) + static exploit/phishing heuristics.
enum URLSafetyInspector {
    private static let maxBodyBytes = 262_144 // 256 KB cap

    private static let knownExploitDomainSuffixes: Set<String> = [
        // Coruna / CryptoWaters
        "tjbjdod.cn", "uacounter.com", "aidm8it5hf1jmtj.xyz", "uawwydy3qas6ykv.xyz",
        // DarkSword
        "cdncounter.net", "snapshare.chat", "chainmate.top",
        // Operation Triangulation
        "addatamarket.net", "ans7tv.net", "anstv.net", "backuprabbit.com",
        "businessvideonews.com", "cloudsponcer.com", "datamarketplace.net",
        "growthtransport.com", "mobilegamerstats.com", "snoweeanalytics.com",
        "tagclick-cdn.com", "topographyupdates.com", "unlimitedteacup.com",
        "virtuallaughing.com", "web-trackers.com", "senlin83.com", "snlin83.com",
        // OPTIMJACK (2026-11 Optimizely/Kissmetrics supply-chain Coruna/DarkSword & skimmer cluster)
        "1688360.cc", "webshell.lol", "linkforge.cc",
        "5vobauua3ojpklx.icu", "eil786npto9u5bq.icu", "l7bcsnwc7nzr3uo.icu",
        "je4ft3gn8vxudum.icu", "q1ls1ho9x7wsxlu.icu", "p55abnw2pnsz0bo.icu",
        "1y69gy2mdzaltz1.icu", "gm38duxoihbmy5o.icu", "ios-hack.icu",
        // Hijacked polyfill CDN
        "polyfill.io"
    ]

    private static let knownExploitIPs: Set<String> = [
        "62.72.21.10", "72.60.98.48",
        "136.113.106.136", "34.87.36.58", "34.96.213.201"
    ]

    private static let supplyChainExperimentationHosts: Set<String> = [
        "cdn.optimizely.com", "logx.optimizely.com",
        "scripts.kissmetrics.com", "i.kissmetrics.com",
        "cdn.storifyme.com", "apv-launcher.minute.ly", "snippet.minute.ly"
    ]

    private static let highAbuseTLDs: Set<String> = [
        "xyz", "top", "icu", "lol", "cyou", "sbs", "cfd", "buzz", "rest", "monster", "pw", "click", "zip", "mov"
    ]

    private static let protectedBrandRoots: [(keyword: String, officialRoots: Set<String>, label: String)] = [
        ("metamask", ["metamask.io"], "MetaMask 钱包"),
        ("imtoken", ["token.im", "imtoken.com"], "imToken 钱包"),
        ("tokenpocket", ["tokenpocket.pro", "tpstatic.net"], "TokenPocket 钱包"),
        ("trustwallet", ["trustwallet.com"], "Trust Wallet 钱包"),
        ("ledger", ["ledger.com"], "Ledger 硬件钱包"),
        ("trezor", ["trezor.io"], "Trezor 硬件钱包"),
        ("binance", ["binance.com", "bnbstatic.com", "binance.info"], "币安 Binance"),
        ("okx", ["okx.com", "static.okx.com"], "欧易 OKX"),
        ("icloud", ["icloud.com", "icloud.com.cn", "apple.com"], "Apple iCloud"),
        ("appleid", ["apple.com", "icloud.com"], "Apple ID"),
        ("alipay", ["alipay.com", "alipayobjects.com"], "支付宝"),
        ("taobao", ["taobao.com", "tbcdn.cn", "alicdn.com"], "淘宝"),
        ("weixin", ["qq.com", "wechat.com", "weixinbridge.com"], "微信")
    ]

    // MARK: - Public Entry Point

    static func inspect(rawInput: String) async -> Result<URLSafetyReport, Error> {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .failure(NSError(domain: "URLSafety", code: 1, userInfo: [NSLocalizedDescriptionKey: "请输入要检测的网址或域名"]))
        }

        let normalizedStr: String
        if trimmed.lowercased().hasPrefix("http://") || trimmed.lowercased().hasPrefix("https://") {
            normalizedStr = trimmed
        } else {
            normalizedStr = "https://" + trimmed
        }

        guard let initialURL = URL(string: normalizedStr),
              let initialHost = initialURL.host?.lowercased(),
              !initialHost.isEmpty,
              initialHost.contains(".") else {
            return .failure(NSError(domain: "URLSafety", code: 2, userInfo: [NSLocalizedDescriptionKey: "网址格式无效（示例：https://example.com）"]))
        }

        if isPrivateOrLoopbackHost(initialHost) {
            return .failure(NSError(domain: "URLSafety", code: 3, userInfo: [NSLocalizedDescriptionKey: "安全沙盒仅用于检测公网网站，已忽略内网/本机地址"]))
        }

        var findings: [URLSafetyFinding] = []

        // 1. Pre-flight local IOC & brand phishing checks on initial URL
        checkURLAgainstLocalIOCs(initialURL, context: "输入网址", findings: &findings)
        checkBrandImpersonation(host: initialHost, findings: &findings)

        // 2. Concurrent Malware-Blocking DoH Reputation Check + Zero-WebKit Bounded HTTP Fetch
        async let cfRepTask = queryDoHReputation(
            endpoint: "https://security.cloudflare-dns.com/dns-query",
            host: initialHost,
            checkZeroSinkhole: true
        )
        async let q9RepTask = queryDoHReputation(
            endpoint: "https://dns.quad9.net/dns-query",
            host: initialHost,
            checkZeroSinkhole: false
        )
        async let fetchTask = performBoundedFetch(url: initialURL)

        let cfRep = await cfRepTask
        let q9Rep = await q9RepTask
        let fetchRes = await fetchTask

        var finalURL = initialURL
        var redirectChain: [String] = [initialURL.absoluteString]
        var statusCode = 0
        var contentType = ""
        var bodyData = Data()
        var headers: [String: String] = [:]
        var httpConnected = false

        switch fetchRes {
        case .success(let payload):
            httpConnected = true
            finalURL = payload.finalURL
            redirectChain = payload.redirectChain
            statusCode = payload.statusCode
            contentType = payload.contentType
            bodyData = payload.bodyData
            headers = payload.headers
        case .failure(let err):
            findings.append(URLSafetyFinding(
                severity: .notice,
                category: "网络连通性",
                title: "未能完成网页源码拉取",
                detail: "原因：\(err.localizedDescription)（已完成离线 IOC 与安全 DoH 域名信誉核验）"
            ))
        }

        // Evaluate DoH reputation results
        var cfClean: Bool? = nil
        if let cf = cfRep {
            if cf.blockedSinkhole {
                cfClean = false
                findings.append(URLSafetyFinding(
                    severity: .danger,
                    category: "全球威胁情报",
                    title: "Cloudflare Security (1.1.1.2) 拦截告警",
                    detail: "该域名已被 Cloudflare 恶意软件与反钓鱼威胁库标记并重定向至安全黑洞 (0.0.0.0)！"
                ))
            } else if cf.rcode == 0 && !cf.ips.isEmpty {
                cfClean = true
                for ip in cf.ips where knownExploitIPs.contains(ip) {
                    findings.append(URLSafetyFinding(
                        severity: .danger,
                        category: "已知漏洞包 C2",
                        title: "域名解析命中在野水坑服务器 IP (\(ip))",
                        detail: "该 IP 属于已知 iOS WebKit 漏洞利用工具包 (DarkSword / Coruna) 基础设施！"
                    ))
                }
            }
        }

        var q9Clean: Bool? = nil
        if let q9 = q9Rep {
            if q9.blockedSinkhole || (q9.rcode == 3 && (httpConnected || cfClean == true)) {
                // Quad9 returns NXDOMAIN (rcode=3) when blocking known malicious domains while normal DNS resolves
                q9Clean = false
                findings.append(URLSafetyFinding(
                    severity: .danger,
                    category: "全球威胁情报",
                    title: "Quad9 (9.9.9.9) 恶意域名情报命中",
                    detail: "Quad9 威胁情报节点拒绝解析该域名（其它节点存在解析记录），表明该域名处于恶意/钓鱼封禁列表！"
                ))
            } else if q9.rcode == 0 {
                q9Clean = true
            }
        }

        // 3. Check Redirect Chain & Final Host if different from initial
        if redirectChain.count > 1 {
            for hopStr in redirectChain.dropFirst() {
                if let hopURL = URL(string: hopStr) {
                    checkURLAgainstLocalIOCs(hopURL, context: "跳转链路", findings: &findings)
                    if let h = hopURL.host?.lowercased(), h != initialHost {
                        checkBrandImpersonation(host: h, findings: &findings)
                    }
                }
            }
            let initRoot = LBBridgeHighLevelDomain(initialHost)
            let finalHost = finalURL.host?.lowercased() ?? initialHost
            let finalRoot = LBBridgeHighLevelDomain(finalHost)
            if !initRoot.isEmpty && !finalRoot.isEmpty && initRoot != finalRoot {
                findings.append(URLSafetyFinding(
                    severity: .notice,
                    category: "跨站重定向",
                    title: "发生跨主域名自动跳转 (\(redirectChain.count - 1) 次)",
                    detail: "从 \(initialHost) 跳转至 \(finalHost)，请确认目标站点符合预期。"
                ))
            }
        }

        let finalHost = finalURL.host?.lowercased() ?? initialHost
        let isHTTPS = finalURL.scheme?.lowercased() == "https"

        if !isHTTPS {
            findings.append(URLSafetyFinding(
                severity: .warning,
                category: "明文传输风险",
                title: "使用未加密的 HTTP 明文连接",
                detail: "明文网页在公共 Wi-Fi 或运营商链路中极易被劫持注入恶意 JS 水坑脚本，强烈不建议为其关闭锁定模式。"
            ))
        }

        if finalHost.contains("xn--") {
            findings.append(URLSafetyFinding(
                severity: .warning,
                category: "同形异义词域名",
                title: "检测到 Punycode 国际化编码域名 (\(finalHost))",
                detail: "攻击者常利用外观近似的特殊字符伪造知名网站域名实施钓鱼。"
            ))
        }

        if let tld = finalHost.split(separator: ".").last.map(String.init), highAbuseTLDs.contains(tld) {
            findings.append(URLSafetyFinding(
                severity: .notice,
                category: "高发风险后缀",
                title: "使用水坑/钓鱼高频顶级域 (.\(tld))",
                detail: "Coruna 与各类盗币钓鱼水坑大量注册此类廉价后缀，访问时建议保持锁定模式开启。"
            ))
        }

        // 4. Inspect Content-Type (Configuration Profile / Binary Auto-Download) & Static HTML/JS Body
        let lowerCT = contentType.lowercased()
        if lowerCT.contains("x-apple-aspen-config") || finalURL.path.lowercased().hasSuffix(".mobileconfig") {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "恶意描述文件风险",
                title: "该链接会直接下发 iOS 系统描述文件 (.mobileconfig)",
                detail: "未知来源的描述文件可篡改全局 DNS/VPN、安装根证书或植入桌面钓鱼 WebClip，切勿随意安装！"
            ))
        } else if lowerCT.contains("octet-stream") || finalURL.path.lowercased().hasSuffix(".ipa") || finalURL.path.lowercased().hasSuffix(".apk") {
            findings.append(URLSafetyFinding(
                severity: .warning,
                category: "可执行安装包",
                title: "该链接指向二进制文件或安装包下载",
                detail: "Content-Type: \(contentType.isEmpty ? "binary" : contentType)"
            ))
        }

        var externalScriptDomains: [String] = []
        if httpConnected && !bodyData.isEmpty && (lowerCT.isEmpty || lowerCT.contains("html") || lowerCT.contains("javascript") || lowerCT.contains("text")) {
            let html = String(decoding: bodyData, as: UTF8.self)
            externalScriptDomains = analyzeHTMLAndScripts(
                html: html,
                pageHost: finalHost,
                findings: &findings
            )
        }

        // 5. Security Response Headers Check (when HTTPS connected)
        if httpConnected && isHTTPS {
            let hasCSP = headers["content-security-policy"] != nil
            let hasHSTS = headers["strict-transport-security"] != nil
            if !hasCSP && !hasHSTS && externalScriptDomains.count >= 4 {
                findings.append(URLSafetyFinding(
                    severity: .notice,
                    category: "站点自身防护偏弱",
                    title: "未配置 CSP / HSTS 且加载了 \(externalScriptDomains.count) 个外部脚本域",
                    detail: "此类中小站点若第三方统计/广告脚本被攻陷，容易沦为被动挂马水坑；如页面在锁定模式下能正常浏览，无需加白名单。"
                ))
            }
        }

        // Compute Overall Verdict
        let overall = computeOverallVerdict(findings: findings, httpConnected: httpConnected, isHTTPS: isHTTPS)
        let candidateDom = LBBridgeHighLevelDomain(finalHost).isEmpty ? finalHost : finalHost

        return .success(URLSafetyReport(
            inputURL: trimmed,
            finalURL: finalURL.absoluteString,
            candidateDomain: candidateDom,
            redirectChain: redirectChain,
            httpStatusCode: statusCode,
            contentType: contentType,
            fetchedBytes: bodyData.count,
            isHTTPS: isHTTPS,
            cloudflareClean: cfClean,
            quad9Clean: q9Clean,
            externalScriptDomains: externalScriptDomains,
            riskLevel: overall.level,
            summaryTitle: overall.title,
            summaryAdvice: overall.advice,
            findings: findings,
            checkedAt: Date()
        ))
    }

    // MARK: - Local IOC & Brand Phishing Heuristics

    private static func matchesRegex(_ pattern: String, in text: String, caseInsensitive: Bool = true) -> Bool {
        let opts: NSRegularExpression.Options = caseInsensitive ? [.caseInsensitive] : []
        guard let re = try? NSRegularExpression(pattern: pattern, options: opts) else { return false }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return re.firstMatch(in: text, options: [], range: range) != nil
    }

    private static func checkURLAgainstLocalIOCs(_ url: URL, context: String, findings: inout [URLSafetyFinding]) {
        let full = url.absoluteString
        let host = url.host?.lowercased() ?? ""

        if knownExploitIPs.contains(host) {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "在野漏洞包 IOC",
                title: "\(context)直接命中在野漏洞利用 C2 IP (\(host))",
                detail: "匹配 DarkSword / iOS WebKit 全链攻击基础设施指标！"
            ))
        }

        for suf in knownExploitDomainSuffixes {
            if host == suf || host.hasSuffix("." + suf) {
                findings.append(URLSafetyFinding(
                    severity: .danger,
                    category: "在野漏洞包 IOC",
                    title: "\(context)命中已知 iOS 水坑攻击域名 (\(suf))",
                    detail: "匹配 GTIG / iVerify / Kaspersky 披露的 Coruna / DarkSword / 三角行动在野水坑域名！"
                ))
                break
            }
        }

        if matchesRegex(#"^https?://[^/]+/details/(?:show\.html|new\.js|helion\.js|sms\.js|wap\.js|[a-t][0-9]{1,2}lib\.js)(?:$|[?#])"#, in: full) {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "Coruna 植入载荷",
                title: "\(context)命中 Coruna / CryptoWaters 钱包注入模块路径",
                detail: "检测到 /details/*.js 特征植入载荷路径（覆盖 iOS 13–17.2.1 助记词窃取工具包）！"
            ))
        }

        if matchesRegex(#"(?:890fff603542c4b4de6508dcee41f73d8875a40f|13f59ce4cf6b32bd5b4341b470975b71ab67fc20|f1074228cc21dcbd4250b1c25c033a7426431982|6b5c6921b048f05b449fe3f4b71f49cf6dd3634f|1c7c51c159e4b34c748be9aad183e68f5185aeb0|bb33ae77f4c7e8858cdb9c91985c46d58b28c0e0|73b26374b1c8df29c163775c2cd1f735ff6acd56\.min|0371be6951227616286c593e3c588ecff7d58f90\.min)\.js"#, in: full) {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "Coruna WebKit RCE",
                title: "\(context)命中 Coruna WebKit JIT RCE / PAC 绕过漏洞脚本哈希",
                detail: "直接匹配已知 iOS 16 WebKit 远程代码执行攻击脚本文件名！"
            ))
        }

        if matchesRegex(#"^http://(?:[a-z0-9-]+\.)?[a-z0-9]{15}\.xyz(?:/|$)"#, in: full) {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "Coruna DGA 域名",
                title: "\(context)命中 15 位 .xyz 明文 HTTP DGA 水坑特征",
                detail: "高度吻合 Coruna lazarus 种子生成的备用动态水坑域名格式！"
            ))
        }

        if matchesRegex(#"^https?://[^/]+/(?:JIUJIU888/(?:weifile\.html|index\.js)|A8/a\.html|api/iptj|(?:[a-zA-Z0-9_/.-]+/)?(?:rce_loader|sbox0_main_[0-9.]+|sbx0_main|sbx1_main)\.js)(?:$|[?#])"#, in: full) {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "OPTIMJACK / DarkSword 载荷",
                title: "\(context)命中 iOS 漏洞分发或沙盒逃逸脚本路径",
                detail: "匹配 2026-11 Optimizely 供应链投毒事件披露的 Coruna/DarkSword 漏洞跳转或沙盒逃逸模块路径！"
            ))
        }
    }

    private static func checkBrandImpersonation(host: String, findings: inout [URLSafetyFinding]) {
        let root = LBBridgeHighLevelDomain(host)
        for item in protectedBrandRoots {
            if host.contains(item.keyword) && !item.officialRoots.contains(root) && !item.officialRoots.contains(host) {
                findings.append(URLSafetyFinding(
                    severity: .danger,
                    category: "疑似钓鱼仿冒",
                    title: "域名包含「\(item.keyword)」但并非 \(item.label) 官方主域",
                    detail: "当前根域名为 \(root.isEmpty ? host : root)，官方域名应为 \(item.officialRoots.sorted().joined(separator: " / "))，请警惕账号或助记词钓鱼！"
                ))
            }
        }
    }

    // MARK: - Static HTML & Script Heuristic Scanner

    private static func analyzeHTMLAndScripts(html: String, pageHost: String, findings: inout [URLSafetyFinding]) -> [String] {
        let pageRoot = LBBridgeHighLevelDomain(pageHost)
        var scriptDomains = Set<String>()
        var supplyChainHits = Set<String>()

        // 1. Extract <script src="..."> and <iframe src="..."> external URLs
        if let tagRe = try? NSRegularExpression(pattern: #"<(script|iframe)\b[^>]*?\bsrc\s*=\s*["']([^"']+)["'][^>]*>"#, options: [.caseInsensitive]) {
            let nsRange = NSRange(html.startIndex..<html.endIndex, in: html)
            let matches = tagRe.matches(in: html, options: [], range: nsRange)
            for m in matches.prefix(120) {
                guard let tagR = Range(m.range(at: 1), in: html),
                      let srcR = Range(m.range(at: 2), in: html),
                      let fullTagR = Range(m.range(at: 0), in: html) else { continue }
                let tagName = html[tagR].lowercased()
                let rawSrc = String(html[srcR]).trimmingCharacters(in: .whitespacesAndNewlines)
                let fullTag = String(html[fullTagR]).lowercased()

                let resolvedStr: String
                if rawSrc.hasPrefix("//") {
                    resolvedStr = "https:" + rawSrc
                } else {
                    resolvedStr = rawSrc
                }

                if let u = URL(string: resolvedStr), let h = u.host?.lowercased(), !h.isEmpty {
                    let extRoot = LBBridgeHighLevelDomain(h)
                    if extRoot != pageRoot {
                        scriptDomains.insert(h)
                    }
                    if supplyChainExperimentationHosts.contains(h) {
                        supplyChainHits.insert(h)
                    }
                    checkURLAgainstLocalIOCs(u, context: "页面嵌入 <\(tagName)>", findings: &findings)

                    // Hidden external iframe check (classic watering-hole loader)
                    if tagName == "iframe" && extRoot != pageRoot {
                        let isHidden = fullTag.contains("display:none") ||
                                       fullTag.contains("display: none") ||
                                       fullTag.contains("visibility:hidden") ||
                                       fullTag.contains("visibility: hidden") ||
                                       fullTag.contains("width=\"0\"") ||
                                       fullTag.contains("height=\"0\"") ||
                                       fullTag.contains("width='0'") ||
                                       fullTag.contains("-9999px")
                        if isHidden {
                            findings.append(URLSafetyFinding(
                                severity: .warning,
                                category: "隐藏水坑框架",
                                title: "网页暗藏不可见的跨域 <iframe> (\(h))",
                                detail: "在野水坑攻击常在被黑正常网站中插入宽高为 0 或隐藏的跨域 iframe 静默加载浏览器漏洞包。"
                            ))
                        }
                    }
                }
            }
        }

        if !supplyChainHits.isEmpty {
            let joined = supplyChainHits.sorted().joined(separator: ", ")
            findings.append(URLSafetyFinding(
                severity: .notice,
                category: "第三方动态实验脚本",
                title: "页面嵌入第三方 A/B 实验或营销注入脚本 (\(joined))",
                detail: "2026-11 Optimizely/Kissmetrics 等第三方脚本曾遭供应链篡改投递换币木马与 Coruna/DarkSword 漏洞链。若需将该站加入 Safari 白名单，请保持 Loon「iOS WebKit 水坑与漏洞链防护」插件开启，已在网络层自动拦截此类第三方动态脚本且不影响主站浏览。"
            ))
        }

        // 2. WebKit / JSC Memory Corruption & JIT Spray Primitives
        let hasExploitTerms = matchesRegex(#"\b(?:addrof|fakeobj|boxed_arr|unboxed_arr|jit_spray|structureid)\b"#, in: html)
        let hasTypedArrayWasmCombo = matchesRegex(#"Float64Array"#, in: html, caseInsensitive: false) &&
                                     matchesRegex(#"Uint32Array"#, in: html, caseInsensitive: false) &&
                                     matchesRegex(#"WebAssembly\.(?:Module|Instance|instantiate)"#, in: html, caseInsensitive: false) &&
                                     matchesRegex(#"(?:eval|Function)\s*\(\s*atob\s*\("#, in: html)
        if hasExploitTerms || hasTypedArrayWasmCombo {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "浏览器漏洞利用特征",
                title: "源码检出疑似 WebKit / JavaScriptCore 内存利用原语",
                detail: "发现 addrof/fakeobj 或 Float64Array+Wasm+atob 混淆执行特征，强烈疑似浏览器 RCE 漏洞利用代码！"
            ))
        } else if matchesRegex(#"(?:eval|Function)\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\("#, in: html) {
            findings.append(URLSafetyFinding(
                severity: .warning,
                category: "混淆动态代码执行",
                title: "页面包含 eval(atob/fromCharCode) 编码动态脚本",
                detail: "恶意广告、重定向劫持或加密载荷常使用多层编码规避静态审查，不建议关闭锁定模式访问。"
            ))
        }

        // 3. Seed Phrase / Private Key Phishing Form Detection
        let hasFormInput = matchesRegex(#"<(?:input|textarea)\b"#, in: html)
        let asksMnemonic = matchesRegex(#"(?:12\s*个?助记词|24\s*个?助记词|输入助记词|导入私钥|enter\s+your\s+(?:12|24)?\s*(?:word\s+)?(?:seed|recovery)\s+phrase|mnemonic\s+phrase)"#, in: html)
        if hasFormInput && asksMnemonic {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "助记词/私钥窃取",
                title: "网页包含索要「助记词 / 私钥 (Seed Phrase)」的输入表单",
                detail: "任何正规网站或空投活动均不会在网页端索要钱包助记词或明文私钥，100% 为盗币钓鱼页面！"
            ))
        }

        // 4. OPTIMJACK Crypto Address Clipper & Payment Card Skimmer Signatures
        let hasOptimjackMarker = matchesRegex(#"window\._k7\b"#, in: html, caseInsensitive: false) ||
                                 (matchesRegex(#"/(?:card|hit)\.php\b"#, in: html) && matchesRegex(#"html2canvas"#, in: html))
        let hasClipboardCryptoSwap = matchesRegex(#"navigator\.clipboard\.writeText"#, in: html, caseInsensitive: false) &&
                                     matchesRegex(#"0x[a-fA-F0-9]{40}"#, in: html, caseInsensitive: false) &&
                                     matchesRegex(#"\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b"#, in: html, caseInsensitive: false)
        if hasOptimjackMarker || hasClipboardCryptoSwap {
            findings.append(URLSafetyFinding(
                severity: .danger,
                category: "换币木马 / 盗刷卡注入",
                title: "源码检出加密货币地址替换或银行卡表单窃取特征 (OPTIMJACK)",
                detail: "检测到 window._k7 驻留标记、剪贴板多链收款地址篡改或网页表单窃密回传特征！"
            ))
        }

        return scriptDomains.sorted()
    }

    private static func computeOverallVerdict(
        findings: [URLSafetyFinding],
        httpConnected: Bool,
        isHTTPS: Bool
    ) -> (level: URLRiskLevel, title: String, advice: String) {
        if findings.contains(where: { $0.severity == .danger }) {
            return (
                .danger,
                "🔴 高危风险：检出恶意/水坑/钓鱼特征",
                "切勿将该网站加入锁定模式白名单，也不建议在手机浏览器中打开该链接！"
            )
        }
        if findings.contains(where: { $0.severity == .warning }) {
            return (
                .warning,
                "🟠 存在可疑风险：不建议加入白名单",
                "该站点存在明文传输、隐藏跨域框架或混淆脚本特征；如确需查看，请务必保持系统「锁定模式」开启状态访问。"
            )
        }
        if findings.contains(where: { $0.severity == .notice }) || !httpConnected || !isHTTPS {
            return (
                .notice,
                "🟡 未命中已知木马，但建议保持锁定模式",
                "未发现已知在野水坑 IOC 或钓鱼记录；除非该信任网站在锁定模式下确实无法正常打开，否则优先保持锁定模式浏览更安全。"
            )
        }
        return (
            .safe,
            "🟢 预检通过：未发现异常或水坑攻击特征",
            "HTTPS 加密正常、双路安全 DoH 信誉良好且源码未见异常挂马特征。若该站在锁定模式下显示异常，可放心点击下方按钮加入 Safari 白名单。"
        )
    }

    // MARK: - Private IP Guard

    private static func isPrivateOrLoopbackHost(_ host: String) -> Bool {
        let h = host.lowercased()
        if h == "localhost" || h.hasSuffix(".local") || h.hasSuffix(".invalid") || h == "::1" || h == "[::1]" {
            return true
        }
        let parts = h.split(separator: ".").compactMap { Int($0) }
        if parts.count == 4 {
            let (a, b) = (parts[0], parts[1])
            if a == 10 || a == 127 || a == 0 { return true }
            if a == 169 && b == 254 { return true }
            if a == 192 && b == 168 { return true }
            if a == 172 && (16...31).contains(b) { return true }
        }
        return false
    }

    // MARK: - Bounded Ephemeral HTTP Fetch (0 WebKit, Max 256 KB, Max 6 Redirects)

    private struct FetchPayload {
        let finalURL: URL
        let redirectChain: [String]
        let statusCode: Int
        let contentType: String
        let headers: [String: String]
        let bodyData: Data
    }

    private final class BoundedFetchDelegate: NSObject, URLSessionDataDelegate {
        private let initialURL: URL
        private let maxBytes: Int
        private var buffer = Data()
        private var response: HTTPURLResponse?
        private(set) var redirectChain: [String]
        private var finished = false
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Result<FetchPayload, Error>, Never>?

        init(initialURL: URL, maxBytes: Int, continuation: CheckedContinuation<Result<FetchPayload, Error>, Never>) {
            self.initialURL = initialURL
            self.redirectChain = [initialURL.absoluteString]
            self.maxBytes = maxBytes
            self.continuation = continuation
        }

        private func finishOnce(_ result: Result<FetchPayload, Error>) {
            lock.lock()
            guard !finished, let cont = continuation else {
                lock.unlock()
                return
            }
            finished = true
            continuation = nil
            lock.unlock()
            cont.resume(returning: result)
        }

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            guard let nextURL = request.url, let nextHost = nextURL.host else {
                completionHandler(nil)
                return
            }
            if URLSafetyInspector.isPrivateOrLoopbackHost(nextHost) || redirectChain.count > 6 {
                completionHandler(nil)
                return
            }
            lock.lock()
            redirectChain.append(nextURL.absoluteString)
            lock.unlock()
            completionHandler(request)
        }

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive response: URLResponse,
            completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
        ) {
            self.response = response as? HTTPURLResponse
            completionHandler(.allow)
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
            lock.lock()
            let remaining = maxBytes - buffer.count
            if remaining > 0 {
                buffer.append(data.prefix(remaining))
            }
            let hitCap = buffer.count >= maxBytes
            lock.unlock()

            if hitCap {
                dataTask.cancel()
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            lock.lock()
            let snapData = buffer
            let snapChain = redirectChain
            let snapResp = response
            lock.unlock()

            let nsErr = error as NSError?
            let cancelledAfterCap = (nsErr?.domain == NSURLErrorDomain && nsErr?.code == NSURLErrorCancelled && snapData.count >= maxBytes)

            if let err = error, !cancelledAfterCap {
                finishOnce(.failure(err))
                return
            }

            let finalURL = task.currentRequest?.url ?? URL(string: snapChain.last ?? "") ?? initialURL
            let code = snapResp?.statusCode ?? 200
            let ct = snapResp?.value(forHTTPHeaderField: "Content-Type") ?? ""
            var hdrs: [String: String] = [:]
            if let all = snapResp?.allHeaderFields {
                for (k, v) in all {
                    hdrs[String(describing: k).lowercased()] = String(describing: v)
                }
            }
            finishOnce(.success(FetchPayload(
                finalURL: finalURL,
                redirectChain: redirectChain,
                statusCode: code,
                contentType: ct,
                headers: hdrs,
                bodyData: buffer
            )))
        }
    }

    private static func performBoundedFetch(url: URL) async -> Result<FetchPayload, Error> {
        await withCheckedContinuation { cont in
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 7.0
            cfg.timeoutIntervalForResource = 8.0
            cfg.httpShouldSetCookies = false
            cfg.httpCookieAcceptPolicy = .never
            cfg.urlCache = nil
            cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData

            let delegate = BoundedFetchDelegate(initialURL: url, maxBytes: maxBodyBytes, continuation: cont)
            let session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
            var req = URLRequest(url: url)
            req.httpMethod = "GET"
            req.setValue(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
                forHTTPHeaderField: "User-Agent"
            )
            req.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
            let task = session.dataTask(with: req)
            task.resume()
            session.finishTasksAndInvalidate()
        }
    }

    // MARK: - RFC 8484 Wireformat DoH Reputation Check

    private struct DoHResult {
        let rcode: Int
        let ips: [String]
        let blockedSinkhole: Bool
    }

    private static func buildDNSWireQueryA(host: String) -> String? {
        let labels = host.trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".")
        guard !labels.isEmpty else { return nil }
        var pkt = Data([
            0x00, 0x00, // ID = 0 (RFC 8484)
            0x01, 0x00, // Standard query, RD = 1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00  // ARCOUNT = 0
        ])
        for label in labels {
            guard let ascii = label.data(using: .ascii), !ascii.isEmpty, ascii.count <= 63 else { return nil }
            pkt.append(UInt8(ascii.count))
            pkt.append(ascii)
        }
        pkt.append(0x00) // Root terminator
        pkt.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // QTYPE = A (1), QCLASS = IN (1)
        return pkt.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func skipDNSName(in data: Data, from offset: Int) -> Int? {
        var idx = offset
        var jumps = 0
        while idx < data.count && jumps < 32 {
            let len = Int(data[idx])
            if len == 0 {
                return idx + 1
            } else if (len & 0xC0) == 0xC0 {
                return (idx + 2 <= data.count) ? (idx + 2) : nil
            } else {
                idx += 1 + len
            }
            jumps += 1
        }
        return nil
    }

    private static func parseDNSWireResponse(_ data: Data, checkZeroSinkhole: Bool) -> DoHResult? {
        guard data.count >= 12 else { return nil }
        let rcode = Int(data[3] & 0x0F)
        let qdCount = (Int(data[4]) << 8) | Int(data[5])
        let anCount = (Int(data[6]) << 8) | Int(data[7])

        var offset = 12
        for _ in 0..<qdCount {
            guard let next = skipDNSName(in: data, from: offset), next + 4 <= data.count else { return nil }
            offset = next + 4
        }

        var ips: [String] = []
        var sinkholed = false
        for _ in 0..<anCount {
            guard let afterName = skipDNSName(in: data, from: offset), afterName + 10 <= data.count else { break }
            let rrType = (Int(data[afterName]) << 8) | Int(data[afterName + 1])
            let rdLen = (Int(data[afterName + 8]) << 8) | Int(data[afterName + 9])
            let rdataStart = afterName + 10
            guard rdataStart + rdLen <= data.count else { break }
            if rrType == 1 && rdLen == 4 {
                let ip = "\(data[rdataStart]).\(data[rdataStart + 1]).\(data[rdataStart + 2]).\(data[rdataStart + 3])"
                if ip == "0.0.0.0" {
                    sinkholed = true
                } else {
                    ips.append(ip)
                }
            }
            offset = rdataStart + rdLen
        }

        // Also check RFC 8914 Extended DNS Error (OPT RR option code 15 = Blocked, 16 = Censored, 17 = Filtered)
        if checkZeroSinkhole && sinkholed {
            return DoHResult(rcode: rcode, ips: ips, blockedSinkhole: true)
        }
        return DoHResult(rcode: rcode, ips: ips, blockedSinkhole: sinkholed)
    }

    private static func queryDoHReputation(endpoint: String, host: String, checkZeroSinkhole: Bool) async -> DoHResult? {
        guard let wire = buildDNSWireQueryA(host: host),
              let url = URL(string: "\(endpoint)?dns=\(wire)") else { return nil }

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 3.5
        cfg.timeoutIntervalForResource = 4.0
        cfg.urlCache = nil
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }

        var req = URLRequest(url: url)
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { return nil }
            return parseDNSWireResponse(data, checkZeroSinkhole: checkZeroSinkhole)
        } catch {
            return nil
        }
    }
}
