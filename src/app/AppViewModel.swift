import Foundation
import SwiftUI
import UIKit

@MainActor
final class AppViewModel: ObservableObject {
    @Published var selectedTab: MainTab = .sites

    @Published var status = SystemLockdownStatus()
    @Published var devMode = DeveloperModeStatus()
    @Published var showDevModeRebootPrompt: Bool = false
    @Published var showManualRebootConfirm: Bool = false

    @Published var excludedSites: [ExcludedWebsiteItem] = []
    @Published var safariDBPaths: [String] = []
    @Published var safariAllKeys: [String] = []

    @Published var apps: [InstalledAppItem] = []
    @Published var appFilter: AppFilterScope = .user
    @Published var appSearchText: String = ""
    @Published var siteSearchText: String = ""

    @Published var domainInput: String = ""
    @Published var expandSubdomains: Bool = true
    @Published var enableDeepAppOverride: Bool = false

    @Published var urlProbeInput: String = ""
    @Published var isProbingURL: Bool = false
    @Published var urlReport: URLSafetyReport? = nil

    @Published var iocItems: [IOCFindingItem] = []
    @Published var iocClean: Bool = true
    @Published var auditSummary = SecurityAuditSummary()
    @Published var iocLastChecked: Date? = nil

    @Published var isBusy: Bool = false
    @Published var toastMessage: String? = nil

    private var iconCache: [String: UIImage] = [:]

    let quickPresets: [QuickSitePreset] = [
        QuickSitePreset(label: "淘宝", domain: "taobao.com"),
        QuickSitePreset(label: "天猫", domain: "tmall.com"),
        QuickSitePreset(label: "京东", domain: "jd.com"),
        QuickSitePreset(label: "哔哩哔哩", domain: "bilibili.com"),
        QuickSitePreset(label: "微信网页/公众号", domain: "weixin.qq.com"),
        QuickSitePreset(label: "QQ / 腾讯登录", domain: "qq.com"),
        QuickSitePreset(label: "支付宝", domain: "alipay.com"),
        QuickSitePreset(label: "GitHub", domain: "github.com"),
        QuickSitePreset(label: "Cloudflare 验证", domain: "challenges.cloudflare.com"),
        QuickSitePreset(label: "ChatGPT", domain: "chatgpt.com"),
        QuickSitePreset(label: "Claude", domain: "claude.ai")
    ]

    init() {
        refreshAll()
    }

    func showToast(_ msg: String) {
        toastMessage = msg
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if self.toastMessage == msg {
                withAnimation {
                    self.toastMessage = nil
                }
            }
        }
    }

    nonisolated private static func parseDevModeStatus(_ dict: [String: Any]) -> DeveloperModeStatus {
        DeveloperModeStatus(
            enabled: (dict["enabled"] as? NSNumber)?.boolValue ?? false,
            armed: (dict["armed"] as? NSNumber)?.boolValue ?? false,
            writable: (dict["writable"] as? NSNumber)?.boolValue ?? true,
            menuVisible: (dict["menuVisible"] as? NSNumber)?.boolValue ?? false,
            xpcAvailable: (dict["xpcAvailable"] as? NSNumber)?.boolValue ?? false,
            overridePath: (dict["overridePath"] as? String) ?? ""
        )
    }

    nonisolated private static func parseAuditSummary(_ dict: [String: Any]) -> SecurityAuditSummary {
        let rawFindings = (dict["findings"] as? [[String: Any]]) ?? []
        let items: [AppAuditFindingItem] = rawFindings.compactMap { row in
            guard let id = row["id"] as? String, let title = row["title"] as? String else { return nil }
            return AppAuditFindingItem(
                id: id,
                severity: (row["severity"] as? String) ?? "medium",
                category: (row["category"] as? String) ?? "",
                title: title,
                target: (row["target"] as? String) ?? "",
                detail: (row["detail"] as? String) ?? ""
            )
        }
        return SecurityAuditSummary(
            scannedApps: (dict["scannedApps"] as? NSNumber)?.intValue ?? 0,
            nonAppStoreApps: (dict["nonAppStoreApps"] as? NSNumber)?.intValue ?? 0,
            highCount: (dict["highCount"] as? NSNumber)?.intValue ?? 0,
            mediumCount: (dict["mediumCount"] as? NSNumber)?.intValue ?? 0,
            findings: items
        )
    }

    func refreshAll() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let sysDict = LBBridgeSystemStatus()
            let devDict = LBBridgeDeveloperModeStatus()
            let safariDict = LBBridgeSafariListExcludedSites()
            let appDicts = LBBridgeListInstalledApps()
            let iocDict = LBBridgeRunIOCScan()
            let auditDict = LBBridgeRunSecurityAudit()

            let parsedStatus = SystemLockdownStatus(
                lockdownEnabled: (sysDict["lockdownEnabled"] as? NSNumber)?.boolValue ?? false,
                ldmGlobalDefaults: (sysDict["ldmGlobalDefaults"] as? NSNumber)?.boolValue ?? false,
                wkCaptivePortalGlobal: (sysDict["wkCaptivePortalGlobal"] as? NSNumber)?.boolValue ?? false,
                ctlProbe: (sysDict["ctlProbe"] as? String) ?? "",
                ctlExitCode: (sysDict["ctlExitCode"] as? NSNumber)?.intValue ?? -1,
                wkSystemPrefsMethods: (sysDict["wkSystemPrefsMethods"] as? [String]) ?? [],
                safariManagerClass: (sysDict["safariManagerClass"] as? String) ?? "",
                safariPreferenceKey: (sysDict["safariPreferenceKey"] as? String) ?? "PerSitePreferencesLockdownMode",
                safariOffValue: (sysDict["safariOffValue"] as? NSNumber)?.intValue ?? 0,
                safariOnValue: (sysDict["safariOnValue"] as? NSNumber)?.intValue ?? 1,
                osVersion: (sysDict["osVersion"] as? String) ?? ""
            )
            let parsedDev = Self.parseDevModeStatus(devDict)

            let rawSites = (safariDict["items"] as? [[String: Any]]) ?? []
            let parsedSites: [ExcludedWebsiteItem] = rawSites.compactMap { row in
                guard let dom = row["domain"] as? String, !dom.isEmpty else { return nil }
                let pref = (row["preference"] as? String) ?? parsedStatus.safariPreferenceKey
                let val = (row["value"] as? NSNumber)?.intValue ?? 0
                let dbp = (row["dbPath"] as? String) ?? ""
                return ExcludedWebsiteItem(domain: dom, preference: pref, value: val, dbPath: dbp)
            }
            let dbPaths = (safariDict["dbPaths"] as? [String]) ?? []
            let allKeys = (safariDict["allPreferenceKeys"] as? [String]) ?? []

            let parsedApps: [InstalledAppItem] = appDicts.compactMap { d in
                guard let bid = d["bundleId"] as? String, !bid.isEmpty else { return nil }
                let name = (d["name"] as? String) ?? bid
                let isSys = (d["isSystem"] as? NSNumber)?.boolValue ?? false
                let cpath = (d["containerPath"] as? String) ?? ""
                let bfolder = (d["bundleFolder"] as? String) ?? ""
                let excl = (d["excluded"] as? NSNumber)?.boolValue ?? false
                let deep = (d["deepIgnored"] as? NSNumber)?.boolValue ?? false
                return InstalledAppItem(
                    bundleId: bid,
                    name: name,
                    isSystem: isSys,
                    containerPath: cpath,
                    bundleFolder: bfolder,
                    excluded: excl,
                    deepIgnored: deep
                )
            }

            let rawIOC = (iocDict["items"] as? [[String: Any]]) ?? []
            let parsedIOC: [IOCFindingItem] = rawIOC.compactMap { item in
                guard let p = item["path"] as? String else { return nil }
                return IOCFindingItem(
                    path: p,
                    family: (item["family"] as? String) ?? "",
                    severity: (item["severity"] as? String) ?? "high",
                    desc: (item["desc"] as? String) ?? "",
                    found: (item["found"] as? NSNumber)?.boolValue ?? false
                )
            }
            let cleanFlag = (iocDict["clean"] as? NSNumber)?.boolValue ?? parsedIOC.allSatisfy { !$0.found }
            let parsedAudit = Self.parseAuditSummary(auditDict)

            await MainActor.run {
                self.status = parsedStatus
                self.devMode = parsedDev
                self.excludedSites = parsedSites
                self.safariDBPaths = dbPaths
                self.safariAllKeys = allKeys
                self.apps = parsedApps
                self.iocItems = parsedIOC
                self.iocClean = cleanFlag
                self.auditSummary = parsedAudit
                self.iocLastChecked = Date()
                self.isBusy = false
            }
        }
    }

    func icon(for bundleId: String) -> UIImage? {
        if let cached = iconCache[bundleId] {
            return cached
        }
        if let data = LBBridgeAppIconPNG(bundleId), let img = UIImage(data: data) {
            iconCache[bundleId] = img
            return img
        }
        return nil
    }

    // MARK: - Domain Parsing & Safari Whitelist Actions

    static func extractCandidateDomains(from rawInput: String, expandSubdomains: Bool) -> [String] {
        let separators = CharacterSet(charactersIn: ",，;；\n\r\t ")
        let tokens = rawInput.components(separatedBy: separators)
        var ordered: [String] = []
        var seen = Set<String>()

        func appendUnique(_ d: String) {
            let clean = d.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !clean.isEmpty, clean.contains("."), !clean.contains(".."), !seen.contains(clean) else { return }
            seen.insert(clean)
            ordered.append(clean)
        }

        for rawTok in tokens {
            var s = rawTok.trimmingCharacters(in: .whitespacesAndNewlines)
            if s.isEmpty { continue }
            if !s.contains("://") {
                s = "https://" + s
            }
            var host = ""
            if let comps = URLComponents(string: s), let h = comps.host, !h.isEmpty {
                host = h.lowercased()
            } else {
                var fallback = rawTok.lowercased()
                if let r = fallback.range(of: "://") {
                    fallback = String(fallback[r.upperBound...])
                }
                if let slash = fallback.firstIndex(of: "/") {
                    fallback = String(fallback[..<slash])
                }
                if let colon = fallback.firstIndex(of: ":") {
                    fallback = String(fallback[..<colon])
                }
                host = fallback
            }
            while host.hasPrefix(".") { host.removeFirst() }
            while host.hasSuffix(".") { host.removeLast() }
            guard !host.isEmpty, host.contains(".") else { continue }

            let root = LBBridgeHighLevelDomain(host)
            if !root.isEmpty {
                appendUnique(root)
            }
            if host.hasPrefix("www.") {
                let noWww = String(host.dropFirst(4))
                if noWww.contains(".") {
                    appendUnique(noWww)
                }
            }
            appendUnique(host)

            if expandSubdomains && !root.isEmpty {
                appendUnique("www." + root)
                appendUnique("m." + root)
            }
        }
        return ordered
    }

    func addDomainsFromInput() {
        let targets = Self.extractCandidateDomains(from: domainInput, expandSubdomains: expandSubdomains)
        guard !targets.isEmpty else {
            showToast("请输入有效域名或网址（如 taobao.com）")
            return
        }
        domainInput = ""
        setSafariDomains(targets, excluded: true)
    }

    func precheckDomainInputInSandbox() {
        let trimmed = domainInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            urlProbeInput = trimmed
        }
        selectedTab = .urlCheck
        if !urlProbeInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            runURLSafetyProbe()
        }
    }

    func quickAddSite(_ domain: String) {
        let targets = Self.extractCandidateDomains(from: domain, expandSubdomains: expandSubdomains)
        setSafariDomains(targets, excluded: true)
    }

    func removeExcludedSite(_ item: ExcludedWebsiteItem) {
        setSafariDomains([item.domain], excluded: false)
    }

    private func setSafariDomains(_ domains: [String], excluded: Bool) {
        guard !domains.isEmpty else { return }
        isBusy = true
        Task.detached(priority: .userInitiated) {
            var failMsg = ""
            var okCount = 0
            for d in domains {
                let err = LBBridgeSafariSetDomainExcluded(d, excluded)
                if err.isEmpty {
                    okCount += 1
                } else if failMsg.isEmpty {
                    failMsg = err
                }
            }
            let safariDict = LBBridgeSafariListExcludedSites()
            let rawSites = (safariDict["items"] as? [[String: Any]]) ?? []
            let prefDefault = (safariDict["preferenceKey"] as? String) ?? "PerSitePreferencesLockdownMode"
            let parsedSites: [ExcludedWebsiteItem] = rawSites.compactMap { row in
                guard let dom = row["domain"] as? String, !dom.isEmpty else { return nil }
                return ExcludedWebsiteItem(
                    domain: dom,
                    preference: (row["preference"] as? String) ?? prefDefault,
                    value: (row["value"] as? NSNumber)?.intValue ?? 0,
                    dbPath: (row["dbPath"] as? String) ?? ""
                )
            }
            let dbPaths = (safariDict["dbPaths"] as? [String]) ?? []

            await MainActor.run {
                self.excludedSites = parsedSites
                self.safariDBPaths = dbPaths
                self.isBusy = false
                if okCount > 0 {
                    if excluded {
                        self.showToast("✅ 已将 \(okCount) 个域名加入白名单（点右上角重启 Safari 立即生效）")
                    } else {
                        self.showToast("🔒 已恢复该域名的锁定模式防护")
                    }
                } else {
                    self.showToast("⚠️ 操作失败：\(failMsg)")
                }
            }
        }
    }

    func restartSafariNow() {
        Task.detached(priority: .userInitiated) {
            let killed = LBBridgeRestartSafari()
            await MainActor.run {
                if killed > 0 {
                    self.showToast("🔄 已重启 Safari（结束 \(killed) 个进程），新白名单立即生效")
                } else {
                    self.showToast("✅ Safari 当前未在后台运行，直接打开即可生效")
                }
            }
        }
    }

    // MARK: - Zero-WebKit URL Safety Pre-Flight Sandbox

    func runURLSafetyProbe(customInput: String? = nil) {
        if let custom = customInput {
            urlProbeInput = custom
        }
        let target = urlProbeInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            showToast("请输入要检测的网址或域名")
            return
        }
        isProbingURL = true
        Task {
            let res = await URLSafetyInspector.inspect(rawInput: target)
            self.isProbingURL = false
            switch res {
            case .success(let report):
                self.urlReport = report
            case .failure(let err):
                self.showToast("⚠️ \(err.localizedDescription)")
            }
        }
    }

    func whitelistProbedReport(_ report: URLSafetyReport) {
        let targets = Self.extractCandidateDomains(from: report.candidateDomain, expandSubdomains: expandSubdomains)
        setSafariDomains(targets, excluded: true)
    }

    // MARK: - App Whitelist Actions

    var filteredApps: [InstalledAppItem] {
        let q = appSearchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return apps.filter { app in
            switch appFilter {
            case .user:
                if app.isSystem && !app.excluded { return false }
            case .excluded:
                if !app.excluded { return false }
            case .all:
                break
            }
            if q.isEmpty { return true }
            return app.name.lowercased().contains(q) || app.bundleId.lowercased().contains(q)
        }
    }

    var filteredSites: [ExcludedWebsiteItem] {
        let q = siteSearchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty { return excludedSites }
        return excludedSites.filter { $0.domain.lowercased().contains(q) }
    }

    func toggleAppExcluded(_ app: InstalledAppItem, to newValue: Bool) {
        let deep = enableDeepAppOverride
        if let idx = apps.firstIndex(where: { $0.bundleId == app.bundleId }) {
            apps[idx].excluded = newValue
            apps[idx].deepIgnored = newValue && deep
        }

        Task.detached(priority: .userInitiated) {
            let err = LBBridgeSetAppExcluded(app.bundleId, app.containerPath, newValue, deep)
            var killed = 0
            if err.isEmpty && !app.bundleFolder.isEmpty {
                killed = LBBridgeRestartApp(app.bundleFolder)
            }
            await MainActor.run {
                if !err.isEmpty {
                    if let idx = self.apps.firstIndex(where: { $0.bundleId == app.bundleId }) {
                        self.apps[idx].excluded = !newValue
                    }
                    self.showToast("⚠️ 修改 \(app.name) 失败：\(err)")
                } else if newValue {
                    let tail = killed > 0 ? "（已自动重启该应用生效）" : "（下次打开立即生效）"
                    self.showToast("✅ 已关闭「\(app.name)」的锁定模式\(tail)")
                } else {
                    self.showToast("🔒 已恢复「\(app.name)」的锁定模式保护")
                }
            }
        }
    }

    // MARK: - Full Offline IOC + WQGuard-Inspired Security Audit

    func runIOCScanOnly() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let iocDict = LBBridgeRunIOCScan()
            let auditDict = LBBridgeRunSecurityAudit()

            let rawIOC = (iocDict["items"] as? [[String: Any]]) ?? []
            let parsedIOC: [IOCFindingItem] = rawIOC.compactMap { item in
                guard let p = item["path"] as? String else { return nil }
                return IOCFindingItem(
                    path: p,
                    family: (item["family"] as? String) ?? "",
                    severity: (item["severity"] as? String) ?? "high",
                    desc: (item["desc"] as? String) ?? "",
                    found: (item["found"] as? NSNumber)?.boolValue ?? false
                )
            }
            let cleanFlag = (iocDict["clean"] as? NSNumber)?.boolValue ?? parsedIOC.allSatisfy { !$0.found }
            let parsedAudit = Self.parseAuditSummary(auditDict)

            await MainActor.run {
                self.iocItems = parsedIOC
                self.iocClean = cleanFlag
                self.auditSummary = parsedAudit
                self.iocLastChecked = Date()
                self.isBusy = false
                let okAll = cleanFlag && parsedAudit.highCount == 0
                self.showToast(okAll ? "🛡️ 深度审计完成：未发现高危木马或水坑痕迹" : "⚠️ 发现高危风险项，请查看报告详情")
            }
        }
    }

    // MARK: - Developer Mode Management (No PC / No 3uTools Needed)

    func armDeveloperModeNow() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let res = LBBridgeDeveloperModeArm()
            let ok = (res["ok"] as? NSNumber)?.boolValue ?? false
            let already = (res["alreadyEnabled"] as? NSNumber)?.boolValue ?? false
            let err = (res["error"] as? String) ?? ""
            let parsed = Self.parseDevModeStatus(res)

            await MainActor.run {
                self.devMode = parsed
                self.isBusy = false
                if already || parsed.enabled {
                    self.showToast("✅ 开发者模式当前已经处于开启状态！")
                } else if ok || parsed.armed {
                    self.showDevModeRebootPrompt = true
                } else {
                    self.showToast("⚠️ \(err.isEmpty ? "预开启失败，请确认已通过巨魔安装" : err)")
                }
            }
        }
    }

    func revealDeveloperModeMenuOnly() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let res = LBBridgeDeveloperModeRevealMenu()
            let ok = (res["ok"] as? NSNumber)?.boolValue ?? false
            let err = (res["error"] as? String) ?? ""
            let parsed = Self.parseDevModeStatus(res)

            await MainActor.run {
                self.devMode = parsed
                self.isBusy = false
                if ok || parsed.menuVisible {
                    self.showToast("✅ 已在「设置 → 隐私与安全性」底部显示开发者模式入口")
                } else {
                    self.showToast("⚠️ 显示入口失败：\(err)")
                }
            }
        }
    }

    func disableDeveloperModeNow() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let res = LBBridgeDeveloperModeDisable()
            let ok = (res["ok"] as? NSNumber)?.boolValue ?? false
            let parsed = Self.parseDevModeStatus(res)

            await MainActor.run {
                self.devMode = parsed
                self.isBusy = false
                self.showToast(ok ? "🔒 已关闭系统开发者模式" : "⚠️ 关闭开发者模式失败")
            }
        }
    }

    func rebootDeviceNow() {
        Task.detached(priority: .userInitiated) {
            LBBridgeRebootDevice()
        }
    }

    func diagnosticReportText() -> String {
        var lines: [String] = []
        lines.append("LockdownBypass v\(LBBridgeVersion()) (\(LBBridgeGitCommit()))")
        lines.append("iOS Version: \(status.osVersion)")
        lines.append("Lockdown Active: \(status.lockdownEnabled) (LDMGlobalDefaults=\(status.ldmGlobalDefaults), WKCaptivePortal=\(status.wkCaptivePortalGlobal))")
        lines.append("Developer Mode: enabled=\(devMode.enabled), armed=\(devMode.armed), writable=\(devMode.writable), menuVisible=\(devMode.menuVisible), xpc=\(devMode.xpcAvailable)")
        lines.append("Root Helper Probe: \(status.ctlProbe) (exit=\(status.ctlExitCode))")
        lines.append("Safari Manager Class: \(status.safariManagerClass.isEmpty ? "<fallback>" : status.safariManagerClass)")
        lines.append("Safari SQLite Key: \(status.safariPreferenceKey) (off=\(status.safariOffValue), on=\(status.safariOnValue))")
        lines.append("Safari DB Paths (\(safariDBPaths.count)):")
        for p in safariDBPaths {
            lines.append("  - \(p)")
        }
        lines.append("Safari Existing Preference Keys: \(safariAllKeys.joined(separator: ", "))")
        lines.append("Excluded Safari Domains: \(excludedSites.count)")
        lines.append("Installed Apps w/ Containers: \(apps.count) (Excluded: \(apps.filter { $0.excluded }.count))")
        lines.append("Security Audit: scanned=\(auditSummary.scannedApps), sideload/troll=\(auditSummary.nonAppStoreApps), high=\(auditSummary.highCount), medium=\(auditSummary.mediumCount)")
        lines.append("_WKSystemPreferences Methods: \(status.wkSystemPrefsMethods.joined(separator: ", "))")
        return lines.joined(separator: "\n")
    }
}
