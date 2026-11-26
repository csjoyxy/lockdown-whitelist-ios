import Foundation
import SwiftUI
import UIKit

@MainActor
final class AppViewModel: ObservableObject {
    @Published var status = SystemLockdownStatus()
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

    @Published var iocItems: [IOCFindingItem] = []
    @Published var iocClean: Bool = true
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
            try? await Task.sleep(nanoseconds: 2_800_000_000)
            if self.toastMessage == msg {
                withAnimation {
                    self.toastMessage = nil
                }
            }
        }
    }

    func refreshAll() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let sysDict = LBBridgeSystemStatus()
            let safariDict = LBBridgeSafariListExcludedSites()
            let appDicts = LBBridgeListInstalledApps()
            let iocDict = LBBridgeRunIOCScan()

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

            await MainActor.run {
                self.status = parsedStatus
                self.excludedSites = parsedSites
                self.safariDBPaths = dbPaths
                self.safariAllKeys = allKeys
                self.apps = parsedApps
                self.iocItems = parsedIOC
                self.iocClean = cleanFlag
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

    func runIOCScanOnly() {
        isBusy = true
        Task.detached(priority: .userInitiated) {
            let iocDict = LBBridgeRunIOCScan()
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

            await MainActor.run {
                self.iocItems = parsedIOC
                self.iocClean = cleanFlag
                self.iocLastChecked = Date()
                self.isBusy = false
                self.showToast(cleanFlag ? "🛡️ 扫描完成：未发现已知植入痕迹" : "⚠️ 发现异常痕迹，请查看详情")
            }
        }
    }

    func diagnosticReportText() -> String {
        var lines: [String] = []
        lines.append("LockdownBypass v\(LBBridgeVersion()) (\(LBBridgeGitCommit()))")
        lines.append("iOS Version: \(status.osVersion)")
        lines.append("Lockdown Active: \(status.lockdownEnabled) (LDMGlobalDefaults=\(status.ldmGlobalDefaults), WKCaptivePortal=\(status.wkCaptivePortalGlobal))")
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
        lines.append("_WKSystemPreferences Methods: \(status.wkSystemPrefsMethods.joined(separator: ", "))")
        return lines.joined(separator: "\n")
    }
}
