import Foundation
import UIKit

enum MainTab: Hashable {
    case sites
    case apps
    case urlCheck
    case audit
    case tools
}

struct SystemLockdownStatus {
    var lockdownEnabled: Bool = false
    var ldmGlobalDefaults: Bool = false
    var wkCaptivePortalGlobal: Bool = false
    var ctlProbe: String = ""
    var ctlExitCode: Int = -1
    var wkSystemPrefsMethods: [String] = []
    var safariManagerClass: String = ""
    var safariPreferenceKey: String = "PerSitePreferencesLockdownMode"
    var safariOffValue: Int = 0
    var safariOnValue: Int = 1
    var osVersion: String = ""

    var isRootHelperReady: Bool {
        ctlExitCode == 0 && ctlProbe.hasPrefix("OK")
    }
}

struct DeveloperModeStatus {
    var enabled: Bool = false
    var armed: Bool = false
    var writable: Bool = true
    var menuVisible: Bool = false
    var xpcAvailable: Bool = false
    var overridePath: String = ""
}

struct ExcludedWebsiteItem: Identifiable, Hashable {
    var id: String { domain }
    let domain: String
    let preference: String
    let value: Int
    let dbPath: String
}

struct InstalledAppItem: Identifiable, Hashable {
    var id: String { bundleId }
    let bundleId: String
    let name: String
    let isSystem: Bool
    let containerPath: String
    let bundleFolder: String
    var excluded: Bool
    var deepIgnored: Bool
}

struct IOCFindingItem: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let family: String
    let severity: String
    let desc: String
    let found: Bool
}

struct AppAuditFindingItem: Identifiable, Hashable {
    let id: String
    let severity: String   // "high" | "medium"
    let category: String
    let title: String
    let target: String
    let detail: String
}

struct SecurityAuditSummary {
    var scannedApps: Int = 0
    var nonAppStoreApps: Int = 0
    var highCount: Int = 0
    var mediumCount: Int = 0
    var findings: [AppAuditFindingItem] = []
}

enum URLRiskLevel: String {
    case safe = "safe"         // 🟢 未见异常
    case notice = "notice"     // 🟡 建议保持锁定模式访问
    case warning = "warning"   // 🟠 可疑风险，不建议加白名单
    case danger = "danger"     // 🔴 高危拦截（水坑/恶意/钓鱼）
}

struct URLSafetyFinding: Identifiable, Hashable {
    let id = UUID()
    let severity: URLRiskLevel
    let category: String
    let title: String
    let detail: String
}

struct URLSafetyReport {
    let inputURL: String
    let finalURL: String
    let candidateDomain: String
    let redirectChain: [String]
    let httpStatusCode: Int
    let contentType: String
    let fetchedBytes: Int
    let isHTTPS: Bool
    let cloudflareClean: Bool?
    let quad9Clean: Bool?
    let externalScriptDomains: [String]
    let riskLevel: URLRiskLevel
    let summaryTitle: String
    let summaryAdvice: String
    let findings: [URLSafetyFinding]
    let checkedAt: Date
}

struct QuickSitePreset: Identifiable {
    var id: String { domain }
    let label: String
    let domain: String
}

enum AppFilterScope: String, CaseIterable, Identifiable {
    case user = "常用应用"
    case excluded = "已加白名单"
    case all = "全部(含系统)"

    var id: String { rawValue }
}
