import Foundation
import UIKit

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
