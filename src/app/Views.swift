import SwiftUI
import UIKit

struct RootContentView: View {
    @StateObject private var vm = AppViewModel()

    var body: some View {
        ZStack(alignment: .bottom) {
            TabView(selection: $vm.selectedTab) {
                SafariSitesTabView(vm: vm)
                    .tabItem {
                        Label("网站白名单", systemImage: "safari.fill")
                    }
                    .tag(MainTab.sites)

                AppsWhitelistTabView(vm: vm)
                    .tabItem {
                        Label("应用白名单", systemImage: "square.grid.2x2.fill")
                    }
                    .tag(MainTab.apps)

                URLSafetyTabView(vm: vm)
                    .tabItem {
                        Label("网址预检", systemImage: "globe")
                    }
                    .tag(MainTab.urlCheck)

                IOCScannerTabView(vm: vm)
                    .tabItem {
                        Label("安全体检", systemImage: "checkmark.shield.fill")
                    }
                    .tag(MainTab.audit)

                DiagnosticsTabView(vm: vm)
                    .tabItem {
                        Label("系统工具", systemImage: "hammer.fill")
                    }
                    .tag(MainTab.tools)
            }

            if let msg = vm.toastMessage {
                Text(msg)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(.white)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(Color.black.opacity(0.84))
                    .clipShape(Capsule())
                    .shadow(color: Color.black.opacity(0.22), radius: 8, x: 0, y: 4)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 62)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: vm.toastMessage)
    }
}

// MARK: - Tab 1: Safari Website Whitelist

struct SafariSitesTabView: View {
    @ObservedObject var vm: AppViewModel

    var body: some View {
        NavigationView {
            List {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: vm.status.lockdownEnabled ? "lock.shield.fill" : "shield.slash")
                            .font(.system(size: 26, weight: .semibold))
                            .foregroundColor(vm.status.lockdownEnabled ? .green : .orange)

                        VStack(alignment: .leading, spacing: 3) {
                            Text(vm.status.lockdownEnabled ? "系统「锁定模式」当前已开启" : "系统「锁定模式」当前未开启")
                                .font(.system(size: 15, weight: .semibold))
                            Text(vm.status.isRootHelperReady
                                 ? "巨魔 Root 助手就绪 · 无需先打开网页即可预设白名单"
                                 : "提示：未检测到 TrollStore Root 权限，请通过巨魔安装")
                                .font(.system(size: 12))
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section(
                    header: Text("主动添加免锁定网站（无需先在 Safari 打开）"),
                    footer: Text("不确定某个网站是否安全时，可点「先安全预检」在不调用 WebKit 的隔离沙盒中检测挂马/钓鱼风险；确认安全后再加白名单并点右上角「重启Safari生效」。")
                ) {
                    VStack(alignment: .leading, spacing: 10) {
                        TextField("输入域名或粘贴完整网址 (如 taobao.com)", text: $vm.domainInput)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                            .textFieldStyle(.roundedBorder)

                        HStack(spacing: 8) {
                            Button {
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                vm.precheckDomainInputInSandbox()
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: "magnifyingglass")
                                    Text("先安全预检")
                                }
                                .font(.system(size: 13, weight: .semibold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 8)
                                .background(Color.secondary.opacity(0.14))
                                .foregroundColor(.primary)
                                .cornerRadius(8)
                            }
                            .buttonStyle(.plain)

                            Button {
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                vm.addDomainsFromInput()
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: "plus.circle.fill")
                                    Text("加白名单")
                                }
                                .font(.system(size: 13, weight: .semibold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 8)
                                .background(Color.accentColor)
                                .foregroundColor(.white)
                                .cornerRadius(8)
                            }
                            .buttonStyle(.plain)
                        }

                        Toggle("同时豁免根域名与常见子域 (www. / m.)", isOn: $vm.expandSubdomains)
                            .font(.system(size: 13.5))
                    }
                    .padding(.vertical, 4)

                    VStack(alignment: .leading, spacing: 8) {
                        Text("常见易受限站点一键预设：")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.secondary)

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(vm.quickPresets) { preset in
                                    let isAdded = vm.excludedSites.contains(where: { $0.domain == preset.domain })
                                    Button {
                                        vm.quickAddSite(preset.domain)
                                    } label: {
                                        HStack(spacing: 4) {
                                            Image(systemName: isAdded ? "checkmark.circle.fill" : "plus.circle")
                                                .font(.system(size: 12))
                                            Text(preset.label)
                                                .font(.system(size: 12.5, weight: .medium))
                                        }
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(isAdded ? Color.green.opacity(0.16) : Color.secondary.opacity(0.12))
                                        .foregroundColor(isAdded ? .green : .primary)
                                        .clipShape(Capsule())
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    .padding(.vertical, 2)
                }

                Section(header: Text("已排除锁定模式的 Safari 网站 (\(vm.excludedSites.count))")) {
                    if !vm.excludedSites.isEmpty {
                        TextField("搜索已添加的域名...", text: $vm.siteSearchText)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                    }

                    if vm.filteredSites.isEmpty {
                        Text(vm.excludedSites.isEmpty
                             ? "当前暂无已排除的网站。在上方输入域名并点击「加白名单」即可添加。"
                             : "没有匹配的域名")
                            .font(.system(size: 13.5))
                            .foregroundColor(.secondary)
                            .padding(.vertical, 6)
                    } else {
                        ForEach(vm.filteredSites) { site in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(site.domain)
                                        .font(.system(size: 15, weight: .medium))
                                    Text("已关闭锁定模式 (启用 JIT / 网页字体 / WebGL)")
                                        .font(.system(size: 11.5))
                                        .foregroundColor(.green)
                                }
                                Spacer()
                                Button(role: .destructive) {
                                    vm.removeExcludedSite(site)
                                } label: {
                                    Text("恢复锁定")
                                        .font(.system(size: 12.5, weight: .semibold))
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 5)
                                        .background(Color.red.opacity(0.12))
                                        .foregroundColor(.red)
                                        .cornerRadius(6)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("网站白名单")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        vm.refreshAll()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        vm.restartSafariNow()
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "bolt.horizontal.circle.fill")
                            Text("重启Safari生效")
                                .font(.system(size: 13.5, weight: .semibold))
                        }
                    }
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}

// MARK: - Tab 2: Installed Apps Whitelist

struct AppsWhitelistTabView: View {
    @ObservedObject var vm: AppViewModel

    var body: some View {
        NavigationView {
            List {
                Section(
                    footer: Text("补齐 iOS 18 主动管理体验：开启右侧开关即为该 App 关闭 WebKit 锁定模式（恢复内置网页的满速 JIT、图标字体与 WebGL），切换时会自动重启正在运行的目标 App 使其立即生效。")
                ) {
                    Picker("筛选", selection: $vm.appFilter) {
                        ForEach(AppFilterScope.allCases) { scope in
                            Text(scope.rawValue).tag(scope)
                        }
                    }
                    .pickerStyle(.segmented)

                    TextField("搜索应用名称或 Bundle ID (如 微信 / taobao)...", text: $vm.appSearchText)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)

                    Toggle(isOn: $vm.enableDeepAppOverride) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("深度豁免模式（可选）")
                                .font(.system(size: 14, weight: .medium))
                            Text("除豁免 WebKit 外，同步在该 App 容器内标记 LDMGlobalEnabled=NO")
                                .font(.system(size: 11.5))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                Section(header: Text("应用列表（开关亮起 = 已加入白名单关闭锁定模式）· 共 \(vm.filteredApps.count) 个")) {
                    if vm.filteredApps.isEmpty {
                        Text("未找到符合条件的应用")
                            .font(.system(size: 13.5))
                            .foregroundColor(.secondary)
                            .padding(.vertical, 8)
                    } else {
                        ForEach(vm.filteredApps) { app in
                            AppRowView(app: app, icon: vm.icon(for: app.bundleId)) { newVal in
                                vm.toggleAppExcluded(app, to: newVal)
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("应用白名单")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        vm.refreshAll()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}

private struct AppRowView: View {
    let app: InstalledAppItem
    let icon: UIImage?
    let onToggle: (Bool) -> Void

    var body: some View {
        HStack(spacing: 12) {
            if let img = icon {
                Image(uiImage: img)
                    .resizable()
                    .frame(width: 38, height: 38)
                    .cornerRadius(8.5)
            } else {
                RoundedRectangle(cornerRadius: 8.5)
                    .fill(Color.accentColor.opacity(0.15))
                    .frame(width: 38, height: 38)
                    .overlay(
                        Image(systemName: "app.fill")
                            .foregroundColor(.accentColor)
                    )
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(app.name)
                        .font(.system(size: 15, weight: .medium))
                        .lineLimit(1)
                    if app.isSystem {
                        Text("系统")
                            .font(.system(size: 10, weight: .semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1.5)
                            .background(Color.secondary.opacity(0.16))
                            .cornerRadius(4)
                    }
                }
                Text(app.bundleId)
                    .font(.system(size: 11.5))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                if app.excluded {
                    Text(app.deepIgnored ? "已豁免锁定模式 (WebKit + 深度偏好)" : "已豁免 WebKit 锁定模式")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.green)
                }
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { app.excluded },
                set: { onToggle($0) }
            ))
            .labelsHidden()
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Tab 3: Zero-WebKit URL Safety Pre-Flight Sandbox

struct URLSafetyTabView: View {
    @ObservedObject var vm: AppViewModel

    private func colorForRisk(_ level: URLRiskLevel) -> Color {
        switch level {
        case .safe: return .green
        case .notice: return .blue
        case .warning: return .orange
        case .danger: return .red
        }
    }

    var body: some View {
        NavigationView {
            List {
                Section(
                    header: Text("零渲染安全沙盒检测（不调用 WebKit · 100% 免触发漏洞）"),
                    footer: Text("为什么不用内置浏览器直接打开？在 iOS 16.4.1 上，一旦用 WebKit 渲染恶意网页就可能直接触发漏洞。本检测通过隔离网络流拉取前 256KB 文本、追踪跳转链、并发核验 Cloudflare(1.1.1.2) 与 Quad9(9.9.9.9) 全球恶意库，并静态审计隐藏挂马 iframe、JIT 利用原语与盗币钓鱼特征。")
                ) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            TextField("输入或粘贴待测网址 (如 https://example.com)", text: $vm.urlProbeInput)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .disableAutocorrection(true)
                                .textFieldStyle(.roundedBorder)

                            Button {
                                if let str = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines), !str.isEmpty {
                                    vm.urlProbeInput = str
                                } else {
                                    vm.showToast("剪贴板为空")
                                }
                            } label: {
                                Text("粘贴")
                                    .font(.system(size: 13, weight: .medium))
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 8)
                                    .background(Color.secondary.opacity(0.14))
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.plain)
                        }

                        Button {
                            UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                            vm.runURLSafetyProbe()
                        } label: {
                            HStack {
                                Spacer()
                                if vm.isProbingURL {
                                    ProgressView()
                                        .padding(.trailing, 6)
                                    Text("正在隔离拉取与多源核验...")
                                } else {
                                    Image(systemName: "checkmark.shield.fill")
                                    Text("开始安全检测")
                                }
                                Spacer()
                            }
                            .font(.system(size: 14.5, weight: .semibold))
                            .padding(.vertical, 9)
                            .background(Color.accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(9)
                        }
                        .buttonStyle(.plain)
                        .disabled(vm.isProbingURL)

                        HStack(spacing: 8) {
                            Text("一键体验：")
                                .font(.system(size: 11.5))
                                .foregroundColor(.secondary)
                            Button {
                                vm.runURLSafetyProbe(customInput: "https://www.apple.com/cn/")
                            } label: {
                                Text("测正常官网")
                                    .font(.system(size: 11.5, weight: .medium))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.green.opacity(0.14))
                                    .foregroundColor(.green)
                                    .clipShape(Capsule())
                            }
                            .buttonStyle(.plain)

                            Button {
                                vm.runURLSafetyProbe(customInput: "http://aidm8it5hf1jmtj.xyz/details/show.html")
                            } label: {
                                Text("测水坑样本(无害模拟)")
                                    .font(.system(size: 11.5, weight: .medium))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.red.opacity(0.14))
                                    .foregroundColor(.red)
                                    .clipShape(Capsule())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.vertical, 4)
                }

                if let report = vm.urlReport {
                    Section(header: Text("检测结论 · \(report.candidateDomain)")) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(report.summaryTitle)
                                .font(.system(size: 15.5, weight: .bold))
                                .foregroundColor(colorForRisk(report.riskLevel))

                            Text(report.summaryAdvice)
                                .font(.system(size: 13))
                                .foregroundColor(.secondary)

                            Divider()

                            VStack(alignment: .leading, spacing: 4) {
                                Text("• 协议与状态：\(report.isHTTPS ? "HTTPS 加密" : "HTTP 明文") · HTTP \(report.httpStatusCode > 0 ? "\(report.httpStatusCode)" : "未响应") · 读取 \(report.fetchedBytes / 1024) KB")
                                Text("• Cloudflare 1.1.1.2 情报：\(dohStatusLabel(report.cloudflareClean))")
                                Text("• Quad9 9.9.9.9 情报：\(dohStatusLabel(report.quad9Clean))")
                                Text("• 跳转次数：\(max(0, report.redirectChain.count - 1)) 次 · 外部脚本域：\(report.externalScriptDomains.count) 个")
                            }
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)

                            if report.riskLevel == .safe || report.riskLevel == .notice {
                                Button {
                                    vm.whitelistProbedReport(report)
                                } label: {
                                    HStack {
                                        Spacer()
                                        Image(systemName: "plus.circle.fill")
                                        Text("将该域名加入 Safari 白名单 (\(report.candidateDomain))")
                                        Spacer()
                                    }
                                    .font(.system(size: 13.5, weight: .semibold))
                                    .padding(.vertical, 8)
                                    .background(Color.green.opacity(0.16))
                                    .foregroundColor(.green)
                                    .cornerRadius(8)
                                }
                                .buttonStyle(.plain)
                                .padding(.top, 4)
                            }
                        }
                        .padding(.vertical, 4)
                    }

                    if !report.findings.isEmpty {
                        Section(header: Text("风险与特征明细 (\(report.findings.count))")) {
                            ForEach(report.findings) { f in
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Text(f.category)
                                            .font(.system(size: 10.5, weight: .bold))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(colorForRisk(f.severity).opacity(0.16))
                                            .foregroundColor(colorForRisk(f.severity))
                                            .cornerRadius(4)
                                        Text(f.title)
                                            .font(.system(size: 13.5, weight: .semibold))
                                    }
                                    Text(f.detail)
                                        .font(.system(size: 12))
                                        .foregroundColor(.secondary)
                                }
                                .padding(.vertical, 3)
                            }
                        }
                    }

                    if report.redirectChain.count > 1 {
                        Section(header: Text("跳转链路追踪 (\(report.redirectChain.count) 跳)")) {
                            ForEach(Array(report.redirectChain.enumerated()), id: \.offset) { idx, hop in
                                Text("\(idx + 1). \(hop)")
                                    .font(.system(size: 11.5, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }

                    if !report.externalScriptDomains.isEmpty {
                        Section(header: Text("页面引用的第三方脚本/框架域名 (\(report.externalScriptDomains.count))")) {
                            Text(report.externalScriptDomains.joined(separator: "  ·  "))
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(.secondary)
                                .padding(.vertical, 2)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("网址预检")
        }
        .navigationViewStyle(.stack)
    }

    private func dohStatusLabel(_ clean: Bool?) -> String {
        guard let c = clean else { return "网络超时或未解析" }
        return c ? "✅ 未见恶意标记" : "🚨 命中恶意/钓鱼黑名单！"
    }
}

// MARK: - Tab 4: Offline Exploit-Kit IOC + WQGuard-Inspired Sideload & Container Audit

struct IOCScannerTabView: View {
    @ObservedObject var vm: AppViewModel

    private var overallHealthy: Bool {
        vm.iocClean && vm.auditSummary.highCount == 0
    }

    var body: some View {
        NavigationView {
            List {
                Section {
                    HStack(spacing: 14) {
                        Image(systemName: overallHealthy ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .font(.system(size: 32))
                            .foregroundColor(overallHealthy ? .green : .red)

                        VStack(alignment: .leading, spacing: 4) {
                            Text(overallHealthy ? "本机未发现水坑植入或高危木马应用" : "检出高危风险项，请立即核查！")
                                .font(.system(size: 15.5, weight: .bold))
                            Text("已审计 \(vm.auditSummary.scannedApps) 个应用（含 \(vm.auditSummary.nonAppStoreApps) 个巨魔/侧载包）· 物理只读零修改")
                                .font(.system(size: 12))
                                .foregroundColor(.secondary)
                            if let dt = vm.iocLastChecked {
                                Text("上次扫描：\(dt.formatted(date: .omitted, time: .standard))")
                                    .font(.system(size: 11.5))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                    .padding(.vertical, 6)

                    Button {
                        vm.runIOCScanOnly()
                    } label: {
                        HStack {
                            Spacer()
                            Label("立即重新扫描（水坑 IOC + 侧载/容器深度审计）", systemImage: "magnifyingglass.circle.fill")
                                .font(.system(size: 14, weight: .semibold))
                            Spacer()
                        }
                        .padding(.vertical, 4)
                    }
                }

                Section(
                    header: Text("巨魔/侧载应用与容器只读审计（借鉴 WQGuard · 适配 iOS 16）"),
                    footer: Text("采用 O_RDONLY | O_NOFOLLOW 物理只读扫描：无需连接电脑或开启环回 VPN，直接检测非 App Store 渠道的二次打包仿冒钱包、TCC 免弹窗隐私越权、注入动态库、后台剪贴板监听、跨容器越界软链与异常受监管状态。")
                ) {
                    if vm.auditSummary.findings.isEmpty {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("全部已安装应用、共享容器软链与监管配置均未发现异常特征")
                                .font(.system(size: 13))
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 4)
                    } else {
                        ForEach(vm.auditSummary.findings) { item in
                            let isHigh = item.severity == "high"
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Text(isHigh ? "高危" : "留意")
                                        .font(.system(size: 10.5, weight: .bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background((isHigh ? Color.red : Color.orange).opacity(0.16))
                                        .foregroundColor(isHigh ? .red : .orange)
                                        .cornerRadius(4)
                                    Text(item.category)
                                        .font(.system(size: 11.5, weight: .semibold))
                                        .foregroundColor(.secondary)
                                    Spacer()
                                }
                                Text(item.title)
                                    .font(.system(size: 14, weight: .semibold))
                                Text(item.target)
                                    .font(.system(size: 11.5, design: .monospaced))
                                    .foregroundColor(.secondary)
                                Text(item.detail)
                                    .font(.system(size: 12))
                                    .foregroundColor(.secondary)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }

                Section(
                    header: Text("Coruna / PLASMAGRID / GHOSTKNIFE 水坑与后门落盘指标"),
                    footer: Text("数据来源：Google Threat Intelligence (GTIG)、iVerify 与 Report URI 披露的在野 iOS WebKit 水坑与后门特征库。")
                ) {
                    ForEach(vm.iocItems) { item in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: item.found ? "xmark.octagon.fill" : "checkmark.circle.fill")
                                .foregroundColor(item.found ? .red : .green)
                                .padding(.top, 2)

                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.path)
                                    .font(.system(size: 12.5, design: .monospaced))
                                    .foregroundColor(item.found ? .red : .primary)
                                Text("\(item.family) · \(item.desc)")
                                    .font(.system(size: 11.5))
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 3)
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("安全体检")
        }
        .navigationViewStyle(.stack)
    }
}

// MARK: - Tab 5: System Tools (One-Tap Developer Mode & Diagnostics)

struct DiagnosticsTabView: View {
    @ObservedObject var vm: AppViewModel

    private var devModeStatusText: String {
        if vm.devMode.enabled {
            return "已开启"
        } else if vm.devMode.armed {
            return "已预开启（重启手机点确认即生效）"
        } else {
            return "未开启"
        }
    }

    private var devModeColor: Color {
        if vm.devMode.enabled { return .green }
        if vm.devMode.armed { return .blue }
        return .orange
    }

    var body: some View {
        NavigationView {
            List {
                Section(
                    header: Text("开发者模式管理（摆脱电脑端爱思助手）"),
                    footer: Text("原理说明：通过巨魔权限直连系统 AppleMobileFileIntegrity (com.apple.amfi.xpc) 与 AMFIShowOverridePath。注意：苹果 iOS 16 原生机制规定，在「全局锁定模式」开启状态下无法首次激活开发者模式；若点击开启时提示受锁定模式限制，可先临时关闭锁定模式 → 在本页一键开启开发者模式 → 再重新开启锁定模式。")
                ) {
                    HStack(spacing: 12) {
                        Image(systemName: vm.devMode.enabled ? "wrench.and.screwdriver.fill" : "hammer.circle.fill")
                            .font(.system(size: 26))
                            .foregroundColor(devModeColor)

                        VStack(alignment: .leading, spacing: 3) {
                            Text("当前状态：\(devModeStatusText)")
                                .font(.system(size: 15, weight: .semibold))
                            Text("系统设置入口：\(vm.devMode.menuVisible ? "已在「隐私与安全性」中显示" : "当前隐藏") · SEP可写：\(vm.devMode.writable ? "是" : "受锁定模式保护")")
                                .font(.system(size: 12))
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 4)

                    if !vm.devMode.enabled {
                        Button {
                            vm.armDeveloperModeNow()
                        } label: {
                            HStack {
                                Spacer()
                                Image(systemName: "bolt.shield.fill")
                                Text(vm.devMode.armed ? "重新发送预开启指令" : "一键开启开发者模式（免电脑）")
                                Spacer()
                            }
                            .font(.system(size: 14.5, weight: .semibold))
                            .padding(.vertical, 9)
                            .background(Color.accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                        }
                        .buttonStyle(.plain)
                    }

                    if vm.devMode.armed && !vm.devMode.enabled {
                        Button {
                            vm.showManualRebootConfirm = true
                        } label: {
                            HStack {
                                Spacer()
                                Image(systemName: "power")
                                Text("立即重启设备以弹出系统开启确认框")
                                Spacer()
                            }
                            .font(.system(size: 14, weight: .semibold))
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.14))
                            .foregroundColor(.blue)
                            .cornerRadius(8)
                        }
                        .buttonStyle(.plain)
                    }

                    Button {
                        vm.revealDeveloperModeMenuOnly()
                    } label: {
                        Label("仅在系统「设置 → 隐私与安全性」显示入口（免重启）", systemImage: "eye.fill")
                            .font(.system(size: 13.5, weight: .medium))
                    }

                    if vm.devMode.enabled {
                        Button(role: .destructive) {
                            vm.disableDeveloperModeNow()
                        } label: {
                            Label("关闭开发者模式（立即生效）", systemImage: "xmark.shield")
                                .font(.system(size: 13.5, weight: .medium))
                        }
                    }
                }

                Section(header: Text("黄金搭配使用建议（iOS 16.4.1）")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("1. 开启系统全局「锁定模式」，让所有陌生链接与广告 iframe 默认运行在无 JIT 沙盒中。")
                        Text("2. 遇到陌生链接不确定安全性时，先在「网址预检」标签页检测是否含水坑挂马或钓鱼特征。")
                        Text("3. 确认安全的常用网站若打不开，在「网站白名单」添加并点右上角「重启 Safari」即可满血访问；常用 App 内置网页异常则在「应用白名单」一键豁免。")
                        Text("4. 搭配本仓库 Loon「iOS WebKit 水坑与漏洞链防护」插件，在网络层零延迟拦截在野漏洞包。")
                    }
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                    .padding(.vertical, 4)
                }

                Section(header: Text("底层运行诊断")) {
                    Text(vm.diagnosticReportText())
                        .font(.system(size: 11.5, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(.vertical, 4)

                    Button {
                        UIPasteboard.general.string = vm.diagnosticReportText()
                        vm.showToast("📋 已复制完整诊断信息到剪贴板")
                    } label: {
                        Label("复制诊断报告", systemImage: "doc.on.doc")
                            .font(.system(size: 14, weight: .semibold))
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("系统工具")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        vm.refreshAll()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .alert("开发者模式已成功预开启！", isPresented: $vm.showDevModeRebootPrompt) {
                Button("立即重启手机", role: .destructive) {
                    vm.rebootDeviceNow()
                }
                Button("稍后手动重启", role: .cancel) {}
            } message: {
                Text("已为您同时开启系统设置菜单与开机激活标记。重启手机解锁后，系统会自动弹出「打开开发者模式？」原生确认框，点击「打开」并输入锁屏密码即可生效。")
            }
            .alert("确认立即重启设备？", isPresented: $vm.showManualRebootConfirm) {
                Button("立即重启", role: .destructive) {
                    vm.rebootDeviceNow()
                }
                Button("取消", role: .cancel) {}
            } message: {
                Text("重启解锁后请在系统弹窗点击「打开」以完成开发者模式启用。")
            }
        }
        .navigationViewStyle(.stack)
    }
}
