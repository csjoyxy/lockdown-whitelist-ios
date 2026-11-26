import SwiftUI
import UIKit

struct RootContentView: View {
    @StateObject private var vm = AppViewModel()

    var body: some View {
        ZStack(alignment: .bottom) {
            TabView {
                SafariSitesTabView(vm: vm)
                    .tabItem {
                        Label("网站白名单", systemImage: "safari.fill")
                    }

                AppsWhitelistTabView(vm: vm)
                    .tabItem {
                        Label("应用白名单", systemImage: "square.grid.2x2.fill")
                    }

                IOCScannerTabView(vm: vm)
                    .tabItem {
                        Label("安全体检", systemImage: "checkmark.shield.fill")
                    }

                DiagnosticsTabView(vm: vm)
                    .tabItem {
                        Label("诊断说明", systemImage: "wrench.and.screwdriver.fill")
                    }
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
                    footer: Text("解决 iOS 16 开启锁定模式后「网站打不开 → 无法点地址栏菜单关锁定模式」的死循环。添加后点右上角「重启 Safari」即可立即满血访问。")
                ) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            TextField("输入域名或粘贴完整网址 (如 taobao.com)", text: $vm.domainInput)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .disableAutocorrection(true)
                                .textFieldStyle(.roundedBorder)

                            Button {
                                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                vm.addDomainsFromInput()
                            } label: {
                                Text("加白名单")
                                    .font(.system(size: 13.5, weight: .semibold))
                                    .padding(.horizontal, 12)
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

// MARK: - Tab 3: Offline Exploit-Kit IOC Scanner

struct IOCScannerTabView: View {
    @ObservedObject var vm: AppViewModel

    var body: some View {
        NavigationView {
            List {
                Section {
                    HStack(spacing: 14) {
                        Image(systemName: vm.iocClean ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .font(.system(size: 32))
                            .foregroundColor(vm.iocClean ? .green : .red)

                        VStack(alignment: .leading, spacing: 4) {
                            Text(vm.iocClean ? "本机未发现已知水坑植入痕迹" : "检测到可疑落地文件痕迹！")
                                .font(.system(size: 16, weight: .bold))
                            if let dt = vm.iocLastChecked {
                                Text("上次检测：\(dt.formatted(date: .omitted, time: .standard)) · 离线零联网扫描")
                                    .font(.system(size: 12))
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
                            Label("立即重新扫描本机 IOC 痕迹", systemImage: "magnifyingglass.circle.fill")
                                .font(.system(size: 14.5, weight: .semibold))
                            Spacer()
                        }
                        .padding(.vertical, 4)
                    }
                }

                Section(
                    header: Text("Coruna / PLASMAGRID (iOS 13–17.2.1) 核心落盘指标"),
                    footer: Text("数据来源：Google Threat Intelligence (GTIG) 与 iVerify 披露的在野 iOS WebKit 水坑攻击链特征库。即使部分内存型载荷重启会清除，上述持久化/锁文件也可辅助排查历史感染。")
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

// MARK: - Tab 4: Diagnostics & Guide

struct DiagnosticsTabView: View {
    @ObservedObject var vm: AppViewModel

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("黄金搭配使用建议（iOS 16.4.1）")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("1. 开启系统全局「锁定模式」（设置 → 隐私与安全性 → 锁定模式），让所有陌生链接、网页广告 iframe 默认运行在无 JIT 安全沙盒中。")
                        Text("2. 遇到打不开或缺少图标字体的信任网站，直接在本工具「网站白名单」输入域名添加，再点右上角「重启 Safari」即可满血打开。")
                        Text("3. 遇到内置网页卡顿或白屏的常用 App（如微信、淘宝等），在「应用白名单」打开开关即可单独豁免该应用，无需关闭全局锁定模式。")
                        Text("4. 搭配 Loon 的「iOS WebKit 水坑与漏洞链防护」插件，在网络层提前阻断已知恶意域名与植入载荷。")
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
            .navigationTitle("诊断说明")
        }
        .navigationViewStyle(.stack)
    }
}
