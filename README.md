# 锁定白名单（LockdownBypass）& Loon 浏览器防投毒套件 · iOS 16 安全加固专仓

![Platform](https://img.shields.io/badge/Platform-iOS%2016.0--16.7%20(TrollStore%20%2B%20Loon)-0A84FF)

专为 **iOS 16.0–16.7（主目标 iOS 16.4.1，巨魔 TrollStore + Loon 环境）** 打造的「系统锁定模式白名单管理 + 零渲染网址安全沙盒 + 侧载木马审计 + 免电脑一键开发者模式 + 网络层漏洞链拦截」一体化安全仓库。

让长期停留在 iOS 16.4.1 的设备可以**安心常开系统「锁定模式（Lockdown Mode）」防住绝大多数在野 WebKit 浏览器漏洞**，配合 **Loon 零延迟水坑 IOC 防护**，同时彻底解决 iOS 16 原生锁定模式与日常玩机的核心痛点！

---

## 🎯 一、巨魔工具：锁定白名单（LockdownBypass v0.2.0 · 五栏全能版）

1. **网站白名单（打破 Safari「打不开网站就加不了白名单」的死循环）**：
   - **无需先在 Safari 打开网页**，直接输入域名或粘贴网址（自动对齐 Safari `safari_userVisibleHostWithoutWWWSubdomain` 查询规则并支持一键展开根域名与 `www.` / `m.` 子域），双通道调用 `SafariShared.framework` (`WBSLockdownModePreferenceManager` + `WBSPerSitePreferencesSQLiteStore`) 并持久化写入 AppGroup `PerSitePreferences.db`，点右上角 **「重启 Safari 生效」** 即可满血打开。
2. **应用白名单（补齐 iOS 18 主动勾选任意 App 豁免体验）**：
   - 列出全机全部已安装应用（含真实图标与搜索筛选），一键调用 `WebKit` `_WKSystemPreferences` 并在目标应用容器写入 `System/Preferences/com.apple.WebKit.cpmconfig_ignore`（同步标记 `WebKitCaptivePortalModeAlertShown` 使系统设置原生列表同步可见，附可选「深度豁免」`LDMGlobalEnabled=NO`），切换时自动重启目标 App 进程立即生效。
3. **网址预检（零 WebKit 渲染安全沙盒 · 先检测再决定是否访问/加白）**：
   - **绝不调用易受攻击的 iOS 16.4.1 `WebKit` / `JavaScriptCore` 渲染引擎**，通过隔离 `ephemeral` 网络流（禁 Cookie、限前 `256 KB` 文本、追踪重定向链并拦截内网 SSRF）并发核验：
     - 本机 Coruna / DarkSword / 三角行动在野水坑 IOC 库；
     - **Cloudflare Security (`1.1.1.2`) + Quad9 (`9.9.9.9`)** 双路加密 DoH 实时恶意/钓鱼域名黑名单；
     - 网页源码静态启发式审计（隐藏跨域挂马 `<iframe>`、`addrof`/`fakeobj`/`Float64Array+Wasm` 浏览器漏洞利用原语、`eval(atob)` 混淆脚本、`.mobileconfig` 恶意描述文件强推、知名钱包/平台仿冒钓鱼域名与助记词表单）。
   - 检测通过后支持一键加入 Safari 白名单。
4. **安全体检（水坑落盘 IOC + 借鉴 `WQGuard` 的巨魔/侧载只读深度审计）**：
   - **在野水坑落盘扫描**：离线检测 Coruna / CryptoWaters (`PLASMAGRID`) 已知落盘文件痕迹。
   - **全机侧载/巨魔应用与容器物理只读审计（免电脑 / 免环回 VPN）**：采用 `O_RDONLY | O_NOFOLLOW` 纯只读解析全机非 App Store 应用的 `Mach-O` 头部与 `LC_CODE_SIGNATURE` 嵌入权限，自动识别二次打包仿冒加密钱包 (`Web3 Drainer`)、`com.apple.private.tcc.allow` 免弹窗隐私越权、重打包注入动态库 (`Dylibs`/`Substrate`/`ElleKit`)、后台常驻+剪贴板读取元组、共享容器越界符号链接及异常「受监管模式 (`IsSupervised`)」篡改。
5. **系统工具（免电脑 / 免爱思助手一键开启「开发者模式」）**：
   - 通过巨魔特权直连 `AppleMobileFileIntegrity` (`com.apple.amfi.xpc` + `AMFIShowOverridePath`)，支持**免插电脑一键显示系统「设置 → 隐私与安全性 → 开发者模式」隐藏入口**、**一键预开启（Arm）开发者模式**及可选一键安全重启（重启解锁后直接弹出苹果原生开启确认框）。

---

## 🛡️ 二、Loon 网络层 WebKit 防投毒插件套件

提供**「核心 IOC 零延迟拦截」+「可选恶意域名安全 DoH」**双插件拆分方案，方便按国内网络环境自由组合：

### 1. 核心插件：iOS WebKit 水坑与漏洞链防护（推荐常开 · 国内零延迟）
- **Loon 插件一键订阅地址**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/lockdown-whitelist-ios/main/ios_webkit_shield.lpx
  ```
- **独立规则集地址（供 Loon `RULE-SET` / Surge / Shadowrocket / 路由器复用）**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/lockdown-whitelist-ios/main/rules/ios_webkit_ioc.list
  ```
- **特点**：**不修改主配置全局 DNS、0 MitM、0 后台常驻耗电**；精准 `REJECT` 阻断 Coruna / CryptoWaters、DarkSword、Operation Triangulation 水坑域名、C2 IP、明文植入载荷路径、15 位 `.xyz` 明文 HTTP DGA 与 `powerd` 异常外联 UA；内置 RFC 2606 `.invalid` 探针一键自检与安全 DoH 测速。

### 2. 可选插件：iOS 恶意域名拦截安全 DoH（按网络流畅度自由开关）
- **Loon 插件一键订阅地址**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/lockdown-whitelist-ios/main/ios_security_doh.lpx
  ```
- **特点**：开启后向 Loon 追加 **Cloudflare Security (`1.1.1.2`)** 与 **Quad9 (`9.9.9.9`)** 实时恶意软件/钓鱼域名拦截加密 DoH（内置静态 Host 引导 IP 防 DNS 抢答）；若当前国内网络直连海外 DoH 偶有变慢，随手关闭本插件开关即可零残留恢复原解析速度。

---

## 🏗 仓库结构

```text
src/
  ldmctl.m                     # 短时按需唤醒的 uid=0 助手（容器扫描、SQLite 原子写入、AMFI 开发者模式 XPC、Mach-O/容器只读审计、IOC 扫描）
  entitlements-app.plist       # 主程序巨魔权限（persona-mgmt + AppDataContainers + Safari AppGroup + Metal IOKit）
  entitlements-helper.plist    # 助手权限（platform-application + no-sandbox + Safari AppGroup + amfi.developer-mode-control + shutdown）
  app/
    LockdownBridge.h/.m        # Objective-C 动态运行时桥接（SafariShared + _WKSystemPreferences + LockdownMode + AMFI/Audit 桥接）
    Models.swift               # 状态、审计与网址预检报告模型
    URLSafetyInspector.swift   # 零 WebKit 网址安全预检引擎（双路安全 DoH + 限流跳转追踪 + 静态挂马/钓鱼启发式扫描）
    AppViewModel.swift         # 域名解析扩展、双通道持久化调度、开发者模式与安全检测状态管理
    Views.swift                # 五栏原生 SwiftUI 界面（网站白名单 / 应用白名单 / 网址预检 / 安全体检 / 系统工具）
    AppMain.swift              # 应用入口
    Info.plist                 # 应用包配置 (com.lili.lockdownwhitelist v0.2.0)
ios_webkit_shield.lpx          # Loon 核心 WebKit 水坑与漏洞链 IOC 零延迟防护插件
ios_security_doh.lpx           # Loon 可选 Cloudflare 1.1.1.2 / Quad9 9.9.9.9 安全 DoH 插件
rules/
  ios_webkit_ioc.list          # 独立 IOC 规则集（兼容 Loon RULE-SET / Surge / Shadowrocket）
scripts/
  verify-lockdown.py           # 打包后 Mach-O ARM64 签名与嵌入权限门禁校验脚本
  webkit_shield_check.js       # Loon 插件内置手动一键自检与安全 DoH 测速脚本
tests/
  test_webkit_shield.js        # Loon 插件 #!source SHA-256、IOC 拦截与零误杀自动化测试
.github/workflows/
  build-tipa.yml               # GitHub Actions 自动编译打包、双门禁测试与 Release 发布流水线
```

## 🧪 本地校验

```bash
node tests/test_webkit_shield.js
python3 -m py_compile scripts/verify-lockdown.py
```
