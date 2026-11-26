# 锁定白名单（LockdownBypass）& Loon 浏览器防投毒套件 · iOS 16 安全加固专仓

![Platform](https://img.shields.io/badge/Platform-iOS%2016.0--16.7%20(TrollStore%20%2B%20Loon)-0A84FF)

专为 **iOS 16.0–16.7（主目标 iOS 16.4.1，巨魔 TrollStore + Loon 环境）** 打造的「系统锁定模式白名单管理 + 网络层 WebKit 漏洞利用链拦截」一体化安全仓库。

让长期停留在 iOS 16.4.1 的设备可以**安心常开系统「锁定模式（Lockdown Mode）」防住绝大多数在野 WebKit 浏览器漏洞（禁用陌生网页 JIT、WebAssembly、WebGL、高危字体解析）**，配合 **Loon 零延迟水坑 IOC 防护**，同时彻底解决 iOS 16 原生锁定模式的两大日常使用痛点，对齐 iOS 18 的丝滑白名单体验！

---

## 🎯 一、巨魔工具：锁定白名单（LockdownBypass）

### 解决哪两大 iOS 16 原生痛点？

1. **打破 Safari「打不开网站就加不了白名单」的死循环**：
   - 在 iOS 16 中，Safari 的「已排除网站」列表没有添加入口——必须在 Safari 成功打开目标网页后，点地址栏 `大小 → 网站设置` 才能关闭锁定模式；一旦目标网站因锁定模式直接报错/白屏卡死，就永远没法加进白名单。
   - **本工具方案**：**无需先在 Safari 打开网页**，直接输入域名或粘贴网址（自动对齐 Safari `safari_userVisibleHostWithoutWWWSubdomain` 查询规则并支持一键展开根域名与 `www.` / `m.` 子域），双通道调用 `SafariShared.framework` (`WBSLockdownModePreferenceManager` + `WBSPerSitePreferencesSQLiteStore`) 并持久化写入 AppGroup `PerSitePreferences.db`，点一下右上角 **「重启 Safari 生效」** 即可满血打开该网站。
2. **补齐 iOS 18 才好用的「主动添加任意 App 白名单」**：
   - 在 iOS 16 系统设置中，未触发过特定弹窗的应用不会出现在 `设置 → 隐私与安全性 → 锁定模式 → 配置网页浏览` 列表中，无法提前自由勾选豁免。
   - **本工具方案**：直接列出全机全部已安装应用（支持按名称/`Bundle ID` 搜索与真实图标展示），一键调用 `WebKit` `_WKSystemPreferences` 并在目标应用容器创建 `System/Preferences/com.apple.WebKit.cpmconfig_ignore`（同时同步 `WebKitCaptivePortalModeAlertShown` 使系统原生设置列表也同步可见，并附可选「深度豁免」`LDMGlobalEnabled=NO`），切换时通知 WebKit 并自动重启目标 App 进程立即恢复满速内置网页与图标字体。
3. **附带离线零联网「在野漏洞包 IOC 体检」**：
   - 内置针对 **Coruna / CryptoWaters (PLASMAGRID)** 等覆盖 iOS 13–17.2.1 在野 WebKit 水坑工具包的本机文件痕迹离线扫描（零网络请求、1 秒出结果）。

### 安装与使用步骤

1. 前往本仓库 [**Releases 页面**](https://github.com/csjoyxy/lockdown-whitelist-ios/releases) 下载最新 **`LockdownBypass.tipa`**。
2. 在手机上通过 **TrollStore（巨魔）** 安装 **「锁定白名单」**。
3. 在系统 `设置 → 隐私与安全性 → 锁定模式` 开启锁定模式后：
   - **网站打不开 / 缺字体图标**：打开「锁定白名单」→ **网站白名单** → 输入域名点 **「加白名单」** → 点右上角 **「重启 Safari 生效」**。
   - **某个 App 内置网页卡顿 / 异常**：打开「锁定白名单」→ **应用白名单** → 搜索该 App 并打开右侧开关即可单独关闭其锁定模式。

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
- **特点**：**不修改主配置全局 DNS、0 MitM、0 后台常驻耗电**；精准 `REJECT` 阻断 Google Threat Intelligence (GTIG)、iVerify、Kaspersky 披露的 **Coruna / CryptoWaters**（覆盖 iOS 13–17.2.1 全链 WebKit RCE 与 20+ 款钱包注入模块）、**DarkSword**、**Operation Triangulation（三角行动）** 水坑域名、C2 IP、明文植入载荷路径、15 位 `.xyz` 明文 HTTP DGA 与 `powerd` 异常外联 UA。
- **一键自检**：安装后可在 Loon 插件详情页点击 **「立即自检防护与安全DoH延迟」**，使用 RFC 2606 `.invalid` 本地安全探针 1 秒验证 `REJECT` 防线是否生效，并实测当前网络直连安全 DoH 的毫秒级延迟。

### 2. 可选插件：iOS 恶意域名拦截安全 DoH（按网络流畅度自由开关）
- **Loon 插件一键订阅地址**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/lockdown-whitelist-ios/main/ios_security_doh.lpx
  ```
- **特点**：开启后向 Loon 追加 **Cloudflare Security (`1.1.1.2`)** 与 **Quad9 (`9.9.9.9`)** 实时恶意软件/钓鱼域名拦截加密 DoH（内置静态 Host 引导 IP 防 DNS 抢答）；若当前国内网络直连海外 DoH 偶有变慢，在 Loon 插件列表**随手关闭本插件开关即可零残留恢复原解析速度**，完全不影响上方核心 IOC 防护插件。

---

## 🏗 仓库结构

```text
src/
  ldmctl.m                     # 短时按需唤醒的 uid=0 助手（容器扫描、SQLite 原子写入与属主修正、Safari/App 重启、IOC 扫描）
  entitlements-app.plist       # 主程序巨魔权限（persona-mgmt + AppDataContainers + Safari AppGroup + Metal IOKit）
  entitlements-helper.plist    # 助手权限（platform-application + no-sandbox + Safari AppGroup）
  app/
    LockdownBridge.h/.m        # Objective-C 动态运行时桥接（SafariShared + _WKSystemPreferences + LockdownMode + LSApplicationWorkspace）
    Models.swift               # 状态与列表数据模型
    AppViewModel.swift         # 域名解析扩展、双通道持久化调度与诊断报告生成
    Views.swift                # 四栏原生 SwiftUI 界面（网站白名单 / 应用白名单 / 安全体检 / 诊断说明）
    AppMain.swift              # 应用入口
    Info.plist                 # 应用包配置 (com.lili.lockdownwhitelist)
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
