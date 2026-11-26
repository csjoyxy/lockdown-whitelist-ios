# 锁定白名单（LockdownBypass）· iOS 16 锁定模式网站与 App 主动豁免工具

![Platform](https://img.shields.io/badge/Platform-iOS%2016.0--16.7%20(TrollStore)-0A84FF)

专为 **iOS 16.0–16.7（主目标 iOS 16.4.1，巨魔 TrollStore 安装）** 打造的「锁定模式（Lockdown Mode）」精细化白名单管理工具。

让停留在 iOS 16.4.1 的设备可以**安心常开系统「锁定模式」防住绝大多数在野 WebKit 浏览器漏洞（禁用陌生网页 JIT、WebAssembly、WebGL、高危字体解析）**，同时彻底解决 iOS 16 原生锁定模式的两大体验痛点，对齐 iOS 18 的丝滑白名单体验！

---

## 🎯 解决哪两大 iOS 16 原生痛点？

1. **打破 Safari「打不开网站就加不了白名单」的死胡同**：
   - 在 iOS 16 中，Safari 的「已排除网站」列表没有添加按钮——必须在 Safari 成功打开目标网页后，点地址栏 `大小 → 网站设置` 才能关闭锁定模式；一旦目标网站因锁定模式直接报错/白屏卡死，就永远没法加进白名单。
   - **本工具方案**：**无需先在 Safari 打开网页**，直接输入域名或粘贴网址（支持一键同时豁免根域名与 `www.` / `m.` 子域），双通道调用 `SafariShared.framework` (`WBSLockdownModePreferenceManager`) 并持久化写入 `PerSitePreferences.db`，点一下右上角 **「重启 Safari 生效」** 即可满血打开该网站。
2. **补齐 iOS 18 才好用的「主动添加任意 App 白名单」**：
   - 在 iOS 16 系统设置中，无法提前自由勾选需要豁免锁定模式的 App。
   - **本工具方案**：直接列出手机全部已安装应用（支持按名称/`Bundle ID` 搜索与真实图标展示），一键调用 `WebKit` `_WKSystemPreferences` 并在目标应用容器写入 `Library/Preferences/com.apple.WebKit.cpmconfig_ignore`（还提供可选「深度豁免」同步写入容器级 `LDMGlobalEnabled=NO`），切换时自动重启目标 App 进程立即恢复满速内置网页与图标字体。
3. **附带离线零联网「在野漏洞包 IOC 体检」**：
   - 内置针对 **Coruna / CryptoWaters (PLASMAGRID)** 等覆盖 iOS 13–17.2.1 在野 WebKit 水坑工具包的本机文件痕迹离线扫描（零网络请求、1 秒出结果）。

---

## 🚀 安装与使用步骤

1. 前往本仓库 [**Releases 页面**](https://github.com/csjoyxy/lockdown-whitelist-ios/releases)（或最新 GitHub Actions 构建产物）下载 **`LockdownBypass.tipa`**。
2. 在手机上通过 **TrollStore（巨魔）** 安装 **「锁定白名单」**。
3. 在系统 `设置 → 隐私与安全性 → 锁定模式` 开启锁定模式后：
   - **网站打不开 / 缺字体图标**：打开「锁定白名单」→ **网站白名单** → 输入域名点 **「加白名单」** → 点右上角 **「重启 Safari 生效」**。
   - **某个 App 内置网页卡顿 / 异常**：打开「锁定白名单」→ **应用白名单** → 搜索该 App 并打开右侧开关即可单独关闭其锁定模式。

---

## 🏗 仓库结构

```text
src/
  ldmctl.m                     # 短时按需唤醒的 uid=0 助手（容器扫描、SQLite 原子写入与属主修正、Safari/App 重启、IOC 扫描）
  entitlements-app.plist       # 主程序巨魔权限（persona-mgmt + AppDataContainers + Safari + Metal IOKit）
  entitlements-helper.plist    # 助手权限（platform-application + no-sandbox）
  app/
    LockdownBridge.h/.m        # Objective-C 动态运行时桥接（SafariShared + _WKSystemPreferences + LSApplicationWorkspace）
    Models.swift               # 状态与列表数据模型
    AppViewModel.swift         # 域名解析扩展、双通道持久化调度与诊断报告生成
    Views.swift                # 四栏原生 SwiftUI 界面（网站白名单 / 应用白名单 / 安全体检 / 诊断说明）
    AppMain.swift              # 应用入口
    Info.plist                 # 应用包配置 (com.lili.lockdownwhitelist)
scripts/
  verify-lockdown.py           # 打包后 Mach-O ARM64 签名与嵌入权限门禁校验脚本
.github/workflows/
  build-tipa.yml               # GitHub Actions 自动编译打包、验包与 Release 发布流水线
```
