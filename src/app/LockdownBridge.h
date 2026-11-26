/*
 * LockdownBridge.h — Objective-C runtime bridge for iOS 16 Lockdown Mode
 * Safari Per-Site Whitelist (SafariShared + PerSitePreferences.db),
 * App Container Whitelist (_WKSystemPreferences + cpmconfig_ignore),
 * App Enumeration (LSApplicationWorkspace), and POSIX persona root helper (ldmctl).
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define LB_VERSION "0.2.0"
#ifndef LB_COMMIT
#define LB_COMMIT "dev"
#endif

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *LBBridgeVersion(void);
FOUNDATION_EXPORT NSString *LBBridgeGitCommit(void);

FOUNDATION_EXPORT NSString *LBBridgeRunCtl(NSArray<NSString *> *args, int * _Nullable exitCodeOut);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeSystemStatus(void);

FOUNDATION_EXPORT NSString *LBBridgeHighLevelDomain(NSString *host);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeSafariListExcludedSites(void);
FOUNDATION_EXPORT NSString *LBBridgeSafariSetDomainExcluded(NSString *domain, BOOL excluded);
FOUNDATION_EXPORT NSInteger LBBridgeRestartSafari(void);

FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *LBBridgeListInstalledApps(void);
FOUNDATION_EXPORT NSData * _Nullable LBBridgeAppIconPNG(NSString *bundleId);
FOUNDATION_EXPORT NSString *LBBridgeSetAppExcluded(NSString *bundleId,
                                                   NSString *containerPath,
                                                   BOOL excluded,
                                                   BOOL deepOverride);
FOUNDATION_EXPORT NSInteger LBBridgeRestartApp(NSString *appBundleFolderName);

FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeRunIOCScan(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeRunSecurityAudit(void);

FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeDeveloperModeStatus(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeDeveloperModeRevealMenu(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeDeveloperModeArm(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *LBBridgeDeveloperModeDisable(void);
FOUNDATION_EXPORT void LBBridgeRebootDevice(void);

NS_ASSUME_NONNULL_END
