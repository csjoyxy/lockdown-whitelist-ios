/*
 * LockdownBridge.m — Safe Objective-C runtime introspection + ldmctl root helper bridge.
 */

#import "LockdownBridge.h"
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <spawn.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t *, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *, uid_t);
extern char **environ;

NSString *LBBridgeVersion(void) {
    return @LB_VERSION;
}

NSString *LBBridgeGitCommit(void) {
    return @LB_COMMIT;
}

static uint64_t LBMonotonicMillis(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void LBDrainPipeFD(int fd, NSMutableData *outData) {
    char buf[1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            [outData appendBytes:buf length:(NSUInteger)n];
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

NSString *LBBridgeRunCtl(NSArray<NSString *> *args, int *exitCodeOut) {
    if (exitCodeOut) *exitCodeOut = -1;
    NSString *binPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"ldmctl"];
    const char *cbin = binPath.fileSystemRepresentation;
    if (!cbin || access(cbin, X_OK) != 0) {
        return @"{\"ok\":false,\"error\":\"helper_missing\"}";
    }

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
        return @"{\"ok\":false,\"error\":\"pipe_failed\"}";
    }

    NSUInteger argc = args.count + 1;
    char **argv = (char **)calloc(argc + 1, sizeof(char *));
    if (!argv) {
        close(pipefd[0]);
        close(pipefd[1]);
        return @"{\"ok\":false,\"error\":\"nomem\"}";
    }
    argv[0] = strdup(cbin);
    for (NSUInteger i = 0; i < args.count; i++) {
        argv[i + 1] = strdup([args[i] UTF8String] ?: "");
    }
    argv[argc] = NULL;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (pipefd[0] > STDERR_FILENO) {
        posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    }
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO);
    if (pipefd[1] > STDERR_FILENO) {
        posix_spawn_file_actions_addclose(&actions, pipefd[1]);
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);

    pid_t child = 0;
    int rc = posix_spawn(&child, cbin, &actions, &attr, argv, environ);

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    close(pipefd[1]);

    NSMutableData *outData = [NSMutableData data];
    if (rc == 0 && child > 0) {
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        uint64_t deadline = LBMonotonicMillis() + 3500ULL;
        int status = 0;
        BOOL done = NO;

        while (LBMonotonicMillis() < deadline) {
            struct pollfd pfd;
            pfd.fd = pipefd[0];
            pfd.events = POLLIN | POLLHUP;
            pfd.revents = 0;
            (void)poll(&pfd, 1, 35);

            LBDrainPipeFD(pipefd[0], outData);

            pid_t w;
            do {
                w = waitpid(child, &status, WNOHANG);
            } while (w < 0 && errno == EINTR);

            if (w == child) {
                done = YES;
                if (WIFEXITED(status) && exitCodeOut) {
                    *exitCodeOut = WEXITSTATUS(status);
                }
                break;
            } else if (w < 0) {
                done = YES;
                break;
            }
        }
        LBDrainPipeFD(pipefd[0], outData);

        if (!done) {
            kill(child, SIGKILL);
            int status2 = 0;
            while (waitpid(child, &status2, 0) < 0 && errno == EINTR) {}
        }
    }
    close(pipefd[0]);

    if (rc != 0) {
        return [NSString stringWithFormat:@"{\"ok\":false,\"error\":\"spawn_%d\"}", rc];
    }
    NSString *text = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding];
    return text ?: @"";
}

static NSDictionary *LBParseJSONDict(NSString *raw) {
    if (raw.length == 0) return @{};
    NSData *d = [raw dataUsingEncoding:NSUTF8StringEncoding];
    if (!d) return @{};
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
}

// MARK: - Private Frameworks Dynamic Loading & Safe Invocation

static void LBEnsurePrivateFrameworksLoaded(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
        dlopen("/System/Library/Frameworks/WebKit.framework/WebKit", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/SafariCore.framework/SafariCore", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/SafariShared.framework/SafariShared", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/SafariSharedUI.framework/SafariSharedUI", RTLD_NOW);
    });
}

static id _Nullable LBSafeInvoke0(id target, NSString *selName) {
    if (!target || selName.length == 0) return nil;
    SEL sel = NSSelectorFromString(selName);
    if (![target respondsToSelector:sel]) return nil;
    @try {
        NSMethodSignature *sig = [target methodSignatureForSelector:sel];
        if (!sig || sig.numberOfArguments != 2) return nil;
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        [inv setSelector:sel];
        [inv setTarget:target];
        [inv invoke];
        const char rt = sig.methodReturnType[0];
        if (rt == '@') {
            __unsafe_unretained id rawObj = nil;
            [inv getReturnValue:&rawObj];
            return rawObj;
        } else if (rt == 'B' || rt == 'c') {
            BOOL b = NO;
            [inv getReturnValue:&b];
            return @(b);
        } else if (rt == 'q' || rt == 'l') {
            long long v = 0;
            [inv getReturnValue:&v];
            return @(v);
        } else if (rt == 'i' || rt == 's') {
            int v = 0;
            [inv getReturnValue:&v];
            return @(v);
        }
    } @catch (__unused NSException *ex) {}
    return nil;
}

static id _Nullable LBSafeInvoke1Obj(id target, NSString *selName, id arg1) {
    if (!target || selName.length == 0) return nil;
    SEL sel = NSSelectorFromString(selName);
    if (![target respondsToSelector:sel]) return nil;
    @try {
        NSMethodSignature *sig = [target methodSignatureForSelector:sel];
        if (!sig || sig.numberOfArguments != 3) return nil;
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        [inv setSelector:sel];
        [inv setTarget:target];
        [inv setArgument:&arg1 atIndex:2];
        [inv invoke];
        const char rt = sig.methodReturnType[0];
        if (rt == '@') {
            __unsafe_unretained id rawObj = nil;
            [inv getReturnValue:&rawObj];
            return rawObj;
        } else if (rt == 'B' || rt == 'c') {
            BOOL b = NO;
            [inv getReturnValue:&b];
            return @(b);
        } else if (rt == 'q' || rt == 'l') {
            long long v = 0;
            [inv getReturnValue:&v];
            return @(v);
        } else if (rt == 'i' || rt == 's') {
            int v = 0;
            [inv getReturnValue:&v];
            return @(v);
        }
    } @catch (__unused NSException *ex) {}
    return nil;
}

// MARK: - _WKSystemPreferences Introspection

static NSArray<NSString *> *LBDiscoverWKSystemPrefsMethods(void) {
    LBEnsurePrivateFrameworksLoaded();
    Class cls = NSClassFromString(@"_WKSystemPreferences");
    if (!cls) return @[];
    NSMutableArray<NSString *> *list = [NSMutableArray array];
    unsigned int count = 0;
    Method *methods = class_copyMethodList(object_getClass(cls), &count);
    if (methods) {
        for (unsigned int i = 0; i < count; i++) {
            SEL s = method_getName(methods[i]);
            if (s) [list addObject:NSStringFromSelector(s)];
        }
        free(methods);
    }
    return list;
}

static BOOL LBInvokeWKSetIgnoredForContainer(NSString *containerPath, BOOL ignore) {
    LBEnsurePrivateFrameworksLoaded();
    Class cls = NSClassFromString(@"_WKSystemPreferences");
    if (!cls || containerPath.length == 0) return NO;

    unsigned int count = 0;
    Method *methods = class_copyMethodList(object_getClass(cls), &count);
    if (!methods) return NO;

    BOOL invoked = NO;
    for (unsigned int i = 0; i < count; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel);
        if (([name rangeOfString:@"setCaptivePortalModeIgnored" options:NSCaseInsensitiveSearch].location != NSNotFound ||
             [name rangeOfString:@"setLockdownModeIgnored" options:NSCaseInsensitiveSearch].location != NSNotFound) &&
            method_getNumberOfArguments(methods[i]) == 4) {
            @try {
                NSMethodSignature *sig = [cls methodSignatureForSelector:sel];
                if (sig && sig.numberOfArguments == 4) {
                    const char *t2 = [sig getArgumentTypeAtIndex:2];
                    const char *t3 = [sig getArgumentTypeAtIndex:3];
                    const char a2 = t2 ? t2[0] : '@';
                    const char a3 = t3 ? t3[0] : '@';
                    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                    [inv setSelector:sel];
                    [inv setTarget:cls];
                    if (a2 == '@' && (a3 == 'B' || a3 == 'c')) {
                        NSString *cp = containerPath;
                        BOOL ig = ignore;
                        [inv setArgument:&cp atIndex:2];
                        [inv setArgument:&ig atIndex:3];
                        [inv invoke];
                        invoked = YES;
                        break;
                    } else if ((a2 == 'B' || a2 == 'c') && a3 == '@') {
                        BOOL ig = ignore;
                        NSString *cp = containerPath;
                        [inv setArgument:&ig atIndex:2];
                        [inv setArgument:&cp atIndex:3];
                        [inv invoke];
                        invoked = YES;
                        break;
                    }
                }
            } @catch (__unused NSException *ex) {}
        }
    }
    free(methods);
    return invoked;
}

static NSNumber * _Nullable LBQueryWKIsIgnoredForContainer(NSString *containerPath) {
    LBEnsurePrivateFrameworksLoaded();
    Class cls = NSClassFromString(@"_WKSystemPreferences");
    if (!cls || containerPath.length == 0) return nil;
    for (NSString *cand in @[@"isCaptivePortalModeIgnored:",
                             @"_isCaptivePortalModeIgnoredForContainer:",
                             @"isCaptivePortalModeIgnoredForContainer:",
                             @"isLockdownModeIgnored:"]) {
        id res = LBSafeInvoke1Obj(cls, cand, containerPath);
        if ([res isKindOfClass:[NSNumber class]]) return (NSNumber *)res;
    }
    return nil;
}

// MARK: - SafariShared WBSLockdownModePreferenceManager Introspection

static NSDictionary<NSString *, id> *LBDiscoverSafariPreferenceSpec(id _Nullable * _Nullable outMgr,
                                                                    id _Nullable * _Nullable outPref) {
    LBEnsurePrivateFrameworksLoaded();
    NSString *resolvedKey = @"PerSitePreferencesLockdownMode";
    int offVal = 0;
    int onVal = 1;
    NSString *mgrClassName = @"";

    Class storeCls = NSClassFromString(@"WBSPerSitePreferencesSQLiteStore");
    Class mgrCls = NSClassFromString(@"WBSLockdownModePreferenceManager");
    if (!mgrCls) mgrCls = NSClassFromString(@"WBSCaptivePortalModePreferenceManager");

    if (!mgrCls) {
        Class baseCls = NSClassFromString(@"WBSPerSitePreferenceManager");
        int numClasses = objc_getClassList(NULL, 0);
        if (numClasses > 0 && baseCls) {
            Class *classes = (Class *)malloc(sizeof(Class) * (size_t)numClasses);
            if (classes) {
                int got = objc_getClassList(classes, numClasses);
                for (int i = 0; i < got; i++) {
                    const char *cname = class_getName(classes[i]);
                    if (!cname || strncmp(cname, "WBS", 3) != 0) continue;
                    if (strstr(cname, "Lockdown") != NULL || strstr(cname, "CaptivePortal") != NULL) {
                        Class sup = class_getSuperclass(classes[i]);
                        while (sup) {
                            if (sup == baseCls) {
                                mgrCls = classes[i];
                                break;
                            }
                            sup = class_getSuperclass(sup);
                        }
                        if (mgrCls) break;
                    }
                }
                free(classes);
            }
        }
    }

    id mgr = nil;
    id pref = nil;
    if (mgrCls) {
        mgrClassName = NSStringFromClass(mgrCls) ?: @"";
        id store = nil;
        if (storeCls) {
            store = LBSafeInvoke0(storeCls, @"sharedStore") ?: LBSafeInvoke0(storeCls, @"defaultStore");
        }
        @try {
            SEL initStoreSel = NSSelectorFromString(@"initWithPerSitePreferencesStore:");
            if (store && [mgrCls instancesRespondToSelector:initStoreSel]) {
                mgr = ((id (*)(id, SEL, id))objc_msgSend)([mgrCls alloc], initStoreSel, store);
            } else {
                mgr = [[mgrCls alloc] init];
            }
        } @catch (__unused NSException *ex) {
            mgr = nil;
        }

        if (mgr) {
            pref = LBSafeInvoke0(mgr, @"lockdownModePreference")
                ?: LBSafeInvoke0(mgr, @"captivePortalPreference");
            if (!pref) {
                id prefsArr = LBSafeInvoke0(mgr, @"preferences");
                if ([prefsArr isKindOfClass:[NSArray class]] && [(NSArray *)prefsArr count] > 0) {
                    pref = [(NSArray *)prefsArr firstObject];
                }
            }
            if (pref) {
                id pName = LBSafeInvoke1Obj(mgr, @"preferenceNameForPreference:", pref)
                        ?: LBSafeInvoke0(pref, @"identifier");
                if ([pName isKindOfClass:[NSString class]] && [(NSString *)pName length] > 0) {
                    resolvedKey = (NSString *)pName;
                }
                id offObj = LBSafeInvoke1Obj(mgr, @"offValueForPreference:", pref);
                if ([offObj isKindOfClass:[NSNumber class]]) {
                    offVal = [(NSNumber *)offObj intValue];
                }
                id onObj = LBSafeInvoke1Obj(mgr, @"onValueForPreference:", pref);
                if ([onObj isKindOfClass:[NSNumber class]]) {
                    onVal = [(NSNumber *)onObj intValue];
                }
            }
        }
    }

    // Cross-check with existing SQLite keys if any exist on disk
    int ec = -1;
    NSDictionary *dbInfo = LBParseJSONDict(LBBridgeRunCtl(@[@"--safari-list", resolvedKey], &ec));
    NSArray *dbKeys = dbInfo[@"detectedLockdownKeys"];
    if ([mgrClassName length] == 0 && [dbKeys isKindOfClass:[NSArray class]] && dbKeys.count > 0) {
        NSString *firstDbKey = dbKeys.firstObject;
        if ([firstDbKey isKindOfClass:[NSString class]] && firstDbKey.length > 0) {
            resolvedKey = firstDbKey;
        }
    }

    if (outMgr) *outMgr = mgr;
    if (outPref) *outPref = pref;
    return @{
        @"managerClass": mgrClassName,
        @"preferenceKey": resolvedKey,
        @"offVal": @(offVal),
        @"onVal": @(onVal)
    };
}

NSString *LBBridgeHighLevelDomain(NSString *host) {
    LBEnsurePrivateFrameworksLoaded();
    NSString *clean = [[host stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if ([clean hasSuffix:@"."]) {
        clean = [clean substringToIndex:clean.length - 1];
    }
    if (clean.length == 0) return @"";

    id safariHLD = LBSafeInvoke0(clean, @"safari_highLevelDomainFromHost");
    if ([safariHLD isKindOfClass:[NSString class]] && [(NSString *)safariHLD length] > 0) {
        return [(NSString *)safariHLD lowercaseString];
    }

    NSArray<NSString *> *parts = [clean componentsSeparatedByString:@"."];
    if (parts.count <= 2) return clean;
    NSSet<NSString *> *twoLevelSuffixes = [NSSet setWithArray:@[
        @"com.cn", @"net.cn", @"org.cn", @"gov.cn", @"edu.cn", @"ac.cn",
        @"com.hk", @"com.tw", @"co.jp", @"co.uk", @"co.kr", @"com.sg", @"com.au"
    ]];
    NSString *lastTwo = [NSString stringWithFormat:@"%@.%@", parts[parts.count - 2], parts[parts.count - 1]];
    if ([twoLevelSuffixes containsObject:lastTwo] && parts.count >= 3) {
        return [NSString stringWithFormat:@"%@.%@", parts[parts.count - 3], lastTwo];
    }
    return lastTwo;
}

NSDictionary<NSString *, id> *LBBridgeSystemStatus(void) {
    LBEnsurePrivateFrameworksLoaded();
    BOOL ldmDefaults = [[NSUserDefaults standardUserDefaults] boolForKey:@"LDMGlobalEnabled"];

    BOOL wkGlobal = ldmDefaults;
    Class wkSys = NSClassFromString(@"_WKSystemPreferences");
    if (wkSys) {
        id r1 = LBSafeInvoke0(wkSys, @"isCaptivePortalModeEnabled")
             ?: LBSafeInvoke0(wkSys, @"_isCaptivePortalModeEnabledGlobally");
        if ([r1 isKindOfClass:[NSNumber class]]) {
            wkGlobal = [(NSNumber *)r1 boolValue];
        }
    }

    int ec = -1;
    NSString *probe = [LBBridgeRunCtl(@[@"--probe"], &ec) stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSDictionary *safariSpec = LBDiscoverSafariPreferenceSpec(NULL, NULL);

    return @{
        @"lockdownEnabled": @(ldmDefaults || wkGlobal),
        @"ldmGlobalDefaults": @(ldmDefaults),
        @"wkCaptivePortalGlobal": @(wkGlobal),
        @"ctlProbe": probe ?: @"",
        @"ctlExitCode": @(ec),
        @"wkSystemPrefsMethods": LBDiscoverWKSystemPrefsMethods(),
        @"safariManagerClass": safariSpec[@"managerClass"] ?: @"",
        @"safariPreferenceKey": safariSpec[@"preferenceKey"] ?: @"PerSitePreferencesLockdownMode",
        @"safariOffValue": safariSpec[@"offVal"] ?: @0,
        @"safariOnValue": safariSpec[@"onVal"] ?: @1,
        @"osVersion": [[UIDevice currentDevice] systemVersion] ?: @""
    };
}

NSDictionary<NSString *, id> *LBBridgeSafariListExcludedSites(void) {
    id mgr = nil;
    id pref = nil;
    NSDictionary *spec = LBDiscoverSafariPreferenceSpec(&mgr, &pref);
    NSString *prefKey = spec[@"preferenceKey"] ?: @"PerSitePreferencesLockdownMode";
    int offVal = [spec[@"offVal"] intValue];

    int ec = -1;
    NSDictionary *ctlDict = LBParseJSONDict(LBBridgeRunCtl(@[@"--safari-list", prefKey], &ec));
    NSArray *rawEntries = [ctlDict[@"entries"] isKindOfClass:[NSArray class]] ? ctlDict[@"entries"] : @[];
    NSArray *dbPaths = [ctlDict[@"dbPaths"] isKindOfClass:[NSArray class]] ? ctlDict[@"dbPaths"] : @[];

    NSMutableDictionary<NSString *, NSDictionary *> *byDomain = [NSMutableDictionary dictionary];
    for (NSDictionary *row in rawEntries) {
        if (![row isKindOfClass:[NSDictionary class]]) continue;
        NSString *dom = [row[@"domain"] isKindOfClass:[NSString class]] ? [row[@"domain"] lowercaseString] : @"";
        int val = [row[@"value"] intValue];
        if (dom.length == 0) continue;
        if (val == offVal) {
            byDomain[dom] = @{
                @"domain": dom,
                @"preference": row[@"preference"] ?: prefKey,
                @"value": @(val),
                @"timestamp": row[@"timestamp"] ?: @0,
                @"dbPath": row[@"dbPath"] ?: @""
            };
        }
    }

    NSArray<NSString *> *sortedDomains = [[byDomain allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray<NSDictionary *> *items = [NSMutableArray arrayWithCapacity:sortedDomains.count];
    for (NSString *d in sortedDomains) {
        [items addObject:byDomain[d]];
    }

    return @{
        @"preferenceKey": prefKey,
        @"offVal": @(offVal),
        @"dbPaths": dbPaths,
        @"allPreferenceKeys": ctlDict[@"allPreferenceKeys"] ?: @[],
        @"items": items
    };
}

NSString *LBBridgeSafariSetDomainExcluded(NSString *domain, BOOL excluded) {
    NSString *clean = [[domain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (clean.length == 0) {
        return @"域名不能为空";
    }

    id mgr = nil;
    id pref = nil;
    NSDictionary *spec = LBDiscoverSafariPreferenceSpec(&mgr, &pref);
    NSString *prefKey = spec[@"preferenceKey"] ?: @"PerSitePreferencesLockdownMode";
    int offVal = [spec[@"offVal"] intValue];
    int onVal = [spec[@"onVal"] intValue];

    // Tier 1: Call native SafariShared WBSLockdownModePreferenceManager on background queue with timeout
    if (mgr && pref) {
        SEL setSel = NSSelectorFromString(@"setValue:ofPreference:forDomain:completionHandler:");
        SEL rmSel = NSSelectorFromString(@"removePreferenceValuesForDomains:fromPreference:completionHandler:");
        if (excluded && [mgr respondsToSelector:setSel]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                @try {
                    void (^handler)(BOOL) = ^(__unused BOOL ok) {
                        dispatch_semaphore_signal(sem);
                    };
                    ((void (*)(id, SEL, id, id, id, void (^)(BOOL)))objc_msgSend)(
                        mgr, setSel, @(offVal), pref, clean, handler);
                } @catch (__unused NSException *ex) {
                    dispatch_semaphore_signal(sem);
                }
            });
            (void)dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(900 * NSEC_PER_MSEC)));
        } else if (!excluded && [mgr respondsToSelector:rmSel]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                @try {
                    NSSet *domSet = [NSSet setWithObject:clean];
                    void (^handler)(BOOL) = ^(__unused BOOL ok) {
                        dispatch_semaphore_signal(sem);
                    };
                    ((void (*)(id, SEL, id, id, void (^)(BOOL)))objc_msgSend)(
                        mgr, rmSel, domSet, pref, handler);
                } @catch (__unused NSException *ex) {
                    dispatch_semaphore_signal(sem);
                }
            });
            (void)dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(900 * NSEC_PER_MSEC)));
        } else if (!excluded && [mgr respondsToSelector:setSel]) {
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                @try {
                    void (^handler)(BOOL) = ^(__unused BOOL ok) {
                        dispatch_semaphore_signal(sem);
                    };
                    ((void (*)(id, SEL, id, id, id, void (^)(BOOL)))objc_msgSend)(
                        mgr, setSel, @(onVal), pref, clean, handler);
                } @catch (__unused NSException *ex) {
                    dispatch_semaphore_signal(sem);
                }
            });
            (void)dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(900 * NSEC_PER_MSEC)));
        }
    }

    // Tier 2: Guaranteed SQLite persistence across all Safari PerSitePreferences.db files via root helper
    int ec = -1;
    NSArray<NSString *> *ctlArgs = @[
        @"--safari-set",
        clean,
        prefKey,
        [NSString stringWithFormat:@"%d", offVal],
        excluded ? @"1" : @"0"
    ];
    NSDictionary *res = LBParseJSONDict(LBBridgeRunCtl(ctlArgs, &ec));
    BOOL ok = [res[@"ok"] boolValue];
    if (!ok) {
        NSArray *errs = res[@"errors"];
        return ([errs isKindOfClass:[NSArray class]] && errs.count > 0)
            ? [errs componentsJoinedByString:@"; "]
            : (res[@"error"] ?: @"写入 PerSitePreferences.db 失败");
    }
    return @"";
}

NSInteger LBBridgeRestartSafari(void) {
    int ec = -1;
    NSDictionary *res = LBParseJSONDict(LBBridgeRunCtl(@[@"--kill-safari"], &ec));
    return [res[@"killed"] integerValue];
}

// MARK: - Installed Applications & Per-App Lockdown Whitelist

NSArray<NSDictionary<NSString *, id> *> *LBBridgeListInstalledApps(void) {
    LBEnsurePrivateFrameworksLoaded();

    int ec = -1;
    NSDictionary *scanDict = LBParseJSONDict(LBBridgeRunCtl(@[@"--scan-containers"], &ec));
    NSArray *rawContainers = [scanDict[@"containers"] isKindOfClass:[NSArray class]] ? scanDict[@"containers"] : @[];

    NSMutableDictionary<NSString *, NSDictionary *> *containerByBundle = [NSMutableDictionary dictionary];
    for (NSDictionary *c in rawContainers) {
        if (![c isKindOfClass:[NSDictionary class]]) continue;
        NSString *bid = c[@"id"];
        if ([bid isKindOfClass:[NSString class]] && bid.length > 0) {
            containerByBundle[bid] = c;
        }
    }

    NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *appsByBundle = [NSMutableDictionary dictionary];
    Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
    id ws = wsCls ? LBSafeInvoke0(wsCls, @"defaultWorkspace") : nil;
    id proxies = ws ? LBSafeInvoke0(ws, @"allInstalledApplications") : nil;

    if ([proxies isKindOfClass:[NSArray class]]) {
        for (id proxy in (NSArray *)proxies) {
            id bidObj = LBSafeInvoke0(proxy, @"applicationIdentifier") ?: LBSafeInvoke0(proxy, @"bundleIdentifier");
            if (![bidObj isKindOfClass:[NSString class]]) continue;
            NSString *bid = (NSString *)bidObj;
            if (bid.length == 0 || [bid isEqualToString:@"com.lili.lockdownwhitelist"]) continue;

            id nameObj = LBSafeInvoke0(proxy, @"localizedName") ?: LBSafeInvoke0(proxy, @"itemName");
            NSString *name = ([nameObj isKindOfClass:[NSString class]] && [(NSString *)nameObj length] > 0)
                ? (NSString *)nameObj
                : bid;

            id typeObj = LBSafeInvoke0(proxy, @"applicationType");
            NSString *appType = [typeObj isKindOfClass:[NSString class]] ? (NSString *)typeObj : @"User";
            BOOL isSystem = [appType isEqualToString:@"System"] || [bid hasPrefix:@"com.apple."];

            NSString *containerPath = @"";
            id dcURL = LBSafeInvoke0(proxy, @"dataContainerURL");
            if ([dcURL isKindOfClass:[NSURL class]]) {
                containerPath = [(NSURL *)dcURL path] ?: @"";
            }
            NSDictionary *cInfo = containerByBundle[bid];
            if (containerPath.length == 0 && cInfo) {
                containerPath = cInfo[@"path"] ?: @"";
            }
            if (containerPath.length == 0) continue; // Only apps with a data container can host WKWebView preferences

            NSString *bundleFolder = @"";
            id bURL = LBSafeInvoke0(proxy, @"bundleURL");
            if ([bURL isKindOfClass:[NSURL class]]) {
                NSString *last = [[(NSURL *)bURL path] lastPathComponent];
                if ([last hasSuffix:@".app"]) {
                    bundleFolder = [NSString stringWithFormat:@"/%@/", last];
                }
            }

            BOOL cpmIgnored = [cInfo[@"cpmIgnored"] boolValue];
            NSNumber *wkStat = LBQueryWKIsIgnoredForContainer(containerPath);
            if (wkStat != nil) {
                cpmIgnored = cpmIgnored || [wkStat boolValue];
            }
            BOOL deepIgnored = [cInfo[@"deepIgnored"] boolValue];

            appsByBundle[bid] = @{
                @"bundleId": bid,
                @"name": name,
                @"isSystem": @(isSystem),
                @"containerPath": containerPath,
                @"bundleFolder": bundleFolder,
                @"excluded": @(cpmIgnored),
                @"deepIgnored": @(deepIgnored)
            };
        }
    }

    // Fallback: include any container found by ldmctl that LSApplicationWorkspace didn't yield
    Class proxyCls = NSClassFromString(@"LSApplicationProxy");
    for (NSString *bid in containerByBundle) {
        if (appsByBundle[bid] != nil || [bid isEqualToString:@"com.lili.lockdownwhitelist"]) continue;
        NSDictionary *cInfo = containerByBundle[bid];
        NSString *cpath = cInfo[@"path"] ?: @"";
        if (cpath.length == 0) continue;

        NSString *name = bid;
        BOOL isSystem = [bid hasPrefix:@"com.apple."];
        NSString *bundleFolder = @"";

        if (proxyCls) {
            id prx = LBSafeInvoke1Obj(proxyCls, @"applicationProxyForIdentifier:", bid);
            if (prx) {
                id nm = LBSafeInvoke0(prx, @"localizedName");
                if ([nm isKindOfClass:[NSString class]] && [(NSString *)nm length] > 0) name = nm;
                id tp = LBSafeInvoke0(prx, @"applicationType");
                if ([tp isKindOfClass:[NSString class]] && [(NSString *)tp isEqualToString:@"System"]) isSystem = YES;
                id bURL = LBSafeInvoke0(prx, @"bundleURL");
                if ([bURL isKindOfClass:[NSURL class]]) {
                    NSString *last = [[(NSURL *)bURL path] lastPathComponent];
                    if ([last hasSuffix:@".app"]) bundleFolder = [NSString stringWithFormat:@"/%@/", last];
                }
            }
        }

        appsByBundle[bid] = @{
            @"bundleId": bid,
            @"name": name,
            @"isSystem": @(isSystem),
            @"containerPath": cpath,
            @"bundleFolder": bundleFolder,
            @"excluded": @([cInfo[@"cpmIgnored"] boolValue]),
            @"deepIgnored": @([cInfo[@"deepIgnored"] boolValue])
        };
    }

    NSArray<NSDictionary<NSString *, id> *> *all = [appsByBundle allValues];
    return [all sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL exA = [a[@"excluded"] boolValue];
        BOOL exB = [b[@"excluded"] boolValue];
        if (exA != exB) return exA ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
}

NSData *LBBridgeAppIconPNG(NSString *bundleId) {
    if (bundleId.length == 0) return nil;
    @try {
        SEL iconSel = NSSelectorFromString(@"_applicationIconImageForBundleIdentifier:format:scale:");
        if ([UIImage respondsToSelector:iconSel]) {
            CGFloat scale = UIScreen.mainScreen.scale;
            UIImage *img = ((UIImage *(*)(id, SEL, NSString *, int, CGFloat))objc_msgSend)(
                [UIImage class], iconSel, bundleId, 2, scale);
            if (img) {
                return UIImagePNGRepresentation(img);
            }
        }
    } @catch (__unused NSException *ex) {}
    return nil;
}

NSString *LBBridgeSetAppExcluded(NSString *bundleId,
                                 NSString *containerPath,
                                 BOOL excluded,
                                 BOOL deepOverride) {
    if (bundleId.length == 0 || containerPath.length == 0) {
        return @"缺少应用容器路径";
    }

    // Tier 1: Call native WebKit _WKSystemPreferences
    (void)LBInvokeWKSetIgnoredForContainer(containerPath, excluded);

    // Tier 2: Persist cpmconfig_ignore + optional deep LDMGlobalEnabled=NO via root helper (ensuring mobile 501:501 ownership)
    int ec = -1;
    NSArray<NSString *> *args = @[
        @"--set-app",
        containerPath,
        bundleId,
        excluded ? @"1" : @"0",
        (excluded && deepOverride) ? @"1" : @"0"
    ];
    NSDictionary *res = LBParseJSONDict(LBBridgeRunCtl(args, &ec));
    BOOL ok = [res[@"ok"] boolValue];
    if (!ok) {
        return res[@"error"] ? [NSString stringWithFormat:@"%@", res[@"error"]] : @"写入应用白名单标记失败";
    }
    return @"";
}

NSInteger LBBridgeRestartApp(NSString *appBundleFolderName) {
    if (appBundleFolderName.length == 0) return 0;
    int ec = -1;
    NSDictionary *res = LBParseJSONDict(LBBridgeRunCtl(@[@"--kill-exec", appBundleFolderName], &ec));
    return [res[@"killed"] integerValue];
}

NSDictionary<NSString *, id> *LBBridgeRunIOCScan(void) {
    int ec = -1;
    return LBParseJSONDict(LBBridgeRunCtl(@[@"--ioc-scan"], &ec));
}
