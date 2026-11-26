/*
 * ldmctl.m — Short-lived root helper for LockdownBypass (TrollStore iOS 16.0 - 16.7).
 * Spawned via POSIX persona(99 / uid=0) on demand; exits immediately after each task (0 background drain).
 *
 * Subcommands:
 *   --probe
 *   --scan-containers
 *   --set-app <containerPath> <bundleId> <ignore:0|1> <deep:0|1>
 *   --safari-list [prefKeyHint]
 *   --safari-set <domain> <prefKey> <offValInt> <exclude:0|1>
 *   --kill-safari
 *   --kill-exec <execNameOrBundleSubpath>
 *   --ioc-scan
 */

#import <Foundation/Foundation.h>
#include <sqlite3.h>
#include <notify.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PROC_PIDPATHINFO_MAXSIZE (4 * 1024)
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static void get_mobile_ids(uid_t *uidOut, gid_t *gidOut) {
    struct passwd *pw = getpwnam("mobile");
    if (pw) {
        *uidOut = pw->pw_uid;
        *gidOut = pw->pw_gid;
    } else {
        *uidOut = 501;
        *gidOut = 501;
    }
}

static void fix_mobile_owner(NSString *path) {
    if (path.length == 0) return;
    uid_t uid = 501;
    gid_t gid = 501;
    get_mobile_ids(&uid, &gid);
    const char *cpath = path.fileSystemRepresentation;
    if (cpath) {
        (void)chown(cpath, uid, gid);
    }
}

static void ensure_mobile_dir(NSString *dirPath) {
    if (dirPath.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) {
        [fm createDirectoryAtPath:dirPath
      withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions: @(0755)}
                            error:nil];
    }
    fix_mobile_owner(dirPath);
}

static void print_json(id obj) {
    if (!obj) {
        printf("{}\n");
        return;
    }
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:obj options:0 error:&err];
    if (!data || err) {
        printf("{\"error\":\"json_serialize_failed\"}\n");
        return;
    }
    fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
}

static BOOL is_safe_app_container_path(NSString *p) {
    if (p.length == 0 || [p containsString:@".."]) return NO;
    return [p hasPrefix:@"/var/mobile/Containers/Data/Application/"] ||
           [p hasPrefix:@"/private/var/mobile/Containers/Data/Application/"];
}

static NSDictionary<NSString *, NSString *> *scan_container_root(NSString *rootDir, NSMutableArray *outItems, NSString *kind) {
    NSMutableDictionary<NSString *, NSString *> *idToPath = [NSMutableDictionary dictionary];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *uuids = [fm contentsOfDirectoryAtPath:rootDir error:nil];
    for (NSString *sub in uuids) {
        NSString *containerPath = [rootDir stringByAppendingPathComponent:sub];
        NSString *metaPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        if (![meta isKindOfClass:[NSDictionary class]]) continue;
        NSString *ident = meta[@"MCMMetadataIdentifier"];
        if (![ident isKindOfClass:[NSString class]] || ident.length == 0) continue;

        idToPath[ident] = containerPath;
        if (outItems) {
            NSString *ignoreFile = [containerPath stringByAppendingPathComponent:@"Library/Preferences/com.apple.WebKit.cpmconfig_ignore"];
            BOOL cpmIgnored = [fm fileExistsAtPath:ignoreFile];
            NSString *prefPath = [containerPath stringByAppendingPathComponent:
                                  [NSString stringWithFormat:@"Library/Preferences/%@.plist", ident]];
            BOOL deepIgnored = NO;
            NSDictionary *appPrefs = [NSDictionary dictionaryWithContentsOfFile:prefPath];
            if ([appPrefs isKindOfClass:[NSDictionary class]] && appPrefs[@"LDMGlobalEnabled"] != nil) {
                deepIgnored = ![appPrefs[@"LDMGlobalEnabled"] boolValue];
            }
            [outItems addObject:@{
                @"kind": kind,
                @"id": ident,
                @"path": containerPath,
                @"cpmIgnored": @(cpmIgnored),
                @"deepIgnored": @(deepIgnored)
            }];
        }
    }
    return idToPath;
}

static NSArray<NSString *> *discover_safari_db_paths(BOOL createFallbackIfEmpty) {
    NSMutableOrderedSet<NSString *> *paths = [NSMutableOrderedSet orderedSet];
    NSFileManager *fm = [NSFileManager defaultManager];

    // 1. MobileSafari App Data Container: Library/Safari/PerSitePreferences.db
    NSDictionary<NSString *, NSString *> *appMap = scan_container_root(@"/var/mobile/Containers/Data/Application", nil, @"app");
    NSString *safariAppContainer = appMap[@"com.apple.mobilesafari"];
    if (safariAppContainer.length > 0) {
        NSString *p = [safariAppContainer stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
        if ([fm fileExistsAtPath:p]) [paths addObject:p];
    }

    // 2. Shared /var/mobile/Library/Safari/PerSitePreferences.db
    NSString *sharedMobileSafariDB = @"/var/mobile/Library/Safari/PerSitePreferences.db";
    if ([fm fileExistsAtPath:sharedMobileSafariDB]) {
        [paths addObject:sharedMobileSafariDB];
    }

    // 3. AppGroup Containers matching safari
    NSDictionary<NSString *, NSString *> *groupMap = scan_container_root(@"/var/mobile/Containers/Shared/AppGroup", nil, @"group");
    for (NSString *gid in groupMap) {
        if ([gid rangeOfString:@"safari" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            NSString *gp = [groupMap[gid] stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
            if ([fm fileExistsAtPath:gp]) {
                [paths addObject:gp];
            }
        }
    }

    if (paths.count == 0 && createFallbackIfEmpty) {
        if (safariAppContainer.length > 0) {
            NSString *dir = [safariAppContainer stringByAppendingPathComponent:@"Library/Safari"];
            ensure_mobile_dir(dir);
            [paths addObject:[dir stringByAppendingPathComponent:@"PerSitePreferences.db"]];
        }
        ensure_mobile_dir(@"/var/mobile/Library/Safari");
        [paths addObject:sharedMobileSafariDB];
    }
    return paths.array;
}

static BOOL table_has_column(sqlite3 *db, const char *tableName, const char *colName) {
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", tableName);
    sqlite3_stmt *stmt = NULL;
    BOOL found = NO;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 1);
            if (name && strcasecmp((const char *)name, colName) == 0) {
                found = YES;
                break;
            }
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    return found;
}

static BOOL is_lockdown_pref_name(NSString *prefName, NSString *hint) {
    if (prefName.length == 0) return NO;
    if (hint.length > 0 && [prefName isEqualToString:hint]) return YES;
    if ([prefName rangeOfString:@"lockdown" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    if ([prefName rangeOfString:@"captiveportal" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static int cmd_safari_list(NSString *prefHint) {
    NSArray<NSString *> *dbPaths = discover_safari_db_paths(NO);
    NSMutableOrderedSet<NSString *> *detectedKeys = [NSMutableOrderedSet orderedSet];
    NSMutableOrderedSet<NSString *> *allKeys = [NSMutableOrderedSet orderedSet];
    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];

    for (NSString *dbPath in dbPaths) {
        sqlite3 *db = NULL;
        if (sqlite3_open_v2(dbPath.fileSystemRepresentation, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            continue;
        }
        sqlite3_busy_timeout(db, 2000);

        const char *keySql = "SELECT DISTINCT preference FROM preference_values UNION SELECT DISTINCT preference FROM default_preferences;";
        sqlite3_stmt *kstmt = NULL;
        if (sqlite3_prepare_v2(db, keySql, -1, &kstmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(kstmt) == SQLITE_ROW) {
                const unsigned char *p = sqlite3_column_text(kstmt, 0);
                if (p) {
                    NSString *ps = [NSString stringWithUTF8String:(const char *)p];
                    if (ps.length > 0) {
                        [allKeys addObject:ps];
                        if (is_lockdown_pref_name(ps, prefHint)) {
                            [detectedKeys addObject:ps];
                        }
                    }
                }
            }
        }
        if (kstmt) sqlite3_finalize(kstmt);

        BOOL hasTs = table_has_column(db, "preference_values", "timestamp");
        const char *rowSql = hasTs
            ? "SELECT domain, preference, preference_value, COALESCE(timestamp, 0) FROM preference_values ORDER BY domain ASC;"
            : "SELECT domain, preference, preference_value, 0 FROM preference_values ORDER BY domain ASC;";
        sqlite3_stmt *rstmt = NULL;
        if (sqlite3_prepare_v2(db, rowSql, -1, &rstmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(rstmt) == SQLITE_ROW) {
                const unsigned char *dom = sqlite3_column_text(rstmt, 0);
                const unsigned char *prf = sqlite3_column_text(rstmt, 1);
                int val = sqlite3_column_int(rstmt, 2);
                double ts = sqlite3_column_double(rstmt, 3);
                if (!dom || !prf) continue;
                NSString *domStr = [NSString stringWithUTF8String:(const char *)dom] ?: @"";
                NSString *prfStr = [NSString stringWithUTF8String:(const char *)prf] ?: @"";
                if (domStr.length > 0 && is_lockdown_pref_name(prfStr, prefHint)) {
                    [entries addObject:@{
                        @"domain": domStr,
                        @"preference": prfStr,
                        @"value": @(val),
                        @"timestamp": @(ts),
                        @"dbPath": dbPath
                    }];
                }
            }
        }
        if (rstmt) sqlite3_finalize(rstmt);
        sqlite3_close(db);
    }

    print_json(@{
        @"ok": @YES,
        @"dbPaths": dbPaths ?: @[],
        @"detectedLockdownKeys": detectedKeys.array ?: @[],
        @"allPreferenceKeys": allKeys.array ?: @[],
        @"entries": entries
    });
    return 0;
}

static int cmd_safari_set(NSString *domain, NSString *prefKey, int offVal, BOOL exclude) {
    NSString *cleanDomain = [[domain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (cleanDomain.length == 0 || prefKey.length == 0) {
        print_json(@{@"ok": @NO, @"error": @"invalid_domain_or_key"});
        return 1;
    }

    NSArray<NSString *> *dbPaths = discover_safari_db_paths(YES);
    NSMutableArray<NSString *> *updatedPaths = [NSMutableArray array];
    NSMutableArray<NSString *> *errors = [NSMutableArray array];

    for (NSString *dbPath in dbPaths) {
        ensure_mobile_dir([dbPath stringByDeletingLastPathComponent]);
        sqlite3 *db = NULL;
        int rc = sqlite3_open_v2(dbPath.fileSystemRepresentation, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if (rc != SQLITE_OK || !db) {
            [errors addObject:[NSString stringWithFormat:@"open_failed:%@(%d)", dbPath, rc]];
            if (db) sqlite3_close(db);
            continue;
        }
        sqlite3_busy_timeout(db, 2500);

        const char *initSql =
            "CREATE TABLE IF NOT EXISTS default_preferences (id INTEGER PRIMARY KEY AUTOINCREMENT, preference TEXT UNIQUE, default_value NUMERIC);"
            "CREATE TABLE IF NOT EXISTS preference_values (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, preference TEXT, preference_value NUMERIC, timestamp REAL, UNIQUE(domain, preference));";
        (void)sqlite3_exec(db, initSql, NULL, NULL, NULL);

        // Delete existing Lockdown/CaptivePortal rows for this domain (case-insensitive)
        const char *delSql =
            "DELETE FROM preference_values WHERE LOWER(domain) = LOWER(?) AND "
            "(preference = ? OR preference LIKE '%Lockdown%' OR preference LIKE '%CaptivePortal%');";
        sqlite3_stmt *dstmt = NULL;
        if (sqlite3_prepare_v2(db, delSql, -1, &dstmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(dstmt, 1, cleanDomain.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(dstmt, 2, prefKey.UTF8String, -1, SQLITE_TRANSIENT);
            (void)sqlite3_step(dstmt);
        }
        if (dstmt) sqlite3_finalize(dstmt);

        BOOL stepOk = YES;
        if (exclude) {
            BOOL hasTs = table_has_column(db, "preference_values", "timestamp");
            const char *insSql = hasTs
                ? "INSERT OR REPLACE INTO preference_values (domain, preference, preference_value, timestamp) VALUES (?, ?, ?, ?);"
                : "INSERT OR REPLACE INTO preference_values (domain, preference, preference_value) VALUES (?, ?, ?);";
            sqlite3_stmt *istmt = NULL;
            if (sqlite3_prepare_v2(db, insSql, -1, &istmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(istmt, 1, cleanDomain.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(istmt, 2, prefKey.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(istmt, 3, offVal);
                if (hasTs) {
                    sqlite3_bind_double(istmt, 4, CFAbsoluteTimeGetCurrent());
                }
                int sRc = sqlite3_step(istmt);
                if (sRc != SQLITE_DONE) {
                    stepOk = NO;
                    const char *emsg = sqlite3_errmsg(db);
                    [errors addObject:[NSString stringWithFormat:@"insert_failed:%@:%s", dbPath, emsg ?: "err"]];
                }
            } else {
                stepOk = NO;
                [errors addObject:[NSString stringWithFormat:@"prepare_failed:%@", dbPath]];
            }
            if (istmt) sqlite3_finalize(istmt);
        }

        (void)sqlite3_exec(db, "PRAGMA wal_checkpoint(PASSIVE);", NULL, NULL, NULL);
        sqlite3_close(db);

        fix_mobile_owner(dbPath);
        fix_mobile_owner([dbPath stringByAppendingString:@"-wal"]);
        fix_mobile_owner([dbPath stringByAppendingString:@"-shm"]);

        if (stepOk) {
            [updatedPaths addObject:dbPath];
        }
    }

    print_json(@{
        @"ok": @(updatedPaths.count > 0),
        @"domain": cleanDomain,
        @"preference": prefKey,
        @"excluded": @(exclude),
        @"updatedPaths": updatedPaths,
        @"errors": errors
    });
    return updatedPaths.count > 0 ? 0 : 1;
}

static int cmd_set_app(NSString *containerPath, NSString *bundleId, BOOL ignore, BOOL deep) {
    if (!is_safe_app_container_path(containerPath) || bundleId.length == 0 || [bundleId containsString:@"/"]) {
        print_json(@{@"ok": @NO, @"error": @"invalid_container_or_bundle"});
        return 1;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *prefsDir = [containerPath stringByAppendingPathComponent:@"Library/Preferences"];
    ensure_mobile_dir([containerPath stringByAppendingPathComponent:@"Library"]);
    ensure_mobile_dir(prefsDir);

    NSString *ignoreFile = [prefsDir stringByAppendingPathComponent:@"com.apple.WebKit.cpmconfig_ignore"];
    NSError *err = nil;
    if (ignore) {
        NSData *marker = [@"1\n" dataUsingEncoding:NSUTF8StringEncoding];
        if (![marker writeToFile:ignoreFile options:NSDataWritingAtomic error:&err]) {
            print_json(@{@"ok": @NO, @"error": err.localizedDescription ?: @"write_cpmconfig_failed"});
            return 1;
        }
        chmod(ignoreFile.fileSystemRepresentation, 0644);
        fix_mobile_owner(ignoreFile);
    } else {
        if ([fm fileExistsAtPath:ignoreFile]) {
            [fm removeItemAtPath:ignoreFile error:nil];
        }
    }

    NSString *appPlistPath = [prefsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist", bundleId]];
    NSMutableDictionary *dict = [[NSDictionary dictionaryWithContentsOfFile:appPlistPath] mutableCopy];
    if (ignore && deep) {
        if (!dict) dict = [NSMutableDictionary dictionary];
        dict[@"LDMGlobalEnabled"] = @NO;
        NSData *bplist = [NSPropertyListSerialization dataWithPropertyList:dict
                                                                    format:NSPropertyListBinaryFormat_v1_0
                                                                   options:0
                                                                     error:nil];
        if (bplist) {
            [bplist writeToFile:appPlistPath options:NSDataWritingAtomic error:nil];
            chmod(appPlistPath.fileSystemRepresentation, 0600);
            fix_mobile_owner(appPlistPath);
        }
    } else if (dict && dict[@"LDMGlobalEnabled"] != nil) {
        [dict removeObjectForKey:@"LDMGlobalEnabled"];
        NSData *bplist = [NSPropertyListSerialization dataWithPropertyList:dict
                                                                    format:NSPropertyListBinaryFormat_v1_0
                                                                   options:0
                                                                     error:nil];
        if (bplist) {
            [bplist writeToFile:appPlistPath options:NSDataWritingAtomic error:nil];
            chmod(appPlistPath.fileSystemRepresentation, 0600);
            fix_mobile_owner(appPlistPath);
        }
    }

    notify_post("com.apple.WebKit.cpmconfig");
    notify_post("WKCaptivePortalModeContainerConfigurationChangedNotification");

    print_json(@{
        @"ok": @YES,
        @"bundleId": bundleId,
        @"containerPath": containerPath,
        @"cpmIgnored": @(ignore),
        @"deepIgnored": @(ignore && deep)
    });
    return 0;
}

static int kill_matching_processes(BOOL safariSuite, NSString *targetSubpath) {
    int countEst = proc_listallpids(NULL, 0);
    if (countEst <= 0) countEst = 512;
    size_t bufSize = (size_t)(countEst + 128) * sizeof(pid_t);
    pid_t *pids = (pid_t *)calloc(1, bufSize);
    if (!pids) return -1;

    int bytes = proc_listallpids(pids, (int)bufSize);
    int n = bytes > 0 ? (bytes / (int)sizeof(pid_t)) : 0;
    pid_t selfPid = getpid();
    pid_t parentPid = getppid();
    int killed = 0;

    for (int i = 0; i < n; i++) {
        pid_t pid = pids[i];
        if (pid <= 1 || pid == selfPid || pid == parentPid) continue;
        char pathBuf[PROC_PIDPATHINFO_MAXSIZE];
        memset(pathBuf, 0, sizeof(pathBuf));
        if (proc_pidpath((int)pid, pathBuf, sizeof(pathBuf)) <= 0) continue;
        NSString *p = [NSString stringWithUTF8String:pathBuf];
        if (p.length == 0) continue;

        BOOL match = NO;
        if (safariSuite) {
            if ([p hasSuffix:@"/MobileSafari.app/MobileSafari"] ||
                [p hasSuffix:@"/SafariViewService.app/SafariViewService"] ||
                [p containsString:@"com.apple.Safari.SandboxBroker"]) {
                match = YES;
            }
        } else if (targetSubpath.length > 0) {
            if (([p hasPrefix:@"/var/containers/Bundle/Application/"] ||
                 [p hasPrefix:@"/private/var/containers/Bundle/Application/"] ||
                 [p hasPrefix:@"/Applications/"]) &&
                [p containsString:targetSubpath] &&
                ![p containsString:@"LockdownBypass.app"]) {
                match = YES;
            }
        }

        if (match) {
            if (kill(pid, SIGTERM) == 0) {
                killed++;
            }
        }
    }
    free(pids);
    return killed;
}

static int cmd_ioc_scan(void) {
    NSArray<NSDictionary<NSString *, NSString *> *> *checks = @[
        @{
            @"path": @"/private/var/mobile/Library/Preferences/com.apple.photolibraryd.plist",
            @"family": @"Coruna / CryptoWaters",
            @"severity": @"high",
            @"desc": @"locationd 植入体持久化配置文件（正常 iOS 系统不会在 mobile/Preferences 下生成此文件）"
        },
        @{
            @"path": @"/private/var/mobile/Library/Preferences/com.apple.photolibraryd.retry.plist",
            @"family": @"Coruna / CryptoWaters",
            @"severity": @"high",
            @"desc": @"locationd 相册窃取模块重试状态文件"
        },
        @{
            @"path": @"/private/var/mobile/Library/Caches/.com.apple.notes.cache.plist",
            @"family": @"Coruna / CryptoWaters",
            @"severity": @"high",
            @"desc": @"苹果备忘录助记词/敏感词扫描缓存文件（隐藏点文件）"
        },
        @{
            @"path": @"/private/var/mobile/Library/Caches/.com.apple.mobileassetd.cache",
            @"family": @"Coruna / CryptoWaters",
            @"severity": @"high",
            @"desc": @"伪装系统资产服务的隐藏载荷缓存文件"
        },
        @{
            @"path": @"/private/var/tmp/pl.sp.exec.guard.lock",
            @"family": @"Coruna / PLASMAGRID",
            @"severity": @"high",
            @"desc": @"powerd 第二阶段植入体互斥锁文件"
        },
        @{
            @"path": @"/private/var/tmp/pl.core.lock",
            @"family": @"Coruna / PLASMAGRID",
            @"severity": @"high",
            @"desc": @"locationd CorePayload 核心调度锁文件"
        },
        @{
            @"path": @"/private/var/tmp/upgrade.dylib",
            @"family": @"Coruna / PLASMAGRID",
            @"severity": @"high",
            @"desc": @"未签名动态库热更新残留文件"
        }
    ];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    NSInteger hits = 0;

    for (NSDictionary<NSString *, NSString *> *item in checks) {
        NSString *p = item[@"path"];
        BOOL exists = [fm fileExistsAtPath:p];
        if (exists) hits++;
        [results addObject:@{
            @"path": p,
            @"family": item[@"family"],
            @"severity": item[@"severity"],
            @"desc": item[@"desc"],
            @"found": @(exists)
        }];
    }

    print_json(@{
        @"ok": @YES,
        @"clean": @(hits == 0),
        @"hitCount": @(hits),
        @"uid": @(geteuid()),
        @"items": results
    });
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            print_json(@{@"ok": @NO, @"error": @"missing_subcommand"});
            return 2;
        }
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];
        if ([cmd isEqualToString:@"--probe"]) {
            printf("OK uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
            return 0;
        }
        if ([cmd isEqualToString:@"--scan-containers"]) {
            NSMutableArray *items = [NSMutableArray array];
            (void)scan_container_root(@"/var/mobile/Containers/Data/Application", items, @"app");
            print_json(@{@"ok": @YES, @"uid": @(geteuid()), @"containers": items});
            return 0;
        }
        if ([cmd isEqualToString:@"--set-app"]) {
            if (argc < 6) {
                print_json(@{@"ok": @NO, @"error": @"usage: --set-app <container> <bundleId> <0|1> <0|1>"});
                return 2;
            }
            NSString *cpath = [NSString stringWithUTF8String:argv[2]];
            NSString *bid = [NSString stringWithUTF8String:argv[3]];
            BOOL ign = atoi(argv[4]) != 0;
            BOOL deep = atoi(argv[5]) != 0;
            return cmd_set_app(cpath, bid, ign, deep);
        }
        if ([cmd isEqualToString:@"--safari-list"]) {
            NSString *hint = (argc >= 3) ? [NSString stringWithUTF8String:argv[2]] : @"";
            return cmd_safari_list(hint);
        }
        if ([cmd isEqualToString:@"--safari-set"]) {
            if (argc < 6) {
                print_json(@{@"ok": @NO, @"error": @"usage: --safari-set <domain> <prefKey> <offVal> <0|1>"});
                return 2;
            }
            NSString *dom = [NSString stringWithUTF8String:argv[2]];
            NSString *key = [NSString stringWithUTF8String:argv[3]];
            int offVal = atoi(argv[4]);
            BOOL excl = atoi(argv[5]) != 0;
            return cmd_safari_set(dom, key, offVal, excl);
        }
        if ([cmd isEqualToString:@"--kill-safari"]) {
            int k = kill_matching_processes(YES, nil);
            print_json(@{@"ok": @YES, @"killed": @(k)});
            return 0;
        }
        if ([cmd isEqualToString:@"--kill-exec"]) {
            if (argc < 3) {
                print_json(@{@"ok": @NO, @"error": @"missing_exec"});
                return 2;
            }
            NSString *sub = [NSString stringWithUTF8String:argv[2]];
            int k = kill_matching_processes(NO, sub);
            print_json(@{@"ok": @YES, @"killed": @(k)});
            return 0;
        }
        if ([cmd isEqualToString:@"--ioc-scan"]) {
            return cmd_ioc_scan();
        }

        print_json(@{@"ok": @NO, @"error": @"unknown_subcommand"});
        return 2;
    }
}
