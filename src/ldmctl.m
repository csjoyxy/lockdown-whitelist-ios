/*
 * ldmctl.m — Short-lived root helper for LockdownBypass (TrollStore iOS 16.0 - 16.7).
 * Spawned via POSIX persona(99 / uid=0) on demand; exits immediately after each task (0 background drain).
 *
 * Subcommands:
 *   --probe
 *   --scan-containers
 *   --set-app <containerPath> <bundleId> <ignore:0|1> <deep:0|1>
 *   --safari-list [prefKeyHint] [dbPathHint]
 *   --safari-set <domain> <prefKey> <offValInt> <exclude:0|1> [dbPathHint]
 *   --kill-safari
 *   --kill-exec <execNameOrBundleSubpath>
 *   --ioc-scan
 *   --security-audit
 *   --devmode-status
 *   --devmode-reveal
 *   --devmode-arm
 *   --devmode-disable
 *   --reboot
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <sqlite3.h>
#include <notify.h>
#include <dlfcn.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
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

static BOOL is_safe_mobile_db_path(NSString *p) {
    if (p.length == 0 || [p containsString:@".."] || ![p hasSuffix:@".db"]) return NO;
    return [p hasPrefix:@"/var/mobile/"] || [p hasPrefix:@"/private/var/mobile/"];
}

static NSString *utc_timestamp_string(void) {
    time_t now = time(NULL);
    struct tm gmt;
    memset(&gmt, 0, sizeof(gmt));
    gmtime_r(&now, &gmt);
    char buf[32];
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &gmt) == 0) {
        return @"";
    }
    return [NSString stringWithUTF8String:buf] ?: @"";
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
            // WebKit _WKSystemPreferences checks <containerPath>/System/Preferences/com.apple.WebKit.cpmconfig_ignore
            NSString *ignoreFile = [containerPath stringByAppendingPathComponent:@"System/Preferences/com.apple.WebKit.cpmconfig_ignore"];
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

static NSArray<NSString *> *discover_safari_db_paths(BOOL createFallbackIfEmpty, NSString *dbPathHint) {
    NSMutableOrderedSet<NSString *> *paths = [NSMutableOrderedSet orderedSet];
    NSFileManager *fm = [NSFileManager defaultManager];

    // 0. Runtime WBSPerSitePreferencesSQLiteStore.defaultDatabaseURL hint (if provided)
    if (is_safe_mobile_db_path(dbPathHint) && [fm fileExistsAtPath:dbPathHint]) {
        [paths addObject:dbPathHint];
    }

    // 1. AppGroup / SystemGroup Containers matching safari (e.g. group.com.apple.safari used by defaultDatabaseURL)
    NSDictionary<NSString *, NSString *> *groupMap = scan_container_root(@"/var/mobile/Containers/Shared/AppGroup", nil, @"group");
    NSString *primarySafariGroup = groupMap[@"group.com.apple.safari"];
    if (primarySafariGroup.length > 0) {
        NSString *gp = [primarySafariGroup stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
        if ([fm fileExistsAtPath:gp]) [paths addObject:gp];
    }
    for (NSString *gid in groupMap) {
        if ([gid rangeOfString:@"safari" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            if (primarySafariGroup.length == 0) primarySafariGroup = groupMap[gid];
            NSString *gp = [groupMap[gid] stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
            if ([fm fileExistsAtPath:gp]) {
                [paths addObject:gp];
            }
        }
    }

    NSDictionary<NSString *, NSString *> *sysGroupMap = scan_container_root(@"/var/mobile/Containers/Shared/SystemGroup", nil, @"sysgroup");
    for (NSString *gid in sysGroupMap) {
        if ([gid rangeOfString:@"safari" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            NSString *gp = [sysGroupMap[gid] stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
            if ([fm fileExistsAtPath:gp]) {
                [paths addObject:gp];
            }
        }
    }

    // 2. MobileSafari App Data Container: Library/Safari/PerSitePreferences.db
    NSDictionary<NSString *, NSString *> *appMap = scan_container_root(@"/var/mobile/Containers/Data/Application", nil, @"app");
    NSString *safariAppContainer = appMap[@"com.apple.mobilesafari"];
    if (safariAppContainer.length > 0) {
        NSString *p = [safariAppContainer stringByAppendingPathComponent:@"Library/Safari/PerSitePreferences.db"];
        if ([fm fileExistsAtPath:p]) [paths addObject:p];
    }

    // 3. Shared /var/mobile/Library/Safari/PerSitePreferences.db
    NSString *sharedMobileSafariDB = @"/var/mobile/Library/Safari/PerSitePreferences.db";
    if ([fm fileExistsAtPath:sharedMobileSafariDB]) {
        [paths addObject:sharedMobileSafariDB];
    }

    if (paths.count == 0 && createFallbackIfEmpty) {
        if (is_safe_mobile_db_path(dbPathHint)) {
            NSString *safariDir = [dbPathHint stringByDeletingLastPathComponent];
            ensure_mobile_dir([safariDir stringByDeletingLastPathComponent]);
            ensure_mobile_dir(safariDir);
            [paths addObject:dbPathHint];
        }
        if (primarySafariGroup.length > 0) {
            ensure_mobile_dir([primarySafariGroup stringByAppendingPathComponent:@"Library"]);
            NSString *dir = [primarySafariGroup stringByAppendingPathComponent:@"Library/Safari"];
            ensure_mobile_dir(dir);
            [paths addObject:[dir stringByAppendingPathComponent:@"PerSitePreferences.db"]];
        }
        if (paths.count == 0) {
            if (safariAppContainer.length > 0) {
                ensure_mobile_dir([safariAppContainer stringByAppendingPathComponent:@"Library"]);
                NSString *dir = [safariAppContainer stringByAppendingPathComponent:@"Library/Safari"];
                ensure_mobile_dir(dir);
                [paths addObject:[dir stringByAppendingPathComponent:@"PerSitePreferences.db"]];
            }
            ensure_mobile_dir(@"/var/mobile/Library/Safari");
            [paths addObject:sharedMobileSafariDB];
        }
    }
    return paths.array;
}

static BOOL sqlite_table_exists(sqlite3 *db, const char *tableName) {
    const char *sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    BOOL exists = NO;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tableName, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            exists = YES;
        }
    }
    if (stmt) sqlite3_finalize(stmt);
    return exists;
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

static int cmd_safari_list(NSString *prefHint, NSString *dbPathHint) {
    NSArray<NSString *> *dbPaths = discover_safari_db_paths(NO, dbPathHint);
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
            ? "SELECT domain, preference, preference_value, COALESCE(CAST(timestamp AS TEXT), '') FROM preference_values ORDER BY domain ASC;"
            : "SELECT domain, preference, preference_value, '' FROM preference_values ORDER BY domain ASC;";
        sqlite3_stmt *rstmt = NULL;
        if (sqlite3_prepare_v2(db, rowSql, -1, &rstmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(rstmt) == SQLITE_ROW) {
                const unsigned char *dom = sqlite3_column_text(rstmt, 0);
                const unsigned char *prf = sqlite3_column_text(rstmt, 1);
                int val = sqlite3_column_int(rstmt, 2);
                const unsigned char *tsTxt = sqlite3_column_text(rstmt, 3);
                if (!dom || !prf) continue;
                NSString *domStr = [NSString stringWithUTF8String:(const char *)dom] ?: @"";
                NSString *prfStr = [NSString stringWithUTF8String:(const char *)prf] ?: @"";
                NSString *tsStr = tsTxt ? ([NSString stringWithUTF8String:(const char *)tsTxt] ?: @"") : @"";
                if (domStr.length > 0 && is_lockdown_pref_name(prfStr, prefHint)) {
                    [entries addObject:@{
                        @"domain": domStr,
                        @"preference": prfStr,
                        @"value": @(val),
                        @"timestamp": tsStr,
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

static int cmd_safari_set(NSString *domain, NSString *prefKey, int offVal, BOOL exclude, NSString *dbPathHint) {
    NSString *cleanDomain = [[domain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (cleanDomain.length == 0 || prefKey.length == 0) {
        print_json(@{@"ok": @NO, @"error": @"invalid_domain_or_key"});
        return 1;
    }

    NSArray<NSString *> *dbPaths = discover_safari_db_paths(YES, dbPathHint);
    NSMutableArray<NSString *> *updatedPaths = [NSMutableArray array];
    NSMutableArray<NSString *> *errors = [NSMutableArray array];
    NSString *tsNow = utc_timestamp_string();

    for (NSString *dbPath in dbPaths) {
        NSString *safariDir = [dbPath stringByDeletingLastPathComponent];
        if ([[safariDir lastPathComponent] isEqualToString:@"Safari"]) {
            ensure_mobile_dir([safariDir stringByDeletingLastPathComponent]);
        }
        ensure_mobile_dir(safariDir);

        sqlite3 *db = NULL;
        int rc = sqlite3_open_v2(dbPath.fileSystemRepresentation, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if (rc != SQLITE_OK || !db) {
            [errors addObject:[NSString stringWithFormat:@"open_failed:%@(%d)", dbPath, rc]];
            if (db) sqlite3_close(db);
            continue;
        }
        sqlite3_busy_timeout(db, 2500);

        // Initialize exact WBSPerSitePreferencesSQLiteStore schema (version 5 on iOS 16) ONLY if brand new
        if (!sqlite_table_exists(db, "preference_values")) {
            const char *initSql =
                "CREATE TABLE IF NOT EXISTS default_preferences (id INTEGER PRIMARY KEY AUTOINCREMENT, preference TEXT NOT NULL UNIQUE, default_value NUMERIC, sync_data BLOB NULL);"
                "CREATE TABLE IF NOT EXISTS preference_values (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, preference TEXT NOT NULL, preference_value NUMERIC, timestamp TEXT NULL, sync_data BLOB NULL, record_name TEXT NULL, UNIQUE(domain, preference));"
                "CREATE TABLE IF NOT EXISTS deleted_cloudkit_records (record_name TEXT NOT NULL UNIQUE, sync_data BLOB);"
                "PRAGMA user_version = 5;";
            (void)sqlite3_exec(db, initSql, NULL, NULL, NULL);
        }

        BOOL stepOk = YES;
        if (!exclude) {
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
        } else {
            // Remove case-mismatched duplicates for the same domain while preserving sync_data on exact match
            const char *cleanDupSql =
                "DELETE FROM preference_values WHERE LOWER(domain) = LOWER(?) AND domain != ? AND "
                "(preference = ? OR preference LIKE '%Lockdown%' OR preference LIKE '%CaptivePortal%');";
            sqlite3_stmt *cstmt = NULL;
            if (sqlite3_prepare_v2(db, cleanDupSql, -1, &cstmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(cstmt, 1, cleanDomain.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(cstmt, 2, cleanDomain.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(cstmt, 3, prefKey.UTF8String, -1, SQLITE_TRANSIENT);
                (void)sqlite3_step(cstmt);
            }
            if (cstmt) sqlite3_finalize(cstmt);

            BOOL hasTs = table_has_column(db, "preference_values", "timestamp");
            const char *upsertSql = hasTs
                ? "INSERT INTO preference_values (domain, preference, preference_value, timestamp) VALUES (?, ?, ?, ?) "
                  "ON CONFLICT(domain, preference) DO UPDATE SET domain = excluded.domain, preference = excluded.preference, "
                  "preference_value = excluded.preference_value, timestamp = excluded.timestamp;"
                : "INSERT INTO preference_values (domain, preference, preference_value) VALUES (?, ?, ?) "
                  "ON CONFLICT(domain, preference) DO UPDATE SET domain = excluded.domain, preference = excluded.preference, "
                  "preference_value = excluded.preference_value;";
            sqlite3_stmt *istmt = NULL;
            if (sqlite3_prepare_v2(db, upsertSql, -1, &istmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(istmt, 1, cleanDomain.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(istmt, 2, prefKey.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(istmt, 3, offVal);
                if (hasTs) {
                    sqlite3_bind_text(istmt, 4, tsNow.UTF8String, -1, SQLITE_TRANSIENT);
                }
                int sRc = sqlite3_step(istmt);
                if (sRc != SQLITE_DONE) {
                    stepOk = NO;
                    const char *emsg = sqlite3_errmsg(db);
                    [errors addObject:[NSString stringWithFormat:@"upsert_failed:%@:%s", dbPath, emsg ?: "err"]];
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

    // WebKit _WKSystemPreferences checks <containerPath>/System/Preferences/com.apple.WebKit.cpmconfig_ignore
    NSString *sysDir = [containerPath stringByAppendingPathComponent:@"System"];
    NSString *sysPrefsDir = [sysDir stringByAppendingPathComponent:@"Preferences"];
    ensure_mobile_dir(sysDir);
    ensure_mobile_dir(sysPrefsDir);

    NSString *libPrefsDir = [containerPath stringByAppendingPathComponent:@"Library/Preferences"];
    ensure_mobile_dir([containerPath stringByAppendingPathComponent:@"Library"]);
    ensure_mobile_dir(libPrefsDir);

    NSString *sysIgnoreFile = [sysPrefsDir stringByAppendingPathComponent:@"com.apple.WebKit.cpmconfig_ignore"];
    NSString *legacyIgnoreFile = [libPrefsDir stringByAppendingPathComponent:@"com.apple.WebKit.cpmconfig_ignore"];

    NSError *err = nil;
    if (ignore) {
        NSData *marker = [NSData data];
        if (![marker writeToFile:sysIgnoreFile options:NSDataWritingAtomic error:&err]) {
            print_json(@{@"ok": @NO, @"error": err.localizedDescription ?: @"write_cpmconfig_failed"});
            return 1;
        }
        chmod(sysIgnoreFile.fileSystemRepresentation, 0644);
        fix_mobile_owner(sysIgnoreFile);
    } else {
        if ([fm fileExistsAtPath:sysIgnoreFile]) {
            [fm removeItemAtPath:sysIgnoreFile error:nil];
        }
        if ([fm fileExistsAtPath:legacyIgnoreFile]) {
            [fm removeItemAtPath:legacyIgnoreFile error:nil];
        }
    }

    // Sync container plist: mark WebKitCaptivePortalModeAlertShown=YES so iOS Settings -> Lockdown Mode also lists the app,
    // plus optional deep LDMGlobalEnabled=NO override.
    NSString *appPlistPath = [libPrefsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist", bundleId]];
    NSMutableDictionary *dict = [[NSDictionary dictionaryWithContentsOfFile:appPlistPath] mutableCopy];
    BOOL plistChanged = NO;
    if (ignore) {
        if (!dict) dict = [NSMutableDictionary dictionary];
        if (![dict[@"WebKitCaptivePortalModeAlertShown"] boolValue]) {
            dict[@"WebKitCaptivePortalModeAlertShown"] = @YES;
            plistChanged = YES;
        }
        if (deep) {
            dict[@"LDMGlobalEnabled"] = @NO;
            plistChanged = YES;
        } else if (dict[@"LDMGlobalEnabled"] != nil) {
            [dict removeObjectForKey:@"LDMGlobalEnabled"];
            plistChanged = YES;
        }
    } else if (dict && dict[@"LDMGlobalEnabled"] != nil) {
        [dict removeObjectForKey:@"LDMGlobalEnabled"];
        plistChanged = YES;
    }

    if (plistChanged && dict) {
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

    notify_post("WKCaptivePortalModeContainerConfigurationChanged");
    notify_post("com.apple.WebKit.cpmconfig");

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
            BOOL isAppPath = [p hasPrefix:@"/var/containers/Bundle/Application/"] ||
                             [p hasPrefix:@"/private/var/containers/Bundle/Application/"] ||
                             [p hasPrefix:@"/Applications/"] ||
                             [p hasPrefix:@"/System/Applications/"] ||
                             [p hasPrefix:@"/System/Cryptexes/"] ||
                             ([p hasPrefix:@"/private/preboot/"] && [p containsString:@"/Applications/"]);
            if (isAppPath &&
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

// MARK: - iOS 16+ Developer Mode Control (AMFI XPC + AMFIShowOverridePath)

typedef BOOL (*LBAMFIBoolFn)(void);
typedef void *(*LBXPCConnCreateFn)(const char *, dispatch_queue_t _Nullable, uint64_t);
typedef void (*LBXPCSetHandlerFn)(void *, void *);
typedef void (*LBXPCVoidConnFn)(void *);
typedef void *(*LBXPCSendSyncFn)(void *, void *);
typedef void *(*LBXPCDictGetValFn)(void *, const char *);
typedef void *(*LBCFXPCCreateMsgFn)(CFTypeRef);
typedef CFTypeRef (*LBCFXPCCreateObjFn)(void *);
typedef void (^LBXPCEventBlock)(void * _Nullable);

static void *amfi_framework_handle(void) {
    static void *handle = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handle = dlopen("/System/Library/PrivateFrameworks/AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity", RTLD_NOW);
    });
    return handle;
}

static NSString *resolve_amfi_override_path(void) {
    void *h = amfi_framework_handle();
    if (h) {
        CFTypeRef *pSym = (CFTypeRef *)dlsym(h, "AMFIShowOverridePath");
        if (pSym && *pSym && CFGetTypeID(*pSym) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)(*pSym);
            if (s.length > 0) return s;
        }
    }
    return @"";
}

static NSDictionary * _Nullable amfi_send_xpc_action(int action, BOOL * _Nullable xpcAvailableOut) {
    LBXPCConnCreateFn fnCreate = (LBXPCConnCreateFn)dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
    LBXPCSetHandlerFn fnSetHandler = (LBXPCSetHandlerFn)dlsym(RTLD_DEFAULT, "xpc_connection_set_event_handler");
    LBXPCVoidConnFn fnResume = (LBXPCVoidConnFn)dlsym(RTLD_DEFAULT, "xpc_connection_resume");
    LBXPCVoidConnFn fnCancel = (LBXPCVoidConnFn)dlsym(RTLD_DEFAULT, "xpc_connection_cancel");
    LBXPCSendSyncFn fnSendSync = (LBXPCSendSyncFn)dlsym(RTLD_DEFAULT, "xpc_connection_send_message_with_reply_sync");
    LBXPCDictGetValFn fnDictGet = (LBXPCDictGetValFn)dlsym(RTLD_DEFAULT, "xpc_dictionary_get_value");
    LBCFXPCCreateMsgFn fnCreateMsg = (LBCFXPCCreateMsgFn)dlsym(RTLD_DEFAULT, "_CFXPCCreateXPCMessageWithCFObject");
    LBCFXPCCreateObjFn fnCreateObj = (LBCFXPCCreateObjFn)dlsym(RTLD_DEFAULT, "_CFXPCCreateCFObjectFromXPCMessage");

    if (!fnCreate || !fnSetHandler || !fnResume || !fnSendSync || !fnDictGet || !fnCreateMsg || !fnCreateObj) {
        if (xpcAvailableOut) *xpcAvailableOut = NO;
        return nil;
    }
    if (xpcAvailableOut) *xpcAvailableOut = YES;

    void *conn = fnCreate("com.apple.amfi.xpc", NULL, 0);
    if (!conn) return nil;

    LBXPCEventBlock emptyBlock = ^(__unused void *ev) {};
    fnSetHandler(conn, (__bridge void *)emptyBlock);
    fnResume(conn);

    NSDictionary *req = @{@"action": @(action)};
    void *msg = fnCreateMsg((__bridge CFDictionaryRef)req);
    NSDictionary *resultDict = nil;
    if (msg) {
        void *reply = fnSendSync(conn, msg);
        if (reply) {
            void *cfReply = fnDictGet(reply, "cfreply");
            if (cfReply) {
                CFTypeRef cfObj = fnCreateObj(cfReply);
                if (cfObj) {
                    id bridged = CFBridgingRelease(cfObj);
                    if ([bridged isKindOfClass:[NSDictionary class]]) {
                        resultDict = (NSDictionary *)bridged;
                    }
                }
            }
        }
    }
    if (fnCancel) fnCancel(conn);
    return resultDict;
}

static BOOL reveal_developer_mode_menu(NSString * _Nullable * _Nullable errOut) {
    NSString *overridePath = resolve_amfi_override_path();
    if (overridePath.length == 0 ||
        ([overridePath rangeOfString:@".."].location != NSNotFound) ||
        !( [overridePath hasPrefix:@"/var/"] || [overridePath hasPrefix:@"/private/var/"] )) {
        if (errOut) *errOut = @"未解析到有效的 AMFIShowOverridePath";
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *parentDir = [overridePath stringByDeletingLastPathComponent];
    if (parentDir.length > 0 && ![fm fileExistsAtPath:parentDir]) {
        [fm createDirectoryAtPath:parentDir
      withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions: @(0755)}
                            error:nil];
    }

    uint64_t val = 1;
    NSData *payload = [NSData dataWithBytes:&val length:sizeof(val)];
    NSError *wErr = nil;
    BOOL ok = [payload writeToFile:overridePath options:NSDataWritingAtomic error:&wErr];
    if (!ok) {
        ok = [fm createFileAtPath:overridePath
                         contents:payload
                       attributes:@{NSFilePosixPermissions: @(0444)}];
    }
    if (ok) {
        chmod(overridePath.fileSystemRepresentation, 0444);
        notify_post("security.mac.amfi.developer_mode_status.changed");
    } else if (errOut) {
        *errOut = wErr.localizedDescription ?: @"写入 AMFIShowOverridePath 失败";
    }
    return ok;
}

static NSDictionary *query_developer_mode_state_dict(void) {
    void *h = amfi_framework_handle();
    BOOL enabled = NO;
    BOOL menuVisible = NO;

    if (h) {
        LBAMFIBoolFn fnIsEnabled = (LBAMFIBoolFn)dlsym(h, "AMFIIsDeveloperModeEnabled");
        LBAMFIBoolFn fnStatus = (LBAMFIBoolFn)dlsym(h, "amfi_developer_mode_status");
        LBAMFIBoolFn fnShowMenu = (LBAMFIBoolFn)dlsym(h, "AMFIShouldShowDeveloperModeSettings");
        if (fnIsEnabled && fnIsEnabled()) enabled = YES;
        if (fnStatus && fnStatus()) enabled = YES;
        if (fnShowMenu && fnShowMenu()) menuVisible = YES;
    }

    NSString *overridePath = resolve_amfi_override_path();
    if (overridePath.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:overridePath]) {
        menuVisible = YES;
    }

    BOOL xpcAvail = NO;
    NSDictionary *reply = amfi_send_xpc_action(2, &xpcAvail); // kAMFIActionStatus = 2
    BOOL armed = NO;
    BOOL writable = YES;
    BOOL xpcSuccess = NO;

    if (reply && [reply[@"success"] isKindOfClass:[NSNumber class]] && [reply[@"success"] boolValue]) {
        xpcSuccess = YES;
        if ([reply[@"status"] isKindOfClass:[NSNumber class]]) {
            enabled = enabled || [reply[@"status"] boolValue];
        }
        if ([reply[@"armed"] isKindOfClass:[NSNumber class]]) {
            armed = [reply[@"armed"] boolValue];
        }
        if ([reply[@"writable"] isKindOfClass:[NSNumber class]]) {
            writable = [reply[@"writable"] boolValue];
        }
    }
    if (enabled || armed) {
        menuVisible = YES;
    }

    return @{
        @"ok": @YES,
        @"enabled": @(enabled),
        @"armed": @(armed),
        @"writable": @(writable),
        @"menuVisible": @(menuVisible),
        @"xpcAvailable": @(xpcAvail && xpcSuccess),
        @"overridePath": overridePath ?: @""
    };
}

static int cmd_devmode_status(void) {
    print_json(query_developer_mode_state_dict());
    return 0;
}

static int cmd_devmode_reveal(void) {
    NSString *err = nil;
    BOOL revealed = reveal_developer_mode_menu(&err);
    NSMutableDictionary *st = [query_developer_mode_state_dict() mutableCopy];
    st[@"ok"] = @(revealed);
    if (!revealed && err.length > 0) {
        st[@"error"] = err;
    }
    print_json(st);
    return revealed ? 0 : 1;
}

static int cmd_devmode_arm(void) {
    NSString *revErr = nil;
    BOOL revealed = reveal_developer_mode_menu(&revErr);

    NSDictionary *before = query_developer_mode_state_dict();
    if ([before[@"enabled"] boolValue]) {
        NSMutableDictionary *res = [before mutableCopy];
        res[@"ok"] = @YES;
        res[@"alreadyEnabled"] = @YES;
        print_json(res);
        return 0;
    }

    BOOL xpcAvail = NO;
    NSDictionary *armReply = amfi_send_xpc_action(0, &xpcAvail); // kAMFIActionArm = 0
    BOOL armOk = armReply && [armReply[@"success"] isKindOfClass:[NSNumber class]] && [armReply[@"success"] boolValue];

    NSMutableDictionary *after = [query_developer_mode_state_dict() mutableCopy];
    after[@"ok"] = @(armOk);
    after[@"alreadyEnabled"] = @NO;
    after[@"armed"] = @(armOk || [after[@"armed"] boolValue]);
    after[@"revealedMenu"] = @(revealed);
    if (!armOk) {
        NSString *errMsg = [armReply[@"error"] isKindOfClass:[NSString class]] ? armReply[@"error"] : @"";
        if (errMsg.length == 0) {
            errMsg = ![before[@"writable"] boolValue]
                ? @"当前系统锁定模式限制写入 SEP 开发者状态（已为您显示设置入口；如需首次激活，可先临时关闭锁定模式→开启开发者模式→再重新开启锁定模式）"
                : @"调用 com.apple.amfi.xpc 预开启失败";
        }
        after[@"error"] = errMsg;
    }
    print_json(after);
    return armOk ? 0 : 1;
}

static int cmd_devmode_disable(void) {
    BOOL xpcAvail = NO;
    NSDictionary *disReply = amfi_send_xpc_action(1, &xpcAvail); // kAMFIActionDisable = 1
    BOOL disOk = disReply && [disReply[@"success"] isKindOfClass:[NSNumber class]] && [disReply[@"success"] boolValue];
    NSMutableDictionary *after = [query_developer_mode_state_dict() mutableCopy];
    after[@"ok"] = @(disOk);
    if (!disOk) {
        after[@"error"] = @"关闭开发者模式失败";
    }
    print_json(after);
    return disOk ? 0 : 1;
}

static int cmd_reboot_device(void) {
    dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
    Class fbsCls = NSClassFromString(@"FBSSystemService");
    SEL sharedSel = NSSelectorFromString(@"sharedService");
    SEL rebootSel = NSSelectorFromString(@"reboot");
    if (fbsCls && [fbsCls respondsToSelector:sharedSel]) {
        id svc = ((id (*)(id, SEL))objc_msgSend)(fbsCls, sharedSel);
        if (svc && [svc respondsToSelector:rebootSel]) {
            print_json(@{@"ok": @YES, @"rebooting": @YES});
            fflush(stdout);
            ((void (*)(id, SEL))objc_msgSend)(svc, rebootSel);
            sleep(1);
            return 0;
        }
    }
    print_json(@{@"ok": @NO, @"error": @"FBSSystemService_unavailable"});
    return 1;
}

// MARK: - WQGuard-Inspired Strictly Read-Only Sideload / Mach-O / Container Audit (iOS 16.4.1)

#ifndef O_CLOEXEC
#define O_CLOEXEC 0x1000000
#endif

static NSData * _Nullable read_regular_file_nofollow(NSString *path, size_t maxBytes) {
    if (path.length == 0) return nil;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        return nil;
    }
    size_t toRead = (size_t)st.st_size;
    if (toRead > maxBytes) toRead = maxBytes;
    NSMutableData *buf = [NSMutableData dataWithLength:toRead];
    if (!buf) {
        close(fd);
        return nil;
    }
    ssize_t got = read(fd, buf.mutableBytes, toRead);
    close(fd);
    if (got <= 0) return nil;
    buf.length = (NSUInteger)got;
    return buf;
}

static NSDictionary * _Nullable inspect_macho_readonly(NSString *execPath) {
    if (execPath.length == 0) return nil;
    int fd = open(execPath.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 32) {
        close(fd);
        return nil;
    }
    uint64_t fileSize = (uint64_t)st.st_size;

    uint8_t fatBuf[4096];
    ssize_t headN = pread(fd, fatBuf, sizeof(fatBuf), 0);
    if (headN < 32) {
        close(fd);
        return nil;
    }

    uint64_t sliceOffset = 0;
    uint32_t rawMagic = *(const uint32_t *)fatBuf;
    if (rawMagic == FAT_CIGAM || rawMagic == FAT_MAGIC) {
        const struct fat_header *fh = (const struct fat_header *)fatBuf;
        uint32_t nfat = (rawMagic == FAT_CIGAM) ? ntohl(fh->nfat_arch) : fh->nfat_arch;
        if (nfat > 32) nfat = 32;
        for (uint32_t i = 0; i < nfat; i++) {
            size_t off = sizeof(struct fat_header) + (size_t)i * sizeof(struct fat_arch);
            if (off + sizeof(struct fat_arch) > (size_t)headN) break;
            const struct fat_arch *fa = (const struct fat_arch *)(fatBuf + off);
            cpu_type_t cpu = (rawMagic == FAT_CIGAM) ? (cpu_type_t)ntohl((uint32_t)fa->cputype) : fa->cputype;
            uint32_t archOff = (rawMagic == FAT_CIGAM) ? ntohl(fa->offset) : fa->offset;
            if (cpu == CPU_TYPE_ARM64 && (uint64_t)archOff + 32 <= fileSize) {
                sliceOffset = archOff;
                break;
            }
        }
    }

    size_t hdrCap = 65536;
    NSMutableData *hdrData = [NSMutableData dataWithLength:hdrCap];
    ssize_t sliceN = pread(fd, hdrData.mutableBytes, hdrCap, (off_t)sliceOffset);
    if (sliceN < (ssize_t)sizeof(struct mach_header_64)) {
        close(fd);
        return nil;
    }

    const uint8_t *base = (const uint8_t *)hdrData.bytes;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
    if (mh->magic != MH_MAGIC_64) {
        close(fd);
        return nil;
    }

    uint32_t ncmds = mh->ncmds;
    if (ncmds > 4096) ncmds = 4096;
    size_t maxCmdEnd = sizeof(struct mach_header_64) + (size_t)mh->sizeofcmds;
    if (maxCmdEnd > (size_t)sliceN) maxCmdEnd = (size_t)sliceN;

    BOOL encrypted = NO;
    uint32_t csOff = 0, csSize = 0;
    uint32_t strOff = 0, strSize = 0;
    NSMutableArray<NSString *> *dylibs = [NSMutableArray array];

    size_t cur = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < ncmds && cur + sizeof(struct load_command) <= maxCmdEnd; i++) {
        const struct load_command *lc = (const struct load_command *)(base + cur);
        if (lc->cmdsize < sizeof(struct load_command) || cur + lc->cmdsize > maxCmdEnd) break;

        if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *enc = (const struct encryption_info_command_64 *)lc;
            if (enc->cryptid != 0) encrypted = YES;
        } else if (lc->cmd == LC_CODE_SIGNATURE && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cs = (const struct linkedit_data_command *)lc;
            csOff = cs->dataoff;
            csSize = cs->datasize;
        } else if (lc->cmd == LC_SYMTAB && lc->cmdsize >= sizeof(struct symtab_command)) {
            const struct symtab_command *sym = (const struct symtab_command *)lc;
            strOff = sym->stroff;
            strSize = sym->strsize;
        } else if ((lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) &&
                   lc->cmdsize >= sizeof(struct dylib_command)) {
            const struct dylib_command *dl = (const struct dylib_command *)lc;
            uint32_t nameOff = dl->dylib.name.offset;
            if (nameOff >= sizeof(struct dylib_command) && nameOff < lc->cmdsize) {
                const char *s = (const char *)lc + nameOff;
                size_t maxLen = lc->cmdsize - nameOff;
                size_t actualLen = strnlen(s, maxLen);
                NSString *ds = [[NSString alloc] initWithBytes:s length:actualLen encoding:NSUTF8StringEncoding];
                if (ds.length > 0) [dylibs addObject:ds];
            }
        }
        cur += lc->cmdsize;
    }

    NSDictionary *entitlements = @{};
    if (csOff > 0 && csSize >= 12 && csSize <= 2 * 1024 * 1024 && sliceOffset + csOff + csSize <= fileSize) {
        NSMutableData *csData = [NSMutableData dataWithLength:csSize];
        if (csData && pread(fd, csData.mutableBytes, csSize, (off_t)(sliceOffset + csOff)) == (ssize_t)csSize) {
            const uint8_t *cb = (const uint8_t *)csData.bytes;
            uint32_t sbMagic = ntohl(*(const uint32_t *)cb);
            uint32_t sbLen = ntohl(*(const uint32_t *)(cb + 4));
            uint32_t sbCount = ntohl(*(const uint32_t *)(cb + 8));
            if (sbMagic == 0xFADE0CC0 && sbLen <= csSize && sbCount <= 64) {
                for (uint32_t j = 0; j < sbCount; j++) {
                    size_t idxOff = 12 + (size_t)j * 8;
                    if (idxOff + 8 > csSize) break;
                    uint32_t slotType = ntohl(*(const uint32_t *)(cb + idxOff));
                    uint32_t blobOff = ntohl(*(const uint32_t *)(cb + idxOff + 4));
                    if (blobOff + 8 > csSize) continue;
                    uint32_t subMagic = ntohl(*(const uint32_t *)(cb + blobOff));
                    uint32_t subLen = ntohl(*(const uint32_t *)(cb + blobOff + 4));
                    if ((slotType == 5 || subMagic == 0xFADE7171) && subLen >= 8 && blobOff + subLen <= csSize) {
                        NSData *xmlData = [NSData dataWithBytes:(cb + blobOff + 8) length:(subLen - 8)];
                        id parsed = [NSPropertyListSerialization propertyListWithData:xmlData
                                                                             options:NSPropertyListImmutable
                                                                              format:NULL
                                                                               error:NULL];
                        if ([parsed isKindOfClass:[NSDictionary class]]) {
                            entitlements = (NSDictionary *)parsed;
                        }
                        break;
                    }
                }
            }
        }
    }

    BOOL usesPasteboard = NO;
    if (!encrypted && strOff > 0 && strSize > 0 && strSize <= 4 * 1024 * 1024 && sliceOffset + strOff + strSize <= fileSize) {
        NSMutableData *symData = [NSMutableData dataWithLength:strSize];
        if (symData && pread(fd, symData.mutableBytes, strSize, (off_t)(sliceOffset + strOff)) == (ssize_t)strSize) {
            if (memmem(symData.bytes, strSize, "UIPasteboard", 12) != NULL ||
                memmem(symData.bytes, strSize, "generalPasteboard", 17) != NULL) {
                usesPasteboard = YES;
            }
        }
    }

    close(fd);
    return @{
        @"encrypted": @(encrypted),
        @"dylibs": dylibs,
        @"entitlements": entitlements,
        @"usesPasteboard": @(usesPasteboard)
    };
}

static BOOL matches_impersonated_wallet_brand(NSString *name, NSString *bundleId) {
    NSString *lowerName = [name lowercaseString] ?: @"";
    NSString *lowerBid = [bundleId lowercaseString] ?: @"";
    NSArray<NSString *> *walletBrands = @[
        @"metamask", @"trust wallet", @"trustwallet", @"imtoken", @"tokenpocket",
        @"phantom wallet", @"onekey", @"ledger live", @"bitget wallet", @"okx wallet"
    ];
    for (NSString *b in walletBrands) {
        if ([lowerName containsString:b] || [lowerBid containsString:[b stringByReplacingOccurrencesOfString:@" " withString:@""]]) {
            return YES;
        }
    }
    return NO;
}

static int cmd_security_audit(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSDictionary *> *findings = [NSMutableArray array];
    NSInteger scannedApps = 0;
    NSInteger nonAppStoreCount = 0;
    NSInteger highCount = 0;
    NSInteger mediumCount = 0;

    // 1. Check Fake Supervision / Rogue MDM CloudConfigurationDetails.plist (WQGuard FAKE_SUPERVISION_MDM)
    NSString *cloudCfgPath = @"/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/CloudConfigurationDetails.plist";
    NSData *cloudData = read_regular_file_nofollow(cloudCfgPath, 256 * 1024);
    if (cloudData) {
        id cloudPlist = [NSPropertyListSerialization propertyListWithData:cloudData options:0 format:NULL error:NULL];
        if ([cloudPlist isKindOfClass:[NSDictionary class]] && [cloudPlist[@"IsSupervised"] boolValue]) {
            NSString *org = [cloudPlist[@"OrganizationName"] isKindOfClass:[NSString class]] ? cloudPlist[@"OrganizationName"] : @"未注明机构";
            highCount++;
            [findings addObject:@{
                @"id": @"FAKE_SUPERVISION_MDM",
                @"severity": @"high",
                @"category": @"系统监管篡改",
                @"title": @"设备当前处于「受监管模式 (Supervised)」",
                @"target": org,
                @"detail": @"若非您本人配置的企业/学校监管或延迟 OTA，恶意描述文件或越权工具可能借此下发全局证书或锁机策略。"
            }];
        }
    }

    // 2. Check Shared AppGroup Caches for Escaping Symlinks (WQGuard ESCAPING_SYMLINK, lstat non-following)
    NSString *appGroupRoot = @"/var/mobile/Containers/Shared/AppGroup";
    NSArray<NSString *> *groupUUIDs = [fm contentsOfDirectoryAtPath:appGroupRoot error:nil];
    for (NSString *guuid in groupUUIDs) {
        NSString *gContainer = [appGroupRoot stringByAppendingPathComponent:guuid];
        NSString *cachesDir = [gContainer stringByAppendingPathComponent:@"Library/Caches"];
        NSArray<NSString *> *cacheEntries = [fm contentsOfDirectoryAtPath:cachesDir error:nil];
        for (NSString *entry in cacheEntries) {
            NSString *entryPath = [cachesDir stringByAppendingPathComponent:entry];
            struct stat lst;
            if (lstat(entryPath.fileSystemRepresentation, &lst) == 0 && S_ISLNK(lst.st_mode)) {
                char linkBuf[PATH_MAX];
                ssize_t len = readlink(entryPath.fileSystemRepresentation, linkBuf, sizeof(linkBuf) - 1);
                if (len > 0) {
                    linkBuf[len] = '\0';
                    NSString *target = [NSString stringWithUTF8String:linkBuf] ?: @"";
                    if ([target hasPrefix:@"/"] &&
                        ![target hasPrefix:gContainer] &&
                        ![target hasPrefix:[@"/private" stringByAppendingString:gContainer]]) {
                        highCount++;
                        [findings addObject:@{
                            @"id": [NSString stringWithFormat:@"SYMLINK_%@_%@", guuid, entry],
                            @"severity": @"high",
                            @"category": @"跨沙盒逃逸软链",
                            @"title": @"共享容器缓存发现越界符号链接",
                            @"target": [NSString stringWithFormat:@"%@ -> %@", entryPath, target],
                            @"detail": @"共享容器 Library/Caches 内存在指向容器外部的符号链接，常见于沙盒逃逸残留。"
                        }];
                    }
                }
            }
        }
    }

    // 3. Static Mach-O + CSBlob Entitlement + Dylib Audit on Installed Apps
    NSString *bundleRoot = @"/var/containers/Bundle/Application";
    NSArray<NSString *> *bundleUUIDs = [fm contentsOfDirectoryAtPath:bundleRoot error:nil];
    for (NSString *buuid in bundleUUIDs) {
        NSString *uuidDir = [bundleRoot stringByAppendingPathComponent:buuid];
        NSArray<NSString *> *subItems = [fm contentsOfDirectoryAtPath:uuidDir error:nil];
        NSString *appBundlePath = nil;
        BOOL hasTrollMarker = NO;
        for (NSString *it in subItems) {
            if ([it hasSuffix:@".app"]) {
                appBundlePath = [uuidDir stringByAppendingPathComponent:it];
            } else if ([it hasPrefix:@"_TrollStore"]) {
                hasTrollMarker = YES;
            }
        }
        if (!appBundlePath) continue;

        NSData *infoData = read_regular_file_nofollow([appBundlePath stringByAppendingPathComponent:@"Info.plist"], 512 * 1024);
        if (!infoData) continue;
        NSDictionary *info = [NSPropertyListSerialization propertyListWithData:infoData options:0 format:NULL error:NULL];
        if (![info isKindOfClass:[NSDictionary class]]) continue;

        NSString *bid = [info[@"CFBundleIdentifier"] isKindOfClass:[NSString class]] ? info[@"CFBundleIdentifier"] : @"";
        NSString *execName = [info[@"CFBundleExecutable"] isKindOfClass:[NSString class]] ? info[@"CFBundleExecutable"] : @"";
        NSString *dispName = [info[@"CFBundleDisplayName"] isKindOfClass:[NSString class]] ? info[@"CFBundleDisplayName"] :
                             ([info[@"CFBundleName"] isKindOfClass:[NSString class]] ? info[@"CFBundleName"] : bid);
        if (bid.length == 0 || execName.length == 0) continue;
        scannedApps++;

        // Skip our own tool and official TrollStore host
        if ([bid isEqualToString:@"com.lili.lockdownwhitelist"] ||
            [bid isEqualToString:@"com.opa334.TrollStore"]) {
            continue;
        }

        NSString *execPath = [appBundlePath stringByAppendingPathComponent:execName];
        NSDictionary *macho = inspect_macho_readonly(execPath);
        BOOL encrypted = [macho[@"encrypted"] boolValue];
        BOOL hasReceipt = [fm fileExistsAtPath:[uuidDir stringByAppendingPathComponent:@"StoreKit/receipt"]] ||
                          [fm fileExistsAtPath:[appBundlePath stringByAppendingPathComponent:@"SC_Info"]];
        BOOL hasMobileProvision = [fm fileExistsAtPath:[appBundlePath stringByAppendingPathComponent:@"embedded.mobileprovision"]];

        NSString *channel = @"AppStore";
        if (hasTrollMarker) {
            channel = @"TrollStore";
        } else if (!encrypted && (!hasReceipt || hasMobileProvision)) {
            channel = @"Sideload";
        }
        if ([channel isEqualToString:@"AppStore"]) continue;
        nonAppStoreCount++;

        NSDictionary *ents = [macho[@"entitlements"] isKindOfClass:[NSDictionary class]] ? macho[@"entitlements"] : @{};
        NSArray<NSString *> *dylibs = [macho[@"dylibs"] isKindOfClass:[NSArray class]] ? macho[@"dylibs"] : @[];
        BOOL usesPasteboard = [macho[@"usesPasteboard"] boolValue];

        // 3a. Brand Impersonation / Fake Web3 Wallet Drainer (HIGH)
        if (matches_impersonated_wallet_brand(dispName, bid)) {
            highCount++;
            [findings addObject:@{
                @"id": [NSString stringWithFormat:@"WALLET_%@", bid],
                @"severity": @"high",
                @"category": @"疑似仿冒钱包",
                @"title": [NSString stringWithFormat:@"%@ (%@)", dispName, channel],
                @"target": bid,
                @"detail": @"非 App Store 渠道安装的加密钱包应用，极易为二次打包窃取助记词/私钥的 Web3 盗币木马，请立即核实安装包来源！"
            }];
        }

        // 3b. Private TCC Prompt Bypass Entitlements (HIGH)
        id tccAllow = ents[@"com.apple.private.tcc.allow"];
        BOOL hasTccBypass = ([tccAllow isKindOfClass:[NSArray class]] && [(NSArray *)tccAllow count] > 0) ||
                            [ents[@"com.apple.private.tcc.allow-prompting-bypass"] boolValue];
        if (hasTccBypass) {
            highCount++;
            [findings addObject:@{
                @"id": [NSString stringWithFormat:@"TCC_%@", bid],
                @"severity": @"high",
                @"category": @"TCC 隐私绕过",
                @"title": [NSString stringWithFormat:@"%@ (%@)", dispName, channel],
                @"target": bid,
                @"detail": @"声明 com.apple.private.tcc.allow 私有免弹窗权限，可静默跳过 iOS 授权弹窗访问相册、麦克风、相机或通讯录。"
            }];
        }

        // 3c. Unsandboxed / Root Spawning Privileges on TrollStore / Sideload Apps (MEDIUM)
        NSMutableArray<NSString *> *privTags = [NSMutableArray array];
        if ([ents[@"com.apple.private.security.no-sandbox"] boolValue]) [privTags addObject:@"no-sandbox(无沙盒)"];
        if ([ents[@"com.apple.private.persona-mgmt"] boolValue]) [privTags addObject:@"persona-mgmt(Root派生)"];
        if ([ents[@"platform-application"] boolValue]) [privTags addObject:@"platform-application(平台特权)"];
        if (privTags.count > 0) {
            mediumCount++;
            [findings addObject:@{
                @"id": [NSString stringWithFormat:@"PRIV_%@", bid],
                @"severity": @"medium",
                @"category": @"巨魔特权审计",
                @"title": [NSString stringWithFormat:@"%@ (%@)", dispName, channel],
                @"target": bid,
                @"detail": [NSString stringWithFormat:@"包含高权限签名：%@。系统增强工具常见，若为普通游戏/娱乐软件请警惕越权窃密。",
                            [privTags componentsJoinedByString:@"、"]]
            }];
        }

        // 3d. Injected Hook Frameworks / Repackaged Dylibs (MEDIUM)
        NSMutableArray<NSString *> *hookNames = [NSMutableArray array];
        NSArray<NSString *> *dylibDirItems = [fm contentsOfDirectoryAtPath:[appBundlePath stringByAppendingPathComponent:@"Dylibs"] error:nil];
        for (NSString *d in dylibDirItems) {
            if ([d hasSuffix:@".dylib"]) [hookNames addObject:d];
        }
        for (NSString *dl in dylibs) {
            NSString *lowerDl = [dl lowercaseString];
            if ([lowerDl containsString:@"substrate"] ||
                [lowerDl containsString:@"ellekit"] ||
                [lowerDl containsString:@"libhooker"] ||
                [lowerDl containsString:@"substitute"] ||
                [lowerDl containsString:@"/dylibs/"]) {
                [hookNames addObject:[dl lastPathComponent]];
            }
        }
        if (hookNames.count > 0) {
            mediumCount++;
            [findings addObject:@{
                @"id": [NSString stringWithFormat:@"HOOK_%@", bid],
                @"severity": @"medium",
                @"category": @"重打包注入库",
                @"title": [NSString stringWithFormat:@"%@ (%@)", dispName, channel],
                @"target": bid,
                @"detail": [NSString stringWithFormat:@"检测到注入动态库/Hook 组件（%@），常见于去广告或改版 IPA，请确认无第三方偷跑脚本。",
                            [hookNames componentsJoinedByString:@", "]]
            }];
        }

        // 3e. Persistent Background Keep-Alive + Pasteboard Access Tuple (MEDIUM)
        NSArray *bgModes = [info[@"UIBackgroundModes"] isKindOfClass:[NSArray class]] ? info[@"UIBackgroundModes"] : @[];
        BOOL persistentBg = [bgModes containsObject:@"audio"] || [bgModes containsObject:@"location"] || [bgModes containsObject:@"voip"];
        if (persistentBg && usesPasteboard) {
            mediumCount++;
            [findings addObject:@{
                @"id": [NSString stringWithFormat:@"CLIP_%@", bid],
                @"severity": @"medium",
                @"category": @"后台剪贴板能力",
                @"title": [NSString stringWithFormat:@"%@ (%@)", dispName, channel],
                @"target": bid,
                @"detail": @"非 App Store 应用同时具备后台保活模式（音视频/定位/VoIP）与 UIPasteboard 剪贴板读取符号，建议在系统设置中将其「从其他 App 粘贴」设为询问或拒绝。"
            }];
        }
    }

    print_json(@{
        @"ok": @YES,
        @"scannedApps": @(scannedApps),
        @"nonAppStoreApps": @(nonAppStoreCount),
        @"highCount": @(highCount),
        @"mediumCount": @(mediumCount),
        @"findings": findings
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
            NSString *dbHint = (argc >= 4) ? [NSString stringWithUTF8String:argv[3]] : @"";
            return cmd_safari_list(hint, dbHint);
        }
        if ([cmd isEqualToString:@"--safari-set"]) {
            if (argc < 6) {
                print_json(@{@"ok": @NO, @"error": @"usage: --safari-set <domain> <prefKey> <offVal> <0|1> [dbPathHint]"});
                return 2;
            }
            NSString *dom = [NSString stringWithUTF8String:argv[2]];
            NSString *key = [NSString stringWithUTF8String:argv[3]];
            int offVal = atoi(argv[4]);
            BOOL excl = atoi(argv[5]) != 0;
            NSString *dbHint = (argc >= 7) ? [NSString stringWithUTF8String:argv[6]] : @"";
            return cmd_safari_set(dom, key, offVal, excl, dbHint);
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
        if ([cmd isEqualToString:@"--security-audit"]) {
            return cmd_security_audit();
        }
        if ([cmd isEqualToString:@"--devmode-status"]) {
            return cmd_devmode_status();
        }
        if ([cmd isEqualToString:@"--devmode-reveal"]) {
            return cmd_devmode_reveal();
        }
        if ([cmd isEqualToString:@"--devmode-arm"]) {
            return cmd_devmode_arm();
        }
        if ([cmd isEqualToString:@"--devmode-disable"]) {
            return cmd_devmode_disable();
        }
        if ([cmd isEqualToString:@"--reboot"]) {
            return cmd_reboot_device();
        }

        print_json(@{@"ok": @NO, @"error": @"unknown_subcommand"});
        return 2;
    }
}
