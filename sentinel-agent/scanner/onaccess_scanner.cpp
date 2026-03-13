/*
 * sentinel-agent/scanner/onaccess_scanner.cpp
 * On-access file scanning implementation.
 *
 * Listens for minifilter CREATE/WRITE events and triggers YARA scans.
 * Uses a SHA-256-keyed cache with a configurable TTL to avoid redundant
 * rescans of the same file content.
 *
 * P8-T2: On-Access File Scanning.
 * Book reference: Chapter 9 — Scanners.
 */

#include "scanner/onaccess_scanner.h"
#include "scanner/yara_scanner.h"
#include "constants.h"

#include <cstdio>
#include <cstring>

/* ── Init / Shutdown ─────────────────────────────────────────────────────── */

void
OnAccessScanner::Init(YaraScanner* scanner)
{
    m_scanner = scanner;
    m_cache.clear();
}

void
OnAccessScanner::Shutdown()
{
    m_cache.clear();
    m_scanner = nullptr;
}

/* ── Cache helpers ───────────────────────────────────────────────────────── */

bool
OnAccessScanner::IsCacheValid(const std::string& hash) const
{
    auto it = m_cache.find(hash);
    if (it == m_cache.end()) {
        return false;
    }

    auto age = std::chrono::steady_clock::now() - it->second.timestamp;
    auto ttl = std::chrono::seconds(SENTINEL_SCAN_CACHE_TTL_SEC);

    return age < ttl;
}

void
OnAccessScanner::UpdateCache(const std::string& hash, bool isMatch, const char* rule)
{
    CacheEntry entry = {};
    entry.isMatch   = isMatch;
    entry.timestamp = std::chrono::steady_clock::now();

    if (rule && rule[0] != '\0') {
        strncpy_s(entry.yaraRule, sizeof(entry.yaraRule), rule, _TRUNCATE);
    }

    m_cache[hash] = entry;
}

/* ── OnFileEvent ─────────────────────────────────────────────────────────── */

bool
OnAccessScanner::OnFileEvent(const SENTINEL_FILE_EVENT& fileEvt,
                              SENTINEL_EVENT& alertOut)
{
    /*
     * 1. Only scan on CREATE (new file appeared / opened for write-access)
     *    and WRITE (content modified). Other ops (RENAME, DELETE, SETINFO)
     *    don't change file content.
     */
    if (fileEvt.Operation != SentinelFileOpCreate &&
        fileEvt.Operation != SentinelFileOpWrite) {
        return false;
    }

    /* 2. Skip files where the driver couldn't compute a hash (> 50 MB). */
    if (fileEvt.HashSkipped) {
        return false;
    }

    /* 3. Need a valid hash for cache lookup. */
    if (fileEvt.Sha256Hex[0] == '\0') {
        return false;
    }

    /* 4. Scanner must be initialized with at least one rule. */
    if (!m_scanner || !m_scanner->IsReady()) {
        return false;
    }

    /* ── Cache lookup ────────────────────────────────────────────── */

    std::string hashKey(fileEvt.Sha256Hex);

    if (IsCacheValid(hashKey)) {
        const CacheEntry& cached = m_cache[hashKey];

        if (cached.isMatch) {
            /* Cached positive — rebuild the alert without rescanning. */
            SentinelEventInit(&alertOut, SentinelSourceScanner,
                              SentinelSeverityHigh);
            alertOut.ProcessCtx.ProcessId = fileEvt.RequestingProcessId;

            auto& scan        = alertOut.Payload.Scanner;
            scan.ScanType     = SentinelScanOnAccess;
            scan.IsMatch      = TRUE;
            scan.TargetProcessId = fileEvt.RequestingProcessId;
            wcscpy_s(scan.TargetPath, SENTINEL_MAX_PATH, fileEvt.FilePath);
            strncpy_s(scan.YaraRule, sizeof(scan.YaraRule),
                      cached.yaraRule, _TRUNCATE);
            strncpy_s(scan.Sha256Hex, sizeof(scan.Sha256Hex),
                      fileEvt.Sha256Hex, _TRUNCATE);
            return true;
        }

        /* Cached clean — nothing to report. */
        return false;
    }

    /* ── Cache miss — perform YARA scan ──────────────────────────── */

    SENTINEL_SCANNER_EVENT result = {};

    if (!m_scanner->ScanFile(fileEvt.FilePath, SentinelScanOnAccess, result)) {
        /* Scan failed (file locked, permissions, etc.) — don't cache. */
        return false;
    }

    /* Copy the driver-provided hash into the result (scanner doesn't hash). */
    strncpy_s(result.Sha256Hex, sizeof(result.Sha256Hex),
              fileEvt.Sha256Hex, _TRUNCATE);

    /* Update cache regardless of match/no-match. */
    UpdateCache(hashKey, result.IsMatch != FALSE,
                result.IsMatch ? result.YaraRule : "");

    if (!result.IsMatch) {
        return false;
    }

    /* ── Build alert event ───────────────────────────────────────── */

    SentinelEventInit(&alertOut, SentinelSourceScanner, SentinelSeverityHigh);
    alertOut.ProcessCtx.ProcessId = fileEvt.RequestingProcessId;
    alertOut.Payload.Scanner      = result;

    return true;
}
