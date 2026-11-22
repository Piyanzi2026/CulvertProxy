/*
 * CulvertProxy 进程注入 Hook。
 * 拦截 Winsock 域名解析与 TCP 连接，把目标交给本机接管入口；
 * 域名解析返回 198.18.0.0/15 内的稳定 fake-IP，避免本地 DNS 泄漏。
 *
 * Copyright © 2026 Nexsteaduser. All Rights Reserved.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <stdint.h>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

#define CP_VERSION        1
#define CP_TOKEN_LEN      16
#define CP_HEADER_LEN     29
#define CP_MAX_PREAMBLE   320
#define CP_FAKE_SLOTS     16384
/* 注入层固定使用 198.19.0.0/16，引擎 fake-IP 默认使用 198.18.0.0/16。 */
#define CP_FAKE_NET       0xC6130000u   /* 198.19.0.0，主机字节序 */
#define CP_FAKE_NET_MASK  0xFFFF0000u   /* /16 */
#define CP_CONNECT_WAIT   8000

typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef INT (WSAAPI *PFN_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
typedef VOID (WSAAPI *PFN_freeaddrinfo)(PADDRINFOA);
typedef INT (WSAAPI *PFN_getaddrinfoW)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
typedef int (WSAAPI *PFN_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef INT (WSAAPI *PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef INT (WSAAPI *PFN_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static PFN_connect      g_realConnect;
static PFN_WSAConnect   g_realWsaConnect;
static PFN_getaddrinfo  g_realGetAddrInfo;
static PFN_freeaddrinfo g_realFreeAddrInfo;
static PFN_getaddrinfoW g_realGetAddrInfoW;
static PFN_sendto       g_realSendTo;
static PFN_WSASendTo    g_realWsaSendTo;
static PFN_WSAIoctl     g_realWsaIoctl;
static LPFN_CONNECTEX   g_realConnectEx;
static LPFN_CONNECTEX   g_rawConnectEx;

static const GUID g_connectExGuid = {
    0x25a207b9, 0xddf3, 0x4660, { 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e }
};

static HINSTANCE g_hModule;
static volatile LONG g_started;

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    LONG enabled;
    LONG port;
    LONG port6;
    LONG failOpen;
    LONG selfExcluded;
    BYTE token[CP_TOKEN_LEN];
    WCHAR exclude[1024];
} HOOK_CONFIG;

static HOOK_CONFIG g_cfg;
static SRWLOCK g_cfgLock = SRWLOCK_INIT;
static volatile LONG64 g_lastConfigCheckTick;

static void BuildConfigPath(WCHAR *buffer, DWORD cch)
{
    WCHAR base[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        GetTempPathW(MAX_PATH, base);
    }
    swprintf_s(buffer, cch, L"%s\\Nexsteaduser\\CulvertProxy\\hook.conf", base);
}

static BOOL WildcardMatch(const WCHAR *pattern, const WCHAR *text)
{
    while (*pattern) {
        if (*pattern == L'*') {
            pattern++;
            if (!*pattern) {
                return TRUE;
            }
            while (*text) {
                if (WildcardMatch(pattern, text)) {
                    return TRUE;
                }
                text++;
            }
            return FALSE;
        }
        if (!*text) {
            return FALSE;
        }
        if (*pattern != L'?' && towlower(*pattern) != towlower(*text)) {
            return FALSE;
        }
        pattern++;
        text++;
    }
    return *text == 0;
}

static BOOL MatchesOwnProcess(const WCHAR *excludes)
{
    WCHAR self[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self, MAX_PATH)) {
        return FALSE;
    }
    WCHAR *name = wcsrchr(self, L'\\');
    name = name ? name + 1 : self;

    WCHAR copy[1024];
    wcsncpy_s(copy, _countof(copy), excludes, _TRUNCATE);
    WCHAR *ctx = NULL;
    WCHAR *token = wcstok_s(copy, L";,", &ctx);
    while (token) {
        while (*token == L' ' || *token == L'\t') token++;
        WCHAR *tail = token + wcslen(token);
        while (tail > token && (tail[-1] == L' ' || tail[-1] == L'\t')) tail--;
        *tail = 0;
        if (*token && WildcardMatch(token, name)) {
            return TRUE;
        }
        token = wcstok_s(NULL, L";,", &ctx);
    }
    return FALSE;
}

static int HexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static BOOL ParseToken(const char *text, BYTE *token)
{
    if (strlen(text) < CP_TOKEN_LEN * 2) {
        return FALSE;
    }
    for (int i = 0; i < CP_TOKEN_LEN; i++) {
        int high = HexValue(text[i * 2]);
        int low = HexValue(text[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return FALSE;
        }
        token[i] = (BYTE)((high << 4) | low);
    }
    return TRUE;
}

static void ParseConfigBytes(const char *data, DWORD size, HOOK_CONFIG *cfg)
{
    cfg->enabled = 0;
    cfg->port = 0;
    cfg->port6 = 0;
    cfg->failOpen = 0;
    cfg->exclude[0] = 0;
    memset(cfg->token, 0, sizeof(cfg->token));

    char *copy = (char *)malloc(size + 1);
    if (!copy) {
        return;
    }
    memcpy(copy, data, size);
    copy[size] = 0;

    char *ctx = NULL;
    char *line = strtok_s(copy, "\r\n", &ctx);
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = 0;
            char *key = line;
            char *value = eq + 1;
            char *keyEnd = key + strlen(key);
            while (keyEnd > key && (keyEnd[-1] == ' ' || keyEnd[-1] == '\t')) *--keyEnd = 0;
            while (*value == ' ' || *value == '\t') value++;

            if (_stricmp(key, "enabled") == 0) {
                cfg->enabled = atoi(value) != 0;
            } else if (_stricmp(key, "port") == 0) {
                cfg->port = atoi(value);
            } else if (_stricmp(key, "port6") == 0) {
                cfg->port6 = atoi(value);
            } else if (_stricmp(key, "failopen") == 0) {
                cfg->failOpen = atoi(value) != 0;
            } else if (_stricmp(key, "token") == 0) {
                ParseToken(value, cfg->token);
            } else if (_stricmp(key, "exclude") == 0) {
                MultiByteToWideChar(CP_UTF8, 0, value, -1, cfg->exclude, _countof(cfg->exclude));
            }
        }
        line = strtok_s(NULL, "\r\n", &ctx);
    }

    free(copy);

    if (cfg->port < 1 || cfg->port > 65535) {
        cfg->enabled = 0;
    }
    if (cfg->port6 < 0 || cfg->port6 > 65535) {
        cfg->port6 = 0;
    }
    cfg->selfExcluded = cfg->exclude[0] && MatchesOwnProcess(cfg->exclude);
}

static void RefreshConfig(BOOL force)
{
    ULONGLONG now = GetTickCount64();

    /* 先做无锁快路径，避免每条连接都抢占配置写锁。 */
    LONG64 last = InterlockedCompareExchange64(&g_lastConfigCheckTick, 0, 0);
    if (!force && last != 0 && now - (ULONGLONG)last < 1000) {
        return;
    }

    AcquireSRWLockExclusive(&g_cfgLock);
    last = g_lastConfigCheckTick;
    if (!force && last != 0 && now - (ULONGLONG)last < 1000) {
        ReleaseSRWLockExclusive(&g_cfgLock);
        return;
    }
    InterlockedExchange64(&g_lastConfigCheckTick, (LONG64)now);
    ReleaseSRWLockExclusive(&g_cfgLock);

    HOOK_CONFIG fresh;
    memset(&fresh, 0, sizeof(fresh));

    WCHAR path[MAX_PATH * 2];
    BuildConfigPath(path, _countof(path));

    BOOL keepPrevious = FALSE;
    HANDLE file = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        char buffer[8192];
        DWORD read = 0;
        if (ReadFile(file, buffer, sizeof(buffer) - 1, &read, NULL) && read > 0) {
            ParseConfigBytes(buffer, read, &fresh);
        } else {
            /* 瞬时读取失败或空文件：保留上一份配置，避免意外放行流量。 */
            keepPrevious = TRUE;
        }
        CloseHandle(file);
    } else {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            keepPrevious = TRUE;
        }
    }

    if (keepPrevious) {
        return;
    }

    BOOL tokenSet = FALSE;
    for (int i = 0; i < CP_TOKEN_LEN; i++) {
        if (fresh.token[i]) {
            tokenSet = TRUE;
            break;
        }
    }
    if (fresh.enabled && !tokenSet) {
        /* 全零 token 视为未配置，拒绝启动接管，避免无鉴权入口。 */
        fresh.enabled = 0;
    }

    AcquireSRWLockExclusive(&g_cfgLock);
    g_cfg = fresh;
    ReleaseSRWLockExclusive(&g_cfgLock);
}

static BOOL GetActiveConfig(HOOK_CONFIG *copy)
{
    RefreshConfig(FALSE);
    AcquireSRWLockShared(&g_cfgLock);
    copy->enabled = g_cfg.enabled;
    copy->port = g_cfg.port;
    copy->port6 = g_cfg.port6;
    copy->failOpen = g_cfg.failOpen;
    copy->selfExcluded = g_cfg.selfExcluded;
    memcpy(copy->token, g_cfg.token, CP_TOKEN_LEN);
    ReleaseSRWLockShared(&g_cfgLock);
    return copy->enabled && copy->port > 0 && !copy->selfExcluded;
}

/* ------------------------------------------------------------------ */
/* fake-IP 映射                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t ip;
    LONG used;
    char host[256];
} FAKE_ENTRY;

static FAKE_ENTRY g_fake[CP_FAKE_SLOTS];
static uint16_t g_fakeByIndex[65536];
static uint32_t g_fakeCounter;
static SRWLOCK g_fakeLock = SRWLOCK_INIT;

static uint32_t HashHost(const char *host)
{
    uint32_t hash = 2166136261u;
    while (*host) {
        unsigned char c = (unsigned char)*host++;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

static void NormalizeHost(const char *input, char *output, size_t size)
{
    size_t i = 0;
    while (*input && i + 1 < size) {
        unsigned char c = (unsigned char)*input++;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        output[i++] = (char)c;
    }
    output[i] = 0;
    while (i > 0 && output[i - 1] == '.') {
        output[--i] = 0;
    }
}

static uint32_t FakeIpForHost(const char *host)
{
    char normalized[256];
    NormalizeHost(host, normalized, sizeof(normalized));
    if (!normalized[0]) {
        return 0;
    }

    uint32_t start = HashHost(normalized) % CP_FAKE_SLOTS;

    /* 已存在的映射只读共享锁，避免并发解析互相排队。 */
    uint32_t result = 0;
    AcquireSRWLockShared(&g_fakeLock);
    for (uint32_t probe = 0; probe < CP_FAKE_SLOTS; probe++) {
        uint32_t slot = (start + probe) % CP_FAKE_SLOTS;
        if (!g_fake[slot].used) {
            break;
        }
        if (_stricmp(g_fake[slot].host, normalized) == 0) {
            result = g_fake[slot].ip;
            break;
        }
    }
    ReleaseSRWLockShared(&g_fakeLock);
    if (result != 0) {
        return result;
    }

    AcquireSRWLockExclusive(&g_fakeLock);
    for (uint32_t probe = 0; probe < CP_FAKE_SLOTS; probe++) {
        uint32_t slot = (start + probe) % CP_FAKE_SLOTS;
        if (!g_fake[slot].used) {
            uint32_t index = (g_fakeCounter++ % 65000u) + 1u;
            uint32_t ip = CP_FAKE_NET | index;
            g_fake[slot].ip = ip;
            strncpy_s(g_fake[slot].host, sizeof(g_fake[slot].host), normalized, _TRUNCATE);
            InterlockedExchange(&g_fake[slot].used, 1);
            g_fakeByIndex[index] = (uint16_t)(slot + 1);
            result = ip;
            break;
        }
        if (_stricmp(g_fake[slot].host, normalized) == 0) {
            result = g_fake[slot].ip;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_fakeLock);
    return result;
}

static BOOL HostForFakeIp(uint32_t ip, char *host, size_t size)
{
    if ((ip & CP_FAKE_NET_MASK) != CP_FAKE_NET) {
        return FALSE;
    }
    uint32_t index = ip & 0xFFFFu;
    AcquireSRWLockShared(&g_fakeLock);
    uint16_t slotPlusOne = g_fakeByIndex[index];
    BOOL found = FALSE;
    if (slotPlusOne != 0 && slotPlusOne <= CP_FAKE_SLOTS) {
        FAKE_ENTRY *entry = &g_fake[slotPlusOne - 1];
        if (InterlockedCompareExchange(&entry->used, 1, 1) == 1 && entry->ip == ip) {
            strncpy_s(host, size, entry->host, _TRUNCATE);
            found = TRUE;
        }
    }
    ReleaseSRWLockShared(&g_fakeLock);
    return found;
}

/* ------------------------------------------------------------------ */
/* fake addrinfo 生命周期                                              */
/* ------------------------------------------------------------------ */

typedef struct FAKE_ALLOC {
    ADDRINFOA ai;
    SOCKADDR_IN addr;
    SOCKADDR_IN6 addr6;
    char canon[256];
    struct FAKE_ALLOC *next;
} FAKE_ALLOC;

typedef struct FAKE_ALLOCW {
    ADDRINFOW ai;
    SOCKADDR_IN addr;
    SOCKADDR_IN6 addr6;
    WCHAR canon[256];
    struct FAKE_ALLOCW *next;
} FAKE_ALLOCW;

static FAKE_ALLOC *g_fakeAllocs;
static FAKE_ALLOCW *g_fakeAllocsW;
static SRWLOCK g_allocLock = SRWLOCK_INIT;

static BOOL IsNumericHost(const char *host)
{
    IN_ADDR v4;
    IN6_ADDR v6;
    return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1;
}

static BOOL IsLocalHostName(const char *host)
{
    if (!host || !*host) {
        return TRUE;
    }
    if (IsNumericHost(host)) {
        return TRUE;
    }
    if (!strchr(host, '.')) {
        return TRUE;
    }

    static const char *suffixes[] = {
        ".local", ".lan", ".home.arpa", ".localdomain", ".localhost",
        ".internal", ".corp", ".intranet",
    };
    size_t length = strlen(host);
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        size_t suffixLength = strlen(suffixes[i]);
        if (length > suffixLength &&
            _stricmp(host + length - suffixLength, suffixes[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsAsciiHost(const char *host)
{
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p >= 0x80) {
            return FALSE;
        }
    }
    return TRUE;
}

static USHORT ResolveServicePort(PCSTR service)
{
    if (!service || !*service) {
        return 0;
    }
    char *end = NULL;
    long value = strtol(service, &end, 10);
    if (end && *end == 0 && value > 0 && value <= 65535) {
        return (USHORT)value;
    }
    struct servent *entry = getservbyname(service, NULL);
    return entry ? ntohs((u_short)entry->s_port) : 0;
}

static void TrackFakeAlloc(FAKE_ALLOC *alloc)
{
    AcquireSRWLockExclusive(&g_allocLock);
    alloc->next = g_fakeAllocs;
    g_fakeAllocs = alloc;
    ReleaseSRWLockExclusive(&g_allocLock);
}

static BOOL UntrackFakeAlloc(ADDRINFOA *ai)
{
    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_allocLock);
    FAKE_ALLOC **cursor = &g_fakeAllocs;
    while (*cursor) {
        if (&(*cursor)->ai == ai) {
            FAKE_ALLOC *victim = *cursor;
            *cursor = victim->next;
            free(victim);
            found = TRUE;
            break;
        }
        cursor = &(*cursor)->next;
    }
    ReleaseSRWLockExclusive(&g_allocLock);
    return found;
}

static void TrackFakeAllocW(FAKE_ALLOCW *alloc)
{
    AcquireSRWLockExclusive(&g_allocLock);
    alloc->next = g_fakeAllocsW;
    g_fakeAllocsW = alloc;
    ReleaseSRWLockExclusive(&g_allocLock);
}

static BOOL UntrackFakeAllocW(ADDRINFOW *ai)
{
    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_allocLock);
    FAKE_ALLOCW **cursor = &g_fakeAllocsW;
    while (*cursor) {
        if (&(*cursor)->ai == ai) {
            FAKE_ALLOCW *victim = *cursor;
            *cursor = victim->next;
            free(victim);
            found = TRUE;
            break;
        }
        cursor = &(*cursor)->next;
    }
    ReleaseSRWLockExclusive(&g_allocLock);
    return found;
}

/* 同一 fake-IP 同时支持 AF_INET 与 v4-mapped AF_INET6 结果。 */
static void FillSockaddr4(SOCKADDR_IN *addr, uint32_t fakeIp, USHORT port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl(fakeIp);
}

static void FillSockaddr6Mapped(SOCKADDR_IN6 *addr, uint32_t fakeIp, USHORT port)
{
    uint32_t networkIp = htonl(fakeIp);
    memset(addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    addr->sin6_addr.u.Byte[10] = 0xFF;
    addr->sin6_addr.u.Byte[11] = 0xFF;
    memcpy(&addr->sin6_addr.u.Byte[12], &networkIp, 4);
}

/* AF_INET6 请求返回 ::ffff:198.19.x.y，连接时按 v4-mapped fake 处理。 */
static void AttachFakeAddress(
    ADDRINFOA *ai,
    FAKE_ALLOC *alloc,
    int family,
    uint32_t fakeIp,
    USHORT port)
{
    if (family == AF_INET6) {
        FillSockaddr6Mapped(&alloc->addr6, fakeIp, port);
        ai->ai_family = AF_INET6;
        ai->ai_addrlen = (size_t)sizeof(SOCKADDR_IN6);
        ai->ai_addr = (struct sockaddr *)&alloc->addr6;
    } else {
        FillSockaddr4(&alloc->addr, fakeIp, port);
        ai->ai_family = AF_INET;
        ai->ai_addrlen = (size_t)sizeof(SOCKADDR_IN);
        ai->ai_addr = (struct sockaddr *)&alloc->addr;
    }
}

/* ------------------------------------------------------------------ */
/* 套接字辅助                                                          */
/* ------------------------------------------------------------------ */

static BOOL WaitWritable(SOCKET socket, int timeoutMs)
{
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(socket, &writeSet);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int result = select(0, NULL, &writeSet, NULL, &tv);
    if (result > 0) {
        return TRUE;
    }
    if (result == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
        return WaitWritable(socket, timeoutMs);
    }
    return FALSE;
}

static BOOL SendAll(SOCKET socket, const char *data, int length)
{
    int offset = 0;
    while (offset < length) {
        int sent = send(socket, data + offset, length - offset, 0);
        if (sent > 0) {
            offset += sent;
            continue;
        }
        int error = WSAGetLastError();
        if (error == WSAEINTR) {
            continue;
        }
        if (error == WSAEWOULDBLOCK && WaitWritable(socket, CP_CONNECT_WAIT)) {
            continue;
        }
        WSASetLastError(error);
        return FALSE;
    }
    return TRUE;
}

static int BuildPreamble(
    const HOOK_CONFIG *cfg,
    BYTE *buffer,
    int addressType,
    const void *address,
    int addressLength,
    BYTE domainLength,
    const char *domain,
    USHORT port)
{
    memcpy(buffer, "CPX1", 4);
    buffer[4] = CP_VERSION;
    buffer[5] = 0;
    uint32_t pid = (uint32_t)GetCurrentProcessId();
    memcpy(buffer + 6, &pid, 4);
    memcpy(buffer + 10, cfg->token, CP_TOKEN_LEN);
    buffer[26] = (BYTE)addressType;
    buffer[27] = (BYTE)(port >> 8);
    buffer[28] = (BYTE)(port & 0xFF);
    int offset = CP_HEADER_LEN;

    if (addressType == 2) {
        buffer[offset++] = domainLength;
        memcpy(buffer + offset, domain, domainLength);
        offset += domainLength;
    } else {
        memcpy(buffer + offset, address, addressLength);
        offset += addressLength;
    }
    return offset;
}

/* ------------------------------------------------------------------ */
/* 直连回退与代理连接                                                  */
/* ------------------------------------------------------------------ */

static int SocketFamily(SOCKET socket)
{
    SOCKADDR_STORAGE bound;
    int length = sizeof(bound);
    if (getsockname(socket, (struct sockaddr *)&bound, &length) == 0) {
        return bound.ss_family;
    }
    return AF_UNSPEC;
}

/* 把 IPv4 地址映射进 IPv6 sockaddr，避免 v6 套接字无法直接拨 v4。 */
static int MapAddressForSocket(
    int socketFamily,
    const struct sockaddr *address,
    int addressLength,
    SOCKADDR_STORAGE *storage,
    int *mappedLength)
{
    if (socketFamily == AF_INET6 && address->sa_family == AF_INET && addressLength >= (int)sizeof(SOCKADDR_IN)) {
        const SOCKADDR_IN *source = (const SOCKADDR_IN *)address;
        SOCKADDR_IN6 *mapped = (SOCKADDR_IN6 *)storage;
        memset(mapped, 0, sizeof(*mapped));
        mapped->sin6_family = AF_INET6;
        mapped->sin6_port = source->sin_port;
        mapped->sin6_addr.u.Byte[10] = 0xFF;
        mapped->sin6_addr.u.Byte[11] = 0xFF;
        memcpy(&mapped->sin6_addr.u.Byte[12], &source->sin_addr.s_addr, 4);
        *mappedLength = sizeof(SOCKADDR_IN6);
        return 0;
    }

    if (socketFamily == AF_INET && address->sa_family != AF_INET) {
        return SOCKET_ERROR;
    }

    if (addressLength <= 0 || addressLength > (int)sizeof(*storage)) {
        return SOCKET_ERROR;
    }

    memcpy(storage, address, (size_t)addressLength);
    *mappedLength = addressLength;
    return 0;
}

static BOOL IsFakeSockaddr(const struct sockaddr *name, int length);

static int ConnectDirect(
    SOCKET socket,
    const struct sockaddr *original,
    int originalLength,
    const char *domain,
    USHORT port)
{
    if (!domain || !*domain) {
        return g_realConnect(socket, original, originalLength);
    }

    char service[16];
    sprintf_s(service, sizeof(service), "%u", (unsigned)port);
    ADDRINFOA hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    PADDRINFOA result = NULL;
    if (g_realGetAddrInfo(domain, service, &hints, &result) != 0) {
        WSASetLastError(WSAHOST_NOT_FOUND);
        return SOCKET_ERROR;
    }

    int family = SocketFamily(socket);
    int lastError = WSAHOST_NOT_FOUND;
    for (ADDRINFOA *entry = result; entry; entry = entry->ai_next) {
        SOCKADDR_STORAGE mapped;
        int mappedLength = 0;
        if (MapAddressForSocket(family, entry->ai_addr, (int)entry->ai_addrlen, &mapped, &mappedLength) != 0) {
            continue;
        }

        int rc = g_realConnect(socket, (const struct sockaddr *)&mapped, mappedLength);
        if (rc == 0) {
            g_realFreeAddrInfo(result);
            return 0;
        }
        lastError = WSAGetLastError();
    }
    g_realFreeAddrInfo(result);
    WSASetLastError(lastError);
    return SOCKET_ERROR;
}

/* 关闭接管后仍可能有应用缓存了 fake-IP；在这里还原域名并直连，避免断网。 */
static BOOL FakeTargetFromSockaddr(
    const struct sockaddr *name,
    int namelen,
    char *domain,
    size_t domainSize,
    USHORT *port)
{
    domain[0] = 0;
    *port = 0;
    if (!IsFakeSockaddr(name, namelen)) {
        return FALSE;
    }

    const SOCKADDR_IN *target = (const SOCKADDR_IN *)name;
    uint32_t ip = ntohl(target->sin_addr.s_addr);
    *port = ntohs(target->sin_port);
    if (name->sa_family == AF_INET6) {
        const SOCKADDR_IN6 *target6 = (const SOCKADDR_IN6 *)name;
        uint32_t networkIp;
        memcpy(&networkIp, &target6->sin6_addr.u.Byte[12], 4);
        ip = ntohl(networkIp);
        *port = ntohs(target6->sin6_port);
    }

    return HostForFakeIp(ip, domain, domainSize);
}

static int ConnectFakeDirect(SOCKET socket, const struct sockaddr *name, int namelen)
{
    char domain[256];
    USHORT port;
    if (!FakeTargetFromSockaddr(name, namelen, domain, sizeof(domain), &port)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }

    return ConnectDirect(socket, name, namelen, domain, port);
}

static BOOL IsFakeSockaddr(const struct sockaddr *name, int length)
{
    if (!name) {
        return FALSE;
    }
    if (name->sa_family == AF_INET && length >= (int)sizeof(SOCKADDR_IN)) {
        const SOCKADDR_IN *target = (const SOCKADDR_IN *)name;
        return (ntohl(target->sin_addr.s_addr) & CP_FAKE_NET_MASK) == CP_FAKE_NET;
    }
    if (name->sa_family == AF_INET6 && length >= (int)sizeof(SOCKADDR_IN6)) {
        const SOCKADDR_IN6 *target = (const SOCKADDR_IN6 *)name;
        if (IN6_IS_ADDR_V4MAPPED(&target->sin6_addr)) {
            uint32_t networkIp;
            memcpy(&networkIp, &target->sin6_addr.u.Byte[12], 4);
            return (ntohl(networkIp) & CP_FAKE_NET_MASK) == CP_FAKE_NET;
        }
    }
    return FALSE;
}

/* 目标换成对应的回环入口；IPv6 套接字必须用 ::1，不能塞 IPv4 sockaddr。 */
static BOOL BuildLocalRedirect(
    SOCKET socket,
    const HOOK_CONFIG *cfg,
    SOCKADDR_STORAGE *storage,
    int *length)
{
    BOOL ipv6 = FALSE;
    SOCKADDR_STORAGE bound;
    int boundLength = sizeof(bound);
    if (getsockname(socket, (struct sockaddr *)&bound, &boundLength) == 0) {
        ipv6 = bound.ss_family == AF_INET6;
    }

    memset(storage, 0, sizeof(*storage));
    if (ipv6) {
        if (cfg->port6 < 1 || cfg->port6 > 65535) {
            return FALSE;
        }
        SOCKADDR_IN6 *local = (SOCKADDR_IN6 *)storage;
        local->sin6_family = AF_INET6;
        local->sin6_port = htons((u_short)cfg->port6);
        local->sin6_addr = in6addr_loopback;
        *length = sizeof(SOCKADDR_IN6);
        return TRUE;
    }

    if (cfg->port < 1 || cfg->port > 65535) {
        return FALSE;
    }

    SOCKADDR_IN *local = (SOCKADDR_IN *)storage;
    local->sin_family = AF_INET;
    local->sin_port = htons((u_short)cfg->port);
    local->sin_addr.s_addr = htonl(0x7F000001u);
    *length = sizeof(SOCKADDR_IN);
    return TRUE;
}

static int ConnectThroughProxy(
    SOCKET socket,
    const HOOK_CONFIG *cfg,
    const BYTE *preamble,
    int preambleLength,
    const struct sockaddr *original,
    int originalLength,
    const char *domain,
    USHORT port,
    LPWSABUF callerData)
{
    SOCKADDR_STORAGE local;
    int localLength = 0;
    if (!BuildLocalRedirect(socket, cfg, &local, &localLength)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }

    int rc = g_realConnect(socket, (const struct sockaddr *)&local, localLength);
    if (rc == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            if (!WaitWritable(socket, CP_CONNECT_WAIT)) {
                WSASetLastError(WSAETIMEDOUT);
                return SOCKET_ERROR;
            }
            int socketError = 0;
            int length = sizeof(socketError);
            if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socketError, &length) == SOCKET_ERROR) {
                return SOCKET_ERROR;
            }
            error = socketError;
        }

        if (error != 0) {
            if (cfg->failOpen) {
                if (IsFakeSockaddr(original, originalLength) && (!domain || !*domain)) {
                    WSASetLastError(WSAENETUNREACH);
                    return SOCKET_ERROR;
                }
                return ConnectDirect(socket, original, originalLength, domain, port);
            }
            WSASetLastError(error);
            return SOCKET_ERROR;
        }
    }

    if (!SendAll(socket, (const char *)preamble, preambleLength)) {
        return SOCKET_ERROR;
    }
    if (callerData && callerData->len > 0 && callerData->buf) {
        if (!SendAll(socket, callerData->buf, (int)callerData->len)) {
            return SOCKET_ERROR;
        }
    }
    WSASetLastError(0);
    return 0;
}

static BOOL IsLoopbackV4(uint32_t ip)
{
    return (ip >> 24) == 127 || ip == 0;
}

static BOOL IsLoopbackV6(const struct in6_addr *address)
{
    return IN6_IS_ADDR_LOOPBACK(address) || IN6_IS_ADDR_UNSPECIFIED(address);
}

static int RedirectSocket(
    SOCKET socket,
    const HOOK_CONFIG *cfg,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF callerData)
{
    if (!name) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    BYTE preamble[CP_MAX_PREAMBLE];
    int preambleLength = 0;
    USHORT port = 0;
    char domain[256];
    domain[0] = 0;
    const char *directDomain = NULL;

    if (name->sa_family == AF_INET) {
        if (namelen < (int)sizeof(SOCKADDR_IN)) {
            return g_realConnect(socket, name, namelen);
        }
        const SOCKADDR_IN *target = (const SOCKADDR_IN *)name;
        uint32_t ip = ntohl(target->sin_addr.s_addr);
        port = ntohs(target->sin_port);
        if (IsLoopbackV4(ip)) {
            return g_realConnect(socket, name, namelen);
        }

        int socketType = 0;
        int typeLength = sizeof(socketType);
        getsockopt(socket, SOL_SOCKET, SO_TYPE, (char *)&socketType, &typeLength);
        if (socketType != 0 && socketType != SOCK_STREAM && socketType != SOCK_DGRAM) {
            /* 原始套接字等非 TCP 类型不归代理管。 */
            return g_realConnect(socket, name, namelen);
        }
        if (socketType == SOCK_DGRAM && (ip & CP_FAKE_NET_MASK) == CP_FAKE_NET) {
            /* 无法注入 UDP 数据报，阻断 QUIC 走 fake-IP，促使应用回落 TCP。 */
            WSASetLastError(WSAENETUNREACH);
            return SOCKET_ERROR;
        }
        if (socketType == SOCK_DGRAM) {
            return g_realConnect(socket, name, namelen);
        }

        if (HostForFakeIp(ip, domain, sizeof(domain))) {
            preambleLength = BuildPreamble(cfg, preamble, 2, NULL, 0,
                (BYTE)strlen(domain), domain, port);
            directDomain = domain;
        } else {
            uint32_t networkIp = target->sin_addr.s_addr;
            preambleLength = BuildPreamble(cfg, preamble, 1, &networkIp, 4, 0, NULL, port);
        }
    } else if (name->sa_family == AF_INET6) {
        if (namelen < (int)sizeof(SOCKADDR_IN6)) {
            return g_realConnect(socket, name, namelen);
        }
        const SOCKADDR_IN6 *target = (const SOCKADDR_IN6 *)name;
        port = ntohs(target->sin6_port);
        if (IsLoopbackV6(&target->sin6_addr)) {
            return g_realConnect(socket, name, namelen);
        }

        int socketType = 0;
        int typeLength = sizeof(socketType);
        getsockopt(socket, SOL_SOCKET, SO_TYPE, (char *)&socketType, &typeLength);
        if (socketType != 0 && socketType != SOCK_STREAM && socketType != SOCK_DGRAM) {
            return g_realConnect(socket, name, namelen);
        }

        if (IN6_IS_ADDR_V4MAPPED(&target->sin6_addr)) {
            uint32_t networkIp;
            memcpy(&networkIp, &target->sin6_addr.u.Byte[12], 4);
            uint32_t ip = ntohl(networkIp);
            if (IsLoopbackV4(ip)) {
                return g_realConnect(socket, name, namelen);
            }
            if (socketType == SOCK_DGRAM && (ip & CP_FAKE_NET_MASK) == CP_FAKE_NET) {
                WSASetLastError(WSAENETUNREACH);
                return SOCKET_ERROR;
            }
            if (socketType == SOCK_DGRAM) {
                return g_realConnect(socket, name, namelen);
            }
            if (HostForFakeIp(ip, domain, sizeof(domain))) {
                preambleLength = BuildPreamble(cfg, preamble, 2, NULL, 0,
                    (BYTE)strlen(domain), domain, port);
                directDomain = domain;
            } else {
                preambleLength = BuildPreamble(cfg, preamble, 1, &networkIp, 4, 0, NULL, port);
            }
        } else {
            if (socketType == SOCK_DGRAM) {
                return g_realConnect(socket, name, namelen);
            }

            preambleLength = BuildPreamble(cfg, preamble, 3, &target->sin6_addr, 16, 0, NULL, port);
        }
    } else {
        return g_realConnect(socket, name, namelen);
    }

    return ConnectThroughProxy(socket, cfg, preamble, preambleLength,
        name, namelen, directDomain, port, callerData);
}

/* ------------------------------------------------------------------ */
/* ConnectEx：.NET 等异步套接字不走 connect，需要单独接管              */
/* ------------------------------------------------------------------ */

#define CX_SLOT_COUNT 4096
#define CX_SLOT_SIZE  1024
/* 未完成的 overlapped 连接可能持续到系统 TCP 超时；过早回收会覆盖内核仍引用的缓冲。 */
#define CX_SLOT_AGE_MS 180000

typedef struct {
    volatile LONG busy;
    volatile ULONGLONG usedAt;
    BYTE data[CX_SLOT_SIZE];
} CX_SLOT;

static CX_SLOT g_cxSlots[CX_SLOT_COUNT];
static SRWLOCK g_cxLock = SRWLOCK_INIT;
static volatile LONG g_cxCursor;

static CX_SLOT *AllocCxSlot(DWORD size)
{
    if (size == 0 || size > CX_SLOT_SIZE) {
        return NULL;
    }

    ULONGLONG now = GetTickCount64();
    ULONG start = (ULONG)InterlockedIncrement(&g_cxCursor);
    CX_SLOT *result = NULL;
    AcquireSRWLockExclusive(&g_cxLock);
    for (ULONG i = 0; i < CX_SLOT_COUNT; i++) {
        ULONG index = (start + i) % CX_SLOT_COUNT;
        CX_SLOT *slot = &g_cxSlots[index];
        if (slot->busy == 0 || now - slot->usedAt > CX_SLOT_AGE_MS) {
            slot->busy = 1;
            slot->usedAt = now;
            result = slot;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_cxLock);
    return result;
}

static void FreeCxSlot(CX_SLOT *slot)
{
    if (slot) {
        InterlockedExchange(&slot->busy, 0);
    }
}

static int PrepareConnectPreamble(
    const HOOK_CONFIG *cfg,
    const struct sockaddr *name,
    int namelen,
    BYTE *preamble,
    USHORT *port,
    char *domain,
    size_t domainSize,
    BOOL *loopback,
    BOOL *hasDomain)
{
    *loopback = FALSE;
    *hasDomain = FALSE;
    *port = 0;
    domain[0] = 0;
    if (!name) {
        return 0;
    }

    if (name->sa_family == AF_INET) {
        if (namelen < (int)sizeof(SOCKADDR_IN)) {
            return 0;
        }
        const SOCKADDR_IN *target = (const SOCKADDR_IN *)name;
        uint32_t ip = ntohl(target->sin_addr.s_addr);
        *port = ntohs(target->sin_port);
        if (IsLoopbackV4(ip)) {
            *loopback = TRUE;
            return 0;
        }

        if (HostForFakeIp(ip, domain, domainSize)) {
            *hasDomain = TRUE;
            return BuildPreamble(cfg, preamble, 2, NULL, 0,
                (BYTE)strlen(domain), domain, *port);
        }

        uint32_t networkIp = target->sin_addr.s_addr;
        return BuildPreamble(cfg, preamble, 1, &networkIp, 4, 0, NULL, *port);
    }

    if (name->sa_family == AF_INET6) {
        if (namelen < (int)sizeof(SOCKADDR_IN6)) {
            return 0;
        }
        const SOCKADDR_IN6 *target = (const SOCKADDR_IN6 *)name;
        *port = ntohs(target->sin6_port);
        if (IsLoopbackV6(&target->sin6_addr)) {
            *loopback = TRUE;
            return 0;
        }

        if (IN6_IS_ADDR_V4MAPPED(&target->sin6_addr)) {
            uint32_t networkIp;
            memcpy(&networkIp, &target->sin6_addr.u.Byte[12], 4);
            uint32_t ip = ntohl(networkIp);
            if (IsLoopbackV4(ip)) {
                *loopback = TRUE;
                return 0;
            }
            if (HostForFakeIp(ip, domain, domainSize)) {
                *hasDomain = TRUE;
                return BuildPreamble(cfg, preamble, 2, NULL, 0,
                    (BYTE)strlen(domain), domain, *port);
            }

            return BuildPreamble(cfg, preamble, 1, &networkIp, 4, 0, NULL, *port);
        }

        return BuildPreamble(cfg, preamble, 3, &target->sin6_addr, 16, 0, NULL, *port);
    }

    return 0;
}

static BOOL ConnectExToDomain(
    SOCKET socket,
    const char *domain,
    USHORT port,
    PVOID sendBuffer,
    DWORD sendLength,
    LPDWORD bytesSent,
    LPOVERLAPPED overlapped)
{
    char service[16];
    sprintf_s(service, sizeof(service), "%u", (unsigned)port);
    ADDRINFOA hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOA result = NULL;
    if (g_realGetAddrInfo(domain, service, &hints, &result) != 0) {
        WSASetLastError(WSAHOST_NOT_FOUND);
        return FALSE;
    }

    int family = SocketFamily(socket);
    int lastError = WSAHOST_NOT_FOUND;
    for (ADDRINFOA *entry = result; entry; entry = entry->ai_next) {
        SOCKADDR_STORAGE mapped;
        int mappedLength = 0;
        if (MapAddressForSocket(family, entry->ai_addr, (int)entry->ai_addrlen, &mapped, &mappedLength) != 0) {
            continue;
        }

        BOOL ok = g_realConnectEx(
            socket,
            (const struct sockaddr *)&mapped,
            mappedLength,
            sendBuffer,
            sendLength,
            bytesSent,
            overlapped);
        if (ok) {
            g_realFreeAddrInfo(result);
            return TRUE;
        }

        int error = WSAGetLastError();
        if (error == WSA_IO_PENDING) {
            g_realFreeAddrInfo(result);
            WSASetLastError(error);
            return FALSE;
        }
        lastError = error;
    }

    g_realFreeAddrInfo(result);
    WSASetLastError(lastError);
    return FALSE;
}

static BOOL ConnectExFakeDirect(
    SOCKET socket,
    const struct sockaddr *name,
    int namelen,
    PVOID sendBuffer,
    DWORD sendLength,
    LPDWORD bytesSent,
    LPOVERLAPPED overlapped)
{
    char domain[256];
    USHORT port;
    if (!FakeTargetFromSockaddr(name, namelen, domain, sizeof(domain), &port)) {
        WSASetLastError(WSAENETUNREACH);
        return FALSE;
    }

    return ConnectExToDomain(socket, domain, port, sendBuffer, sendLength, bytesSent, overlapped);
}

static BOOL PASCAL DetourConnectEx(
    SOCKET socket,
    const struct sockaddr *name,
    int namelen,
    PVOID sendBuffer,
    DWORD sendLength,
    LPDWORD bytesSent,
    LPOVERLAPPED overlapped)
{
    if (!g_realConnectEx) {
        WSASetLastError(WSAEOPNOTSUPP);
        return FALSE;
    }

    HOOK_CONFIG cfg;
    if (!GetActiveConfig(&cfg) || !name) {
        if (name && IsFakeSockaddr(name, namelen)) {
            return ConnectExFakeDirect(socket, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
        }
        return g_realConnectEx(socket, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
    }

    int socketType = 0;
    int typeLength = sizeof(socketType);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, (char *)&socketType, &typeLength) == 0
        && socketType != SOCK_STREAM) {
        return g_realConnectEx(socket, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
    }

    BYTE preamble[CP_MAX_PREAMBLE];
    char domain[256];
    USHORT port = 0;
    BOOL loopback = FALSE;
    BOOL hasDomain = FALSE;
    int preambleLength = PrepareConnectPreamble(
        &cfg, name, namelen, preamble, &port, domain, sizeof(domain), &loopback, &hasDomain);
    if (loopback || preambleLength <= 0) {
        return g_realConnectEx(socket, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
    }

    DWORD payload = (sendBuffer && sendLength > 0) ? sendLength : 0;
    DWORD total = (DWORD)preambleLength + payload;
    if (total > CX_SLOT_SIZE) {
        /* ConnectEx 的发送缓冲几乎总是为空；过大时拒绝而不是泄漏。 */
        WSASetLastError(WSAENOBUFS);
        return FALSE;
    }

    CX_SLOT *slot = AllocCxSlot(total);
    if (!slot) {
        WSASetLastError(WSAENOBUFS);
        return FALSE;
    }

    memcpy(slot->data, preamble, (size_t)preambleLength);
    if (payload) {
        memcpy(slot->data + preambleLength, sendBuffer, payload);
    }

    SOCKADDR_STORAGE local;
    int localLength = 0;
    if (!BuildLocalRedirect(socket, &cfg, &local, &localLength)) {
        FreeCxSlot(slot);
        WSASetLastError(WSAENETUNREACH);
        return FALSE;
    }

    BOOL ok = g_realConnectEx(
        socket,
        (const struct sockaddr *)&local,
        localLength,
        slot->data,
        total,
        bytesSent,
        overlapped);
    if (ok) {
        FreeCxSlot(slot);
        if (bytesSent) {
            *bytesSent = payload;
        }
        return TRUE;
    }

    int error = WSAGetLastError();
    if (error == WSA_IO_PENDING) {
        /* 缓冲区由未完成的 overlapped 操作持有，超时后由分配器回收。 */
        return FALSE;
    }

    FreeCxSlot(slot);
    if (cfg.failOpen) {
        if (hasDomain) {
            char service[16];
            sprintf_s(service, sizeof(service), "%u", (unsigned)port);
            ADDRINFOA hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            PADDRINFOA result = NULL;
            if (g_realGetAddrInfo(domain, service, &hints, &result) == 0) {
                BOOL direct = g_realConnectEx(
                    socket,
                    result->ai_addr,
                    (int)result->ai_addrlen,
                    sendBuffer,
                    sendLength,
                    bytesSent,
                    overlapped);
                int directError = WSAGetLastError();
                g_realFreeAddrInfo(result);
                if (direct || directError == WSA_IO_PENDING) {
                    return direct;
                }
                error = directError;
            }
        } else if (!IsFakeSockaddr(name, namelen)) {
            return g_realConnectEx(socket, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
        }
    }

    WSASetLastError(error);
    return FALSE;
}

static int WSAAPI DetourWsaIoctl(
    SOCKET socket,
    DWORD code,
    LPVOID inBuffer,
    DWORD inBufferSize,
    LPVOID outBuffer,
    DWORD outBufferSize,
    LPDWORD bytesReturned,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    int result = g_realWsaIoctl(
        socket, code, inBuffer, inBufferSize, outBuffer, outBufferSize,
        bytesReturned, overlapped, completion);

    if (result == 0
        && code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && inBuffer && inBufferSize >= sizeof(GUID)
        && outBuffer && outBufferSize >= sizeof(void *)) {
        GUID guid;
        memcpy(&guid, inBuffer, sizeof(guid));
        if (memcmp(&guid, &g_connectExGuid, sizeof(GUID)) == 0) {
            void *raw = *(void **)outBuffer;
            if (raw) {
                InterlockedCompareExchangePointer((PVOID volatile *)&g_rawConnectEx, raw, NULL);
                InterlockedCompareExchangePointer((PVOID volatile *)&g_realConnectEx, raw, NULL);
                *(void **)outBuffer = (void *)DetourConnectEx;
            }
        }
    }

    return result;
}

static void InstallConnectExHook(void)
{
    SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (probe == INVALID_SOCKET) {
        return;
    }

    LPFN_CONNECTEX pointer = NULL;
    DWORD bytes = 0;
    if (WSAIoctl(
            probe,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (LPVOID)&g_connectExGuid,
            sizeof(GUID),
            &pointer,
            sizeof(pointer),
            &bytes,
            NULL,
            NULL) == 0
        && pointer) {
        g_rawConnectEx = pointer;
        LPVOID trampoline = NULL;
        if (MH_CreateHook((LPVOID)pointer, (LPVOID)DetourConnectEx, &trampoline) == MH_OK && trampoline) {
            g_realConnectEx = (LPFN_CONNECTEX)trampoline;
        } else {
            g_realConnectEx = pointer;
        }
    }

    closesocket(probe);
}

/* ------------------------------------------------------------------ */
/* Hook 入口                                                           */
/* ------------------------------------------------------------------ */

static int WSAAPI DetourConnect(SOCKET socket, const struct sockaddr *name, int namelen)
{
    HOOK_CONFIG cfg;
    if (!GetActiveConfig(&cfg)) {
        if (name && IsFakeSockaddr(name, namelen)) {
            return ConnectFakeDirect(socket, name, namelen);
        }
        return g_realConnect(socket, name, namelen);
    }
    return RedirectSocket(socket, &cfg, name, namelen, NULL);
}

static int WSAAPI DetourWsaConnect(
    SOCKET socket,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF callerData,
    LPWSABUF calleeData,
    LPQOS sqos,
    LPQOS gqos)
{
    (void)sqos;
    (void)gqos;
    HOOK_CONFIG cfg;
    if (!GetActiveConfig(&cfg)) {
        if (name && IsFakeSockaddr(name, namelen)) {
            int rc = ConnectFakeDirect(socket, name, namelen);
            if (rc == 0 && callerData && callerData->len > 0 && callerData->buf) {
                if (!SendAll(socket, callerData->buf, (int)callerData->len)) {
                    return SOCKET_ERROR;
                }
            }
            if (calleeData) {
                calleeData->len = 0;
            }
            return rc;
        }
        return g_realWsaConnect(socket, name, namelen, callerData, calleeData, sqos, gqos);
    }
    if (calleeData) {
        calleeData->len = 0;
    }
    return RedirectSocket(socket, &cfg, name, namelen, callerData);
}

static INT WSAAPI DetourGetAddrInfo(
    PCSTR nodeName,
    PCSTR serviceName,
    const ADDRINFOA *hints,
    PADDRINFOA *result)
{
    HOOK_CONFIG cfg;
    if (!GetActiveConfig(&cfg) || !nodeName || !*nodeName || !result) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }
    if (hints && (hints->ai_flags & (AI_PASSIVE | AI_NUMERICHOST))) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }
    if (IsLocalHostName(nodeName) || !IsAsciiHost(nodeName) || strlen(nodeName) > 253) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }
    if (hints && hints->ai_socktype == SOCK_RAW) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }
    if (hints && hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET && hints->ai_family != AF_INET6) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }

    uint32_t fakeIp = FakeIpForHost(nodeName);
    if (fakeIp == 0) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }

    USHORT port = ResolveServicePort(serviceName);
    if (serviceName && *serviceName && port == 0) {
        return g_realGetAddrInfo(nodeName, serviceName, hints, result);
    }

    FAKE_ALLOC *alloc = (FAKE_ALLOC *)calloc(1, sizeof(FAKE_ALLOC));
    if (!alloc) {
        return EAI_MEMORY;
    }

    int family = hints && hints->ai_family == AF_INET6 ? AF_INET6 : AF_INET;
    AttachFakeAddress(&alloc->ai, alloc, family, fakeIp, port);

    alloc->ai.ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
    if (hints && hints->ai_protocol) {
        alloc->ai.ai_protocol = hints->ai_protocol;
    } else if (hints && hints->ai_socktype == SOCK_DGRAM) {
        alloc->ai.ai_protocol = IPPROTO_UDP;
    } else {
        alloc->ai.ai_protocol = IPPROTO_TCP;
    }
    alloc->ai.ai_next = NULL;
    if (hints && (hints->ai_flags & AI_CANONNAME)) {
        strncpy_s(alloc->canon, sizeof(alloc->canon), nodeName, _TRUNCATE);
        alloc->ai.ai_canonname = alloc->canon;
    }

    TrackFakeAlloc(alloc);
    *result = &alloc->ai;
    return 0;
}

static void WSAAPI DetourFreeAddrInfo(PADDRINFOA ai)
{
    if (ai && UntrackFakeAlloc(ai)) {
        return;
    }

    /* FreeAddrInfoW 在 ws2_32 中与 freeaddrinfo 是同一入口，宽字符分配也在这里释放。 */
    if (ai && UntrackFakeAllocW((PADDRINFOW)ai)) {
        return;
    }

    g_realFreeAddrInfo(ai);
}

/* 把宽字符串主机名转为 ASCII；含非 ASCII 时返回 FALSE，交还原函数。 */
static BOOL WideHostToAscii(PCWSTR host, char *output, size_t size)
{
    if (!host || !*host || size == 0) {
        return FALSE;
    }

    size_t index = 0;
    for (const WCHAR *cursor = host; *cursor; cursor++) {
        if (*cursor > 0x7F || index + 1 >= size) {
            return FALSE;
        }
        output[index++] = (char)*cursor;
    }

    output[index] = 0;
    return TRUE;
}

static BOOL WideServiceToAscii(PCWSTR service, char *output, size_t size)
{
    if (!service || !*service) {
        output[0] = 0;
        return TRUE;
    }

    size_t index = 0;
    for (const WCHAR *cursor = service; *cursor; cursor++) {
        if (*cursor > 0x7F || index + 1 >= size) {
            return FALSE;
        }
        output[index++] = (char)*cursor;
    }

    output[index] = 0;
    return TRUE;
}

static INT WSAAPI DetourGetAddrInfoW(
    PCWSTR nodeName,
    PCWSTR serviceName,
    const ADDRINFOW *hints,
    PADDRINFOW *result)
{
    HOOK_CONFIG cfg;
    if (!GetActiveConfig(&cfg) || !nodeName || !*nodeName || !result) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }
    if (hints && (hints->ai_flags & (AI_PASSIVE | AI_NUMERICHOST))) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }

    char host[300];
    char service[64];
    if (!WideHostToAscii(nodeName, host, sizeof(host))
        || !WideServiceToAscii(serviceName, service, sizeof(service))) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }
    if (IsLocalHostName(host) || strlen(host) > 253) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }
    if (hints && hints->ai_socktype == SOCK_RAW) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }
    if (hints && hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET && hints->ai_family != AF_INET6) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }

    uint32_t fakeIp = FakeIpForHost(host);
    if (fakeIp == 0) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }

    USHORT port = ResolveServicePort(service);
    if (serviceName && *serviceName && port == 0) {
        return g_realGetAddrInfoW(nodeName, serviceName, hints, result);
    }

    FAKE_ALLOCW *alloc = (FAKE_ALLOCW *)calloc(1, sizeof(FAKE_ALLOCW));
    if (!alloc) {
        return EAI_MEMORY;
    }

    int family = hints && hints->ai_family == AF_INET6 ? AF_INET6 : AF_INET;
    if (family == AF_INET6) {
        FillSockaddr6Mapped(&alloc->addr6, fakeIp, port);
        alloc->ai.ai_family = AF_INET6;
        alloc->ai.ai_addrlen = (size_t)sizeof(SOCKADDR_IN6);
        alloc->ai.ai_addr = (struct sockaddr *)&alloc->addr6;
    } else {
        FillSockaddr4(&alloc->addr, fakeIp, port);
        alloc->ai.ai_family = AF_INET;
        alloc->ai.ai_addrlen = (size_t)sizeof(SOCKADDR_IN);
        alloc->ai.ai_addr = (struct sockaddr *)&alloc->addr;
    }

    alloc->ai.ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
    if (hints && hints->ai_protocol) {
        alloc->ai.ai_protocol = hints->ai_protocol;
    } else if (hints && hints->ai_socktype == SOCK_DGRAM) {
        alloc->ai.ai_protocol = IPPROTO_UDP;
    } else {
        alloc->ai.ai_protocol = IPPROTO_TCP;
    }
    alloc->ai.ai_next = NULL;
    if (hints && (hints->ai_flags & AI_CANONNAME)) {
        wcsncpy_s(alloc->canon, _countof(alloc->canon), nodeName, _TRUNCATE);
        alloc->ai.ai_canonname = alloc->canon;
    }

    TrackFakeAllocW(alloc);
    *result = &alloc->ai;
    return 0;
}

static BOOL IsFakeDestination(const struct sockaddr *name, int namelen)
{
    if (!name || name->sa_family != AF_INET || namelen < (int)sizeof(SOCKADDR_IN)) {
        return FALSE;
    }
    const SOCKADDR_IN *target = (const SOCKADDR_IN *)name;
    uint32_t ip = ntohl(target->sin_addr.s_addr);
    return (ip & CP_FAKE_NET_MASK) == CP_FAKE_NET;
}

static int WSAAPI DetourSendTo(
    SOCKET socket,
    const char *buffer,
    int length,
    int flags,
    const struct sockaddr *to,
    int toLength)
{
    HOOK_CONFIG cfg;
    if (GetActiveConfig(&cfg) && IsFakeDestination(to, toLength)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    return g_realSendTo(socket, buffer, length, flags, to, toLength);
}

static INT WSAAPI DetourWsaSendTo(
    SOCKET socket,
    LPWSABUF buffers,
    DWORD bufferCount,
    LPDWORD bytesSent,
    DWORD flags,
    const struct sockaddr *to,
    int toLength,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    HOOK_CONFIG cfg;
    if (GetActiveConfig(&cfg) && IsFakeDestination(to, toLength)) {
        if (bytesSent) {
            *bytesSent = 0;
        }
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    return g_realWsaSendTo(socket, buffers, bufferCount, bytesSent, flags, to, toLength, overlapped, completion);
}

/* ------------------------------------------------------------------ */
/* 初始化                                                              */
/* ------------------------------------------------------------------ */

static HANDLE g_readyEvent;

static void SignalReady(void)
{
    WCHAR name[160];
    swprintf_s(name, _countof(name),
        L"Local\\Nexsteaduser.CulvertProxy.HookReady.%lu", GetCurrentProcessId());
    /* 句柄必须保留，关闭后命名事件会立刻销毁。 */
    if (!g_readyEvent) {
        g_readyEvent = CreateEventW(NULL, TRUE, TRUE, name);
    }
}

static void InstallHook(const char *name, LPVOID detour, LPVOID *original)
{
    MH_STATUS status = MH_CreateHookApi(L"ws2_32.dll", name, detour, original);
    if (status != MH_OK && status != MH_ERROR_ALREADY_CREATED) {
        WCHAR message[128];
        swprintf_s(message, _countof(message),
            L"CulvertHook: 无法挂钩 %S，状态 %d\n", name, (int)status);
        OutputDebugStringW(message);
    }
}

static DWORD WINAPI InitThread(LPVOID parameter)
{
    (void)parameter;
    LoadLibraryW(L"ws2_32.dll");
    RefreshConfig(TRUE);

    if (MH_Initialize() != MH_OK) {
        SignalReady();
        return 0;
    }

    /* 先取 ConnectEx 原始指针，此时 WSAIoctl 尚未挂钩。 */
    InstallConnectExHook();

    InstallHook("connect", (LPVOID)DetourConnect, (LPVOID *)&g_realConnect);
    InstallHook("WSAConnect", (LPVOID)DetourWsaConnect, (LPVOID *)&g_realWsaConnect);
    InstallHook("getaddrinfo", (LPVOID)DetourGetAddrInfo, (LPVOID *)&g_realGetAddrInfo);
    InstallHook("freeaddrinfo", (LPVOID)DetourFreeAddrInfo, (LPVOID *)&g_realFreeAddrInfo);
    InstallHook("GetAddrInfoW", (LPVOID)DetourGetAddrInfoW, (LPVOID *)&g_realGetAddrInfoW);
    InstallHook("sendto", (LPVOID)DetourSendTo, (LPVOID *)&g_realSendTo);
    InstallHook("WSASendTo", (LPVOID)DetourWsaSendTo, (LPVOID *)&g_realWsaSendTo);
    InstallHook("WSAIoctl", (LPVOID)DetourWsaIoctl, (LPVOID *)&g_realWsaIoctl);
    MH_EnableHook(MH_ALL_HOOKS);

    InterlockedExchange(&g_started, 1);
    SignalReady();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = instance;
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (thread) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}

__declspec(dllexport) DWORD WINAPI CulvertHookVersion(void)
{
    return (CP_VERSION << 16) | 1;
}
