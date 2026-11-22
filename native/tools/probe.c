/*
 * CulvertProxy 端到端诊断探针。
 * 使用 Winsock getaddrinfo + connect，验证注入后的 fake-IP 与接管链路。
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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* 验证宽字符 getaddrinfo 路径及 AF_INET6 的 v4-mapped fake 地址。 */
static void ProbeWide(const char *host, const char *service)
{
    WCHAR wideHost[256];
    WCHAR wideService[32];
    if (MultiByteToWideChar(CP_UTF8, 0, host, -1, wideHost, _countof(wideHost)) == 0
        || MultiByteToWideChar(CP_UTF8, 0, service, -1, wideService, _countof(wideService)) == 0) {
        printf("WIDE_FAIL conversion\n");
        return;
    }

    ADDRINFOW hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOW results = NULL;
    if (GetAddrInfoW(wideHost, wideService, &hints, &results) != 0 || !results) {
        printf("WIDE_FAIL %d\n", WSAGetLastError());
        return;
    }

    char address[INET6_ADDRSTRLEN] = "?";
    char port[16] = "?";
    getnameinfo(results->ai_addr, (socklen_t)results->ai_addrlen,
        address, sizeof(address), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("WIDE %s %s\n", address, port);
    FreeAddrInfoW(results);

    hints.ai_family = AF_INET6;
    results = NULL;
    if (GetAddrInfoW(wideHost, wideService, &hints, &results) != 0 || !results) {
        printf("WIDE6_FAIL %d\n", WSAGetLastError());
        return;
    }

    address[0] = '?';
    address[1] = 0;
    port[0] = '?';
    port[1] = 0;
    getnameinfo(results->ai_addr, (socklen_t)results->ai_addrlen,
        address, sizeof(address), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("WIDE6 %s %s family=%d\n", address, port, (int)results->ai_family);
    FreeAddrInfoW(results);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: probe <host> <port> [wait-ms]\n");
        return 64;
    }

    int waitMs = argc > 3 ? atoi(argv[3]) : 0;
    if (waitMs > 0) {
        Sleep((DWORD)waitMs);
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSA_START_FAIL\n");
        return 65;
    }

    ProbeWide(argv[1], argv[2]);

    ADDRINFOA hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOA results = NULL;
    int rc = getaddrinfo(argv[1], argv[2], &hints, &results);
    if (rc != 0) {
        printf("RESOLVE_FAIL %d\n", rc);
        WSACleanup();
        return 2;
    }

    const char *mode = argc > 4 ? argv[4] : "";
    if (strcmp(mode, "hold") == 0) {
        /* 给引擎关闭接管的窗口，随后用已缓存的 fake sockaddr 连接。 */
        printf("HOLD_FAKE\n");
        fflush(stdout);
        Sleep(4000);
    }

    for (ADDRINFOA *entry = results; entry; entry = entry->ai_next) {
        char address[INET6_ADDRSTRLEN] = "?";
        char service[16] = "?";
        getnameinfo(entry->ai_addr, (socklen_t)entry->ai_addrlen,
            address, sizeof(address), service, sizeof(service),
            NI_NUMERICHOST | NI_NUMERICSERV);
        printf("ADDR %s %s\n", address, service);
        fflush(stdout);

        SOCKET socket = WSASocketW(entry->ai_family, entry->ai_socktype, entry->ai_protocol, NULL, 0, 0);
        if (socket == INVALID_SOCKET) {
            continue;
        }

        if (connect(socket, entry->ai_addr, (int)entry->ai_addrlen) == 0) {
            const char message[] = "probe-ping";
            if (send(socket, message, (int)sizeof(message) - 1, 0) > 0) {
                char buffer[128];
                int received = recv(socket, buffer, sizeof(buffer), 0);
                if (received > 0) {
                    printf("OK %.*s\n", received, buffer);
                    fflush(stdout);
                    closesocket(socket);
                    freeaddrinfo(results);
                    WSACleanup();
                    return 0;
                }
            }
        } else {
            printf("CONNECT_FAIL %d\n", WSAGetLastError());
            fflush(stdout);
        }

        closesocket(socket);
    }

    freeaddrinfo(results);
    WSACleanup();
    return 3;
}
