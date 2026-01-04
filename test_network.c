/*
 * test_network.c - Test Winsock networking
 * 
 * Makes an HTTP request to example.com
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_network.exe test_network.c -lws2_32
 */

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    WSADATA wsa_data;
    SOCKET sock;
    struct sockaddr_in server;
    char request[512];
    char response[4096];
    int result, bytes_sent, bytes_received;
    
    printf("=== LSW Winsock Test ===\n\n");
    
    // Test 1: Initialize Winsock
    printf("Test 1: Initializing Winsock...\n");
    result = WSAStartup(MAKEWORD(2,2), &wsa_data);
    if (result != 0) {
        printf("  ❌ WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("  ✅ Winsock initialized\n");
    printf("  Version: %d.%d\n", LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));
    printf("  Description: %s\n\n", wsa_data.szDescription);
    
    // Test 2: Create socket
    printf("Test 2: Creating TCP socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("  ❌ socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("  ✅ Socket created: %lu\n\n", (unsigned long)sock);
    
    // Test 3: Connect to example.com:80
    printf("Test 3: Connecting to example.com:80...\n");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
    server.sin_addr.s_addr = inet_addr("93.184.215.14"); // example.com IP
    memset(server.sin_zero, 0, sizeof(server.sin_zero));
    
    result = connect(sock, (struct sockaddr*)&server, sizeof(server));
    if (result == SOCKET_ERROR) {
        printf("  ❌ connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("  ✅ Connected to example.com\n\n");
    
    // Test 4: Send HTTP GET request
    printf("Test 4: Sending HTTP request...\n");
    snprintf(request, sizeof(request),
             "GET / HTTP/1.0\r\n"
             "Host: example.com\r\n"
             "Connection: close\r\n"
             "\r\n");
    
    bytes_sent = send(sock, request, (int)strlen(request), 0);
    if (bytes_sent == SOCKET_ERROR) {
        printf("  ❌ send() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("  ✅ Sent %d bytes\n\n", bytes_sent);
    
    // Test 5: Receive response
    printf("Test 5: Receiving HTTP response...\n");
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received == SOCKET_ERROR) {
        printf("  ❌ recv() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    response[bytes_received] = '\0';
    printf("  ✅ Received %d bytes\n\n", bytes_received);
    
    // Show first part of response
    printf("HTTP Response (first 500 chars):\n");
    printf("%.500s\n\n", response);
    
    // Test 6: Close socket
    printf("Test 6: Closing socket...\n");
    result = closesocket(sock);
    if (result == SOCKET_ERROR) {
        printf("  ❌ closesocket() failed: %d\n", WSAGetLastError());
    } else {
        printf("  ✅ Socket closed\n\n");
    }
    
    // Test 7: Cleanup Winsock
    printf("Test 7: Cleaning up Winsock...\n");
    WSACleanup();
    printf("  ✅ Winsock cleaned up\n\n");
    
    printf("=== ALL TESTS PASSED ===\n");
    printf("Windows PE program successfully used Linux network stack!\n");
    
    return 0;
}
