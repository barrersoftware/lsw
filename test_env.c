/*
 * test_env.c - Test Environment and System Info functionality
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_env.exe test_env.c
 */

#include <windows.h>
#include <stdio.h>

int main(void)
{
    SYSTEM_INFO sysinfo;
    DWORD version;
    char buffer[1024];
    DWORD result;
    
    printf("LSW Environment/System Info Test\n");
    printf("=================================\n\n");
    
    /* Test GetVersion */
    version = GetVersion();
    printf("GetVersion: 0x%08lX\n", version);
    printf("  Major: %lu\n", (version & 0xFF));
    printf("  Minor: %lu\n", ((version >> 8) & 0xFF));
    printf("  Build: %lu\n\n", (version >> 16));
    
    /* Test GetSystemInfo */
    GetSystemInfo(&sysinfo);
    printf("GetSystemInfo:\n");
    printf("  Processor Architecture: %u\n", sysinfo.wProcessorArchitecture);
    printf("  Number of Processors: %lu\n", sysinfo.dwNumberOfProcessors);
    printf("  Page Size: %lu bytes\n", sysinfo.dwPageSize);
    printf("  Allocation Granularity: %lu bytes\n", sysinfo.dwAllocationGranularity);
    printf("  Min App Address: 0x%p\n", sysinfo.lpMinimumApplicationAddress);
    printf("  Max App Address: 0x%p\n\n", sysinfo.lpMaximumApplicationAddress);
    
    /* Test GetEnvironmentVariable */
    printf("Environment Variables:\n");
    
    result = GetEnvironmentVariableA("PATH", buffer, sizeof(buffer));
    printf("  PATH: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    result = GetEnvironmentVariableA("TEMP", buffer, sizeof(buffer));
    printf("  TEMP: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    result = GetEnvironmentVariableA("HOME", buffer, sizeof(buffer));
    printf("  HOME: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    result = GetEnvironmentVariableA("APPDATA", buffer, sizeof(buffer));
    printf("  APPDATA: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    result = GetEnvironmentVariableA("WINDIR", buffer, sizeof(buffer));
    printf("  WINDIR: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    result = GetEnvironmentVariableA("PROGRAMFILES", buffer, sizeof(buffer));
    printf("  PROGRAMFILES: %s (len=%lu)\n", result ? buffer : "(not found)", result);
    
    printf("\n=== Environment/System Info Test Complete ===\n");
    
    return 0;
}
