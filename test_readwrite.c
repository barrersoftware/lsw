#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing CreateFile + WriteFile + ReadFile\n");
    
    // Create/open file
    HANDLE hFile = CreateFileA(
        "test_data.txt",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA failed!\n");
        return 1;
    }
    printf("File created: handle=%p\n", hFile);
    
    // Write data
    const char* writeData = "Hello from LSW ReadFile test!";
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, writeData, strlen(writeData), &bytesWritten, NULL)) {
        printf("WriteFile failed!\n");
        CloseHandle(hFile);
        return 1;
    }
    printf("Wrote %lu bytes\n", bytesWritten);
    
    // Close and reopen for reading
    CloseHandle(hFile);
    
    hFile = CreateFileA(
        "test_data.txt",
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA for reading failed!\n");
        return 1;
    }
    printf("File reopened for reading\n");
    
    // Read data
    char readBuffer[256] = {0};
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, readBuffer, sizeof(readBuffer) - 1, &bytesRead, NULL)) {
        printf("ReadFile failed!\n");
        CloseHandle(hFile);
        return 1;
    }
    
    printf("Read %lu bytes: '%s'\n", bytesRead, readBuffer);
    
    CloseHandle(hFile);
    printf("Test complete!\n");
    
    return 0;
}
