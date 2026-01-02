#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing complete file I/O operations\n\n");
    
    // Create and write a file
    HANDLE hFile = CreateFileA("testfile.dat", GENERIC_WRITE | GENERIC_READ, 
                               0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("ERROR: CreateFile failed\n");
        return 1;
    }
    printf("✓ File created\n");
    
    // Write some data
    const char* data = "Hello World from LSW file operations!";
    DWORD written = 0;
    if (!WriteFile(hFile, data, strlen(data), &written, NULL)) {
        printf("ERROR: WriteFile failed\n");
        return 1;
    }
    printf("✓ Wrote %lu bytes\n", written);
    
    // Get file size
    DWORD sizeHigh = 0;
    DWORD sizeLow = GetFileSize(hFile, &sizeHigh);
    printf("✓ GetFileSize: %lu bytes (high=%lu)\n", sizeLow, sizeHigh);
    
    // Set file pointer to beginning
    DWORD newPos = SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    printf("✓ SetFilePointer to start: position=%lu\n", newPos);
    
    // Read the data back
    char buffer[256] = {0};
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, sizeof(buffer)-1, &bytesRead, NULL)) {
        printf("ERROR: ReadFile failed\n");
        return 1;
    }
    printf("✓ Read %lu bytes: '%s'\n", bytesRead, buffer);
    
    // Seek to middle
    newPos = SetFilePointer(hFile, 6, NULL, FILE_BEGIN);
    printf("✓ SetFilePointer to offset 6: position=%lu\n", newPos);
    
    // Read from middle
    memset(buffer, 0, sizeof(buffer));
    if (!ReadFile(hFile, buffer, 10, &bytesRead, NULL)) {
        printf("ERROR: ReadFile from middle failed\n");
        return 1;
    }
    printf("✓ Read from middle: '%s'\n", buffer);
    
    CloseHandle(hFile);
    printf("✓ File closed\n\n");
    
    // Test DeleteFile
    printf("Testing DeleteFileA...\n");
    if (DeleteFileA("testfile.dat")) {
        printf("✓ File deleted successfully\n");
    } else {
        printf("ERROR: DeleteFileA failed\n");
        return 1;
    }
    
    printf("\n🏴‍☠️ ALL FILE OPERATIONS WORKING!\n");
    return 0;
}
