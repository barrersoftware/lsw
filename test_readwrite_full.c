/*
 * test_readwrite_full.c - Test file read/write cycle
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    HANDLE hFile;
    DWORD written, bytesRead;
    const char* write_data = "LSW Read/Write Test!\n";
    char read_buffer[256];
    BOOL result;
    
    printf("LSW Read/Write Cycle Test\n");
    printf("==========================\n\n");
    
    /* WRITE */
    printf("Step 1: Writing file...\n");
    hFile = CreateFileA("C:\\readtest.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("ERROR: Create failed!\n");
        return 1;
    }
    
    WriteFile(hFile, write_data, (DWORD)strlen(write_data), &written, NULL);
    printf("Wrote %lu bytes\n", written);
    CloseHandle(hFile);
    
    /* READ */
    printf("\nStep 2: Reading file...\n");
    hFile = CreateFileA("C:\\readtest.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("ERROR: Open failed!\n");
        return 1;
    }
    
    memset(read_buffer, 0, sizeof(read_buffer));
    ReadFile(hFile, read_buffer, sizeof(read_buffer) - 1, &bytesRead, NULL);
    printf("Read %lu bytes\n", bytesRead);
    printf("Data: '%s'\n", read_buffer);
    CloseHandle(hFile);
    
    /* VERIFY */
    if (strcmp(read_buffer, write_data) == 0) {
        printf("\n✅ SUCCESS! Read/Write cycle works!\n");
        return 0;
    } else {
        printf("\n❌ FAILURE! Data mismatch!\n");
        return 1;
    }
}
