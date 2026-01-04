/*
 * test_file_cdrive.c - Test C: drive mapping
 * 
 * Compile with: x86_64-w64-mingw32-gcc -o test_file_cdrive.exe test_file_cdrive.c
 */

#include <windows.h>
#include <stdio.h>

int main(void)
{
    HANDLE hFile;
    DWORD written;
    const char* data = "Hello from C: drive!\n";
    BOOL result;
    
    printf("LSW C: Drive Test\n");
    printf("==================\n\n");
    
    /* Create file on C: drive */
    printf("Creating C:\\test.txt...\n");
    hFile = CreateFileA("C:\\test.txt",
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("ERROR: Failed to create file!\n");
        return 1;
    }
    
    printf("File created, handle: 0x%p\n", hFile);
    
    /* Write data */
    printf("Writing data...\n");
    result = WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
    
    if (!result) {
        printf("ERROR: WriteFile failed!\n");
        CloseHandle(hFile);
        return 1;
    }
    
    printf("Wrote %lu bytes\n", written);
    
    /* Close file */
    printf("Closing file...\n");
    CloseHandle(hFile);
    
    printf("\n=== SUCCESS ===\n");
    printf("C:\\test.txt should exist at: ~/.lsw/drives/c/test.txt\n");
    
    return 0;
}
