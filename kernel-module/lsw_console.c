/**
 * lsw_console.c - Console I/O subsystem
 * 
 * Translates Windows Console API to Linux terminal/stdout/stderr
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "../include/kernel-module/lsw_kernel.h"

/* Standard handle identifiers from Windows */
#define STD_INPUT_HANDLE    ((__u32)-10)
#define STD_OUTPUT_HANDLE   ((__u32)-11)
#define STD_ERROR_HANDLE    ((__u32)-12)

/* Console handle mapping */
struct lsw_console_handle {
    __u64 lsw_handle;
    struct file *linux_file;
    int fd;  /* Linux file descriptor (0=stdin, 1=stdout, 2=stderr) */
};

static struct lsw_console_handle console_handles[3];
static bool console_initialized = false;

/**
 * lsw_console_init - Initialize console subsystem
 */
int lsw_console_init(void)
{
    lsw_info("Initializing Console I/O subsystem");
    
    /* Map standard handles */
    console_handles[0].lsw_handle = STD_INPUT_HANDLE;
    console_handles[0].fd = 0;
    console_handles[0].linux_file = NULL;
    
    console_handles[1].lsw_handle = STD_OUTPUT_HANDLE;
    console_handles[1].fd = 1;
    console_handles[1].linux_file = NULL;
    
    console_handles[2].lsw_handle = STD_ERROR_HANDLE;
    console_handles[2].fd = 2;
    console_handles[2].linux_file = NULL;
    
    console_initialized = true;
    lsw_info("Console I/O subsystem initialized");
    return 0;
}

/**
 * lsw_console_cleanup - Cleanup console subsystem
 */
void lsw_console_cleanup(void)
{
    int i;
    
    if (!console_initialized) {
        return;
    }
    
    lsw_info("Cleaning up Console I/O subsystem");
    
    for (i = 0; i < 3; i++) {
        if (console_handles[i].linux_file) {
            fput(console_handles[i].linux_file);
            console_handles[i].linux_file = NULL;
        }
    }
    
    console_initialized = false;
}

/**
 * lsw_console_get_linux_file - Get Linux file for standard handle
 */
static struct file *lsw_console_get_linux_file(__u32 std_handle)
{
    int i;
    
    for (i = 0; i < 3; i++) {
        if (console_handles[i].lsw_handle == std_handle) {
            /* Get current task's file descriptor */
            if (!console_handles[i].linux_file) {
                struct file *f = fget(console_handles[i].fd);
                if (f) {
                    console_handles[i].linux_file = f;
                }
            }
            return console_handles[i].linux_file;
        }
    }
    
    return NULL;
}

/**
 * lsw_console_GetStdHandle - Get standard handle
 * 
 * HANDLE GetStdHandle(DWORD nStdHandle);
 */
__u64 lsw_console_GetStdHandle(__u32 std_handle)
{
    int i;
    
    lsw_info("GetStdHandle: nStdHandle=%u", std_handle);
    
    /* Find matching standard handle */
    for (i = 0; i < 3; i++) {
        if (console_handles[i].lsw_handle == std_handle) {
            lsw_info("Returning handle: 0x%llx", console_handles[i].lsw_handle);
            return console_handles[i].lsw_handle;
        }
    }
    
    lsw_err("Invalid standard handle: %u", std_handle);
    return 0;
}

/**
 * lsw_console_WriteConsole - Write to console
 * 
 * BOOL WriteConsoleA(
 *   HANDLE  hConsoleOutput,
 *   const VOID *lpBuffer,
 *   DWORD   nNumberOfCharsToWrite,
 *   LPDWORD lpNumberOfCharsWritten,
 *   LPVOID  lpReserved
 * );
 */
int lsw_console_WriteConsole(
    __u64 handle,
    const void __user *buffer,
    __u32 chars_to_write,
    __u32 __user *chars_written_ptr)
{
    struct file *file;
    char *kernel_buf;
    ssize_t written;
    loff_t pos = 0;
    
    lsw_info("WriteConsole: handle=0x%llx, chars=%u", handle, chars_to_write);
    
    /* Get Linux file for this handle */
    file = lsw_console_get_linux_file((__u32)handle);
    if (!file) {
        lsw_err("Invalid console handle: 0x%llx", handle);
        return -EBADF;
    }
    
    /* Allocate kernel buffer */
    kernel_buf = kmalloc(chars_to_write + 1, GFP_KERNEL);
    if (!kernel_buf) {
        lsw_err("Failed to allocate buffer");
        return -ENOMEM;
    }
    
    /* Copy from userspace */
    if (copy_from_user(kernel_buf, buffer, chars_to_write)) {
        lsw_err("Failed to copy buffer from userspace");
        kfree(kernel_buf);
        return -EFAULT;
    }
    kernel_buf[chars_to_write] = '\0';
    
    /* Write to Linux file */
    written = kernel_write(file, kernel_buf, chars_to_write, &pos);
    
    kfree(kernel_buf);
    
    if (written < 0) {
        lsw_err("kernel_write failed: %ld", written);
        return (int)written;
    }
    
    /* Return chars written to userspace */
    if (chars_written_ptr) {
        __u32 written_count = (__u32)written;
        if (copy_to_user(chars_written_ptr, &written_count, sizeof(__u32))) {
            lsw_err("Failed to copy chars_written to userspace");
            return -EFAULT;
        }
    }
    
    lsw_info("Wrote %ld chars to console", written);
    return 0;
}

/**
 * lsw_console_ReadConsole - Read from console
 * 
 * BOOL ReadConsoleA(
 *   HANDLE  hConsoleInput,
 *   LPVOID  lpBuffer,
 *   DWORD   nNumberOfCharsToRead,
 *   LPDWORD lpNumberOfCharsRead,
 *   LPVOID  pInputControl
 * );
 */
int lsw_console_ReadConsole(
    __u64 handle,
    void __user *buffer,
    __u32 chars_to_read,
    __u32 __user *chars_read_ptr)
{
    struct file *file;
    char *kernel_buf;
    ssize_t bytes_read;
    loff_t pos = 0;
    
    lsw_info("ReadConsole: handle=0x%llx, chars=%u", handle, chars_to_read);
    
    /* Get Linux file for this handle */
    file = lsw_console_get_linux_file((__u32)handle);
    if (!file) {
        lsw_err("Invalid console handle: 0x%llx", handle);
        return -EBADF;
    }
    
    /* Allocate kernel buffer */
    kernel_buf = kmalloc(chars_to_read, GFP_KERNEL);
    if (!kernel_buf) {
        lsw_err("Failed to allocate buffer");
        return -ENOMEM;
    }
    
    /* Read from Linux file */
    bytes_read = kernel_read(file, kernel_buf, chars_to_read, &pos);
    
    if (bytes_read < 0) {
        lsw_err("kernel_read failed: %ld", bytes_read);
        kfree(kernel_buf);
        return (int)bytes_read;
    }
    
    /* Copy to userspace */
    if (copy_to_user(buffer, kernel_buf, bytes_read)) {
        lsw_err("Failed to copy buffer to userspace");
        kfree(kernel_buf);
        return -EFAULT;
    }
    
    kfree(kernel_buf);
    
    /* Return chars read to userspace */
    if (chars_read_ptr) {
        __u32 read_count = (__u32)bytes_read;
        if (copy_to_user(chars_read_ptr, &read_count, sizeof(__u32))) {
            lsw_err("Failed to copy chars_read to userspace");
            return -EFAULT;
        }
    }
    
    lsw_info("Read %ld chars from console", bytes_read);
    return 0;
}
