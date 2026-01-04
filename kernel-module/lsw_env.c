/**
 * lsw_env.c - Environment and System Information subsystem
 * 
 * Provides Windows environment variables and system information
 * with version spoofing support for compatibility modes
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sysinfo.h>
#include <linux/mm.h>
#include <asm/processor.h>
#include "../include/kernel-module/lsw_kernel.h"

/* Windows version constants */
#define WIN_XP_MAJOR        5
#define WIN_XP_MINOR        1
#define WIN_VISTA_MAJOR     6
#define WIN_VISTA_MINOR     0
#define WIN_7_MAJOR         6
#define WIN_7_MINOR         1
#define WIN_8_MAJOR         6
#define WIN_8_MINOR         2
#define WIN_10_MAJOR        10
#define WIN_10_MINOR        0

/* Processor architectures */
#define PROCESSOR_ARCHITECTURE_INTEL    0
#define PROCESSOR_ARCHITECTURE_AMD64    9

/* Current version override (default to Windows 10) */
static __u32 current_major_version = WIN_10_MAJOR;
static __u32 current_minor_version = WIN_10_MINOR;
static __u32 current_build_number = 19045;  /* Windows 10 22H2 */

/**
 * lsw_env_set_version - Set Windows version for compatibility mode
 */
int lsw_env_set_version(const char *version_string)
{
    if (!version_string) {
        return -EINVAL;
    }
    
    lsw_info("Setting Windows version to: %s", version_string);
    
    if (strcmp(version_string, "winxp") == 0) {
        current_major_version = WIN_XP_MAJOR;
        current_minor_version = WIN_XP_MINOR;
        current_build_number = 2600;
        lsw_info("Version set to Windows XP (5.1.2600)");
    }
    else if (strcmp(version_string, "vista") == 0) {
        current_major_version = WIN_VISTA_MAJOR;
        current_minor_version = WIN_VISTA_MINOR;
        current_build_number = 6002;
        lsw_info("Version set to Windows Vista (6.0.6002)");
    }
    else if (strcmp(version_string, "win7") == 0) {
        current_major_version = WIN_7_MAJOR;
        current_minor_version = WIN_7_MINOR;
        current_build_number = 7601;
        lsw_info("Version set to Windows 7 (6.1.7601)");
    }
    else if (strcmp(version_string, "win8") == 0) {
        current_major_version = WIN_8_MAJOR;
        current_minor_version = WIN_8_MINOR;
        current_build_number = 9200;
        lsw_info("Version set to Windows 8 (6.2.9200)");
    }
    else if (strcmp(version_string, "win10") == 0) {
        current_major_version = WIN_10_MAJOR;
        current_minor_version = WIN_10_MINOR;
        current_build_number = 19045;
        lsw_info("Version set to Windows 10 (10.0.19045)");
    }
    else {
        lsw_err("Unknown version string: %s", version_string);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * lsw_env_GetVersion - Get Windows version (legacy API)
 * 
 * Returns version in format: 0xMMmmBBBB
 *   MM = Major version
 *   mm = Minor version
 *   BBBB = Build number
 */
__u32 lsw_env_GetVersion(void)
{
    __u32 version;
    
    /* Pack version into DWORD: minor.major.build */
    version = (current_minor_version << 8) | current_major_version;
    
    lsw_info("GetVersion: returning %u.%u (0x%08x)",
             current_major_version, current_minor_version, version);
    
    return version;
}

/**
 * lsw_env_GetSystemInfo - Get system information
 * 
 * VOID GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
 */
int lsw_env_GetSystemInfo(void __user *system_info_ptr)
{
    struct {
        union {
            __u32 dwOemId;
            struct {
                __u16 wProcessorArchitecture;
                __u16 wReserved;
            } arch;
        } proc;
        __u32 dwPageSize;
        __u64 lpMinimumApplicationAddress;
        __u64 lpMaximumApplicationAddress;
        __u64 dwActiveProcessorMask;
        __u32 dwNumberOfProcessors;
        __u32 dwProcessorType;
        __u32 dwAllocationGranularity;
        __u16 wProcessorLevel;
        __u16 wProcessorRevision;
    } sysinfo;
    
    lsw_info("GetSystemInfo called");
    
    memset(&sysinfo, 0, sizeof(sysinfo));
    
    /* Processor architecture */
#ifdef CONFIG_X86_64
    sysinfo.proc.arch.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
    sysinfo.proc.arch.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif
    
    /* Page size */
    sysinfo.dwPageSize = PAGE_SIZE;
    
    /* Application address range */
    sysinfo.lpMinimumApplicationAddress = 0x10000;  /* 64KB */
#ifdef CONFIG_X86_64
    sysinfo.lpMaximumApplicationAddress = 0x00007FFFFFFEFFFF;  /* 128TB on x64 */
#else
    sysinfo.lpMaximumApplicationAddress = 0x7FFEFFFF;  /* 2GB on x86 */
#endif
    
    /* Processor information */
    sysinfo.dwNumberOfProcessors = num_online_cpus();
    sysinfo.dwActiveProcessorMask = (1ULL << sysinfo.dwNumberOfProcessors) - 1;
    
    /* Processor type (generic) */
    sysinfo.dwProcessorType = 586;  /* Intel Pentium or compatible */
    
    /* Allocation granularity (64KB) */
    sysinfo.dwAllocationGranularity = 65536;
    
    /* Processor level and revision */
    sysinfo.wProcessorLevel = 6;  /* Modern processors */
    sysinfo.wProcessorRevision = 0;
    
    /* Copy to userspace */
    if (copy_to_user(system_info_ptr, &sysinfo, sizeof(sysinfo))) {
        lsw_err("Failed to copy system info to userspace");
        return -EFAULT;
    }
    
    lsw_info("Returned system info: %u CPUs, page size %u",
             sysinfo.dwNumberOfProcessors, sysinfo.dwPageSize);
    
    return 0;
}

/**
 * lsw_env_GetEnvironmentVariable - Get environment variable
 * 
 * DWORD GetEnvironmentVariableA(
 *   LPCSTR lpName,
 *   LPSTR  lpBuffer,
 *   DWORD  nSize
 * );
 */
int lsw_env_GetEnvironmentVariable(
    const char __user *name_ptr,
    char __user *buffer_ptr,
    __u32 buffer_size,
    __u32 __user *result_ptr)
{
    char name[256];
    char *value_kernel;
    __u32 value_len;
    int ret = 0;
    
    /* Copy variable name from userspace */
    if (strncpy_from_user(name, name_ptr, sizeof(name)) < 0) {
        lsw_err("Failed to copy variable name from userspace");
        return -EFAULT;
    }
    name[sizeof(name) - 1] = '\0';
    
    lsw_info("GetEnvironmentVariable: %s", name);
    
    /* Allocate kernel buffer for value */
    value_kernel = kmalloc(4096, GFP_KERNEL);
    if (!value_kernel) {
        return -ENOMEM;
    }
    
    /* Map common Windows environment variables to Linux equivalents */
    if (strcmp(name, "PATH") == 0) {
        /* Default Linux-style PATH */
        strcpy(value_kernel, "/usr/local/bin:/usr/bin:/bin");
    }
    else if (strcmp(name, "TEMP") == 0 || strcmp(name, "TMP") == 0) {
        strcpy(value_kernel, "/tmp");
    }
    else if (strcmp(name, "USERPROFILE") == 0 || strcmp(name, "HOME") == 0) {
        /* Default home directory */
        strcpy(value_kernel, "/home/user");
    }
    else if (strcmp(name, "APPDATA") == 0) {
        strcpy(value_kernel, "/home/user/.config");
    }
    else if (strcmp(name, "LOCALAPPDATA") == 0) {
        strcpy(value_kernel, "/home/user/.local/share");
    }
    else if (strcmp(name, "PROGRAMFILES") == 0) {
        strcpy(value_kernel, "/opt");
    }
    else if (strcmp(name, "SYSTEMROOT") == 0 || strcmp(name, "WINDIR") == 0) {
        strcpy(value_kernel, "/");
    }
    else {
        /* Variable not found */
        lsw_info("Environment variable '%s' not found", name);
        value_kernel[0] = '\0';
        ret = 0;  /* Return 0 to indicate not found */
        goto out;
    }
    
    value_kernel[4095] = '\0';
    value_len = strlen(value_kernel);
    
    lsw_info("Environment variable '%s' = '%s' (len=%u)", name, value_kernel, value_len);
    
    /* Copy value to userspace buffer if provided */
    if (buffer_ptr && buffer_size > 0) {
        __u32 copy_len = (value_len < buffer_size) ? value_len : buffer_size - 1;
        
        if (copy_to_user(buffer_ptr, value_kernel, copy_len)) {
            lsw_err("Failed to copy value to userspace");
            ret = -EFAULT;
            goto out;
        }
        
        /* Null terminate */
        if (put_user('\0', buffer_ptr + copy_len)) {
            lsw_err("Failed to null-terminate buffer");
            ret = -EFAULT;
            goto out;
        }
    }
    
    /* Return required buffer size (including null terminator) */
    ret = value_len + 1;
    
out:
    if (result_ptr) {
        __u32 result = (__u32)ret;
        if (copy_to_user(result_ptr, &result, sizeof(__u32))) {
            lsw_err("Failed to copy result to userspace");
            kfree(value_kernel);
            return -EFAULT;
        }
    }
    
    kfree(value_kernel);
    return 0;
}

/**
 * lsw_env_init - Initialize environment subsystem
 */
int lsw_env_init(void)
{
    lsw_info("Initializing Environment/System Info subsystem");
    lsw_info("Default version: Windows 10 (%u.%u.%u)",
             current_major_version, current_minor_version, current_build_number);
    return 0;
}

/**
 * lsw_env_cleanup - Cleanup environment subsystem
 */
void lsw_env_cleanup(void)
{
    lsw_info("Cleaning up Environment/System Info subsystem");
}
