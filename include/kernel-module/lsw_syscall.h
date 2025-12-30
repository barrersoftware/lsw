/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Win32 Syscall Definitions and Translation Layer
 * 
 * Based on official Windows NT syscall specifications
 */

#ifndef LSW_SYSCALL_H
#define LSW_SYSCALL_H

#include <linux/types.h>

/* Win32 Syscall Numbers (NT Kernel - partial list for MVP) */
#define LSW_SYSCALL_NtCreateFile          0x0055
#define LSW_SYSCALL_NtReadFile            0x0006
#define LSW_SYSCALL_NtWriteFile           0x0008
#define LSW_SYSCALL_NtClose               0x000f
#define LSW_SYSCALL_NtAllocateVirtualMemory 0x0018
#define LSW_SYSCALL_NtFreeVirtualMemory   0x001e
#define LSW_SYSCALL_NtCreateThread        0x004e
#define LSW_SYSCALL_NtTerminateThread     0x0053
#define LSW_SYSCALL_NtQueryInformationProcess 0x0019
#define LSW_SYSCALL_NtDelayExecution      0x0033
#define LSW_SYSCALL_NtQuerySystemInformation 0x0036

/* Syscall request structure from userspace */
struct lsw_syscall_request {
    __u32 syscall_number;    /* Win32 syscall number */
    __u32 arg_count;         /* Number of arguments */
    __u64 args[8];           /* Syscall arguments (max 8) */
    __u64 return_value;      /* Return value (filled by kernel) */
    __s32 error_code;        /* Error code (filled by kernel) */
};

/* Syscall handler function type */
typedef long (*lsw_syscall_handler_t)(struct lsw_syscall_request *req);

/* Syscall translation functions */
long lsw_handle_syscall(struct lsw_syscall_request *req);

/* Individual syscall handlers */
long lsw_syscall_NtCreateFile(struct lsw_syscall_request *req);
long lsw_syscall_NtReadFile(struct lsw_syscall_request *req);
long lsw_syscall_NtWriteFile(struct lsw_syscall_request *req);
long lsw_syscall_NtClose(struct lsw_syscall_request *req);
long lsw_syscall_NtAllocateVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtFreeVirtualMemory(struct lsw_syscall_request *req);
long lsw_syscall_NtQuerySystemInformation(struct lsw_syscall_request *req);

/* Initialize syscall translation system */
int lsw_syscall_init(void);
void lsw_syscall_exit(void);

#endif /* LSW_SYSCALL_H */
