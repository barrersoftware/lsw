/*
 * LSW (Linux Subsystem for Windows) - Userspace Kernel Interface
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Implementation of userspace kernel communication
 */

#include "shared/lsw_kernel_client.h"
#include "shared/lsw_log.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

int lsw_kernel_open(void)
{
    int fd = open(LSW_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        LSW_LOG_ERROR("Failed to open %s: %s", LSW_DEVICE_PATH, strerror(errno));
        return -1;
    }
    
    LSW_LOG_INFO("Opened LSW kernel device: fd=%d", fd);
    return fd;
}

void lsw_kernel_close(int fd)
{
    if (fd >= 0) {
        close(fd);
        LSW_LOG_INFO("Closed LSW kernel device");
    }
}

int lsw_kernel_register_pe(int fd, const struct lsw_pe_info *info)
{
    if (fd < 0 || !info) {
        LSW_LOG_ERROR("Invalid arguments to lsw_kernel_register_pe");
        return -1;
    }
    
    int ret = ioctl(fd, LSW_IOCTL_REGISTER_PE, info);
    if (ret < 0) {
        LSW_LOG_ERROR("Failed to register PE with kernel: %s", strerror(errno));
        return -1;
    }
    
    LSW_LOG_INFO("Successfully registered PE with kernel: PID=%u, base=0x%lx",
                 info->pid, info->base_address);
    return 0;
}

int lsw_kernel_unregister_pe(int fd, pid_t pid)
{
    if (fd < 0) {
        LSW_LOG_ERROR("Invalid file descriptor");
        return -1;
    }
    
    int ret = ioctl(fd, LSW_IOCTL_UNREGISTER_PE, (uint32_t)pid);
    if (ret < 0) {
        LSW_LOG_ERROR("Failed to unregister PE from kernel: %s", strerror(errno));
        return -1;
    }
    
    LSW_LOG_INFO("Successfully unregistered PE from kernel: PID=%u", pid);
    return 0;
}

int lsw_kernel_get_status(int fd)
{
    if (fd < 0) {
        LSW_LOG_ERROR("Invalid file descriptor");
        return -1;
    }
    
    int status = 0;
    int ret = ioctl(fd, LSW_IOCTL_GET_STATUS, &status);
    if (ret < 0) {
        LSW_LOG_ERROR("Failed to get kernel status: %s", strerror(errno));
        return -1;
    }
    
    LSW_LOG_INFO("Kernel status: %d PE processes registered", status);
    return status;
}
