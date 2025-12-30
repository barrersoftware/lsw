/*
 * LSW (Linux Subsystem for Windows) - Kernel Module
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under Barrer Free Software License (BFSL) v1.2
 * 
 * Process and Thread Management Implementation
 * Creates real Linux processes for Win32 executables
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "../include/kernel-module/lsw_kernel.h"
#include "../include/kernel-module/lsw_process.h"
#include "../include/kernel-module/lsw_dll.h"
#include "../include/kernel-module/lsw_pe.h"

/* Global process and thread lists */
static LIST_HEAD(lsw_process_list);
static LIST_HEAD(lsw_thread_list);
static DEFINE_MUTEX(lsw_process_mutex);
static __u32 next_win32_pid = 1000;
static __u32 next_win32_tid = 2000;

/* Statistics */
static atomic_t lsw_process_count = ATOMIC_INIT(0);
static atomic_t lsw_thread_count = ATOMIC_INIT(0);

/**
 * lsw_process_thread_func - Kernel thread for Win32 process
 */
static int lsw_process_thread_func(void *data)
{
    struct lsw_process *proc = (struct lsw_process *)data;
    
    lsw_info("Win32 process thread started: PID=%u, entry=0x%llx",
             proc->win32_pid, proc->entry_point);
    
    /* TODO: Set up Win32 environment and jump to entry point */
    /* For now, just sleep to demonstrate process creation */
    msleep(5000);
    
    lsw_info("Win32 process thread exiting: PID=%u", proc->win32_pid);
    
    return 0;
}

/**
 * lsw_process_create - Create a Win32 process
 */
int lsw_process_create(const char *path, __u32 *win32_pid)
{
    struct lsw_process *proc;
    struct task_struct *task;
    __u64 base_address = 0;
    int ret;
    __u32 pid;
    
    lsw_info("Creating Win32 process: path='%s'", path);
    
    /* Allocate process structure */
    proc = kmalloc(sizeof(*proc), GFP_KERNEL);
    if (!proc) {
        lsw_err("Failed to allocate process structure");
        return -ENOMEM;
    }
    
    /* Assign Win32 PID */
    mutex_lock(&lsw_process_mutex);
    pid = next_win32_pid++;
    mutex_unlock(&lsw_process_mutex);
    
    proc->win32_pid = pid;
    proc->linux_pid = 0;  /* Will be set when thread starts */
    strncpy(proc->executable, path, sizeof(proc->executable) - 1);
    proc->executable[sizeof(proc->executable) - 1] = '\0';
    
    /* Load the executable as a DLL (it's a PE file) */
    ret = lsw_dll_load(pid, path, &base_address);
    if (ret != 0) {
        lsw_err("Failed to load executable: %d", ret);
        kfree(proc);
        return ret;
    }
    
    proc->image_base = base_address;
    proc->entry_point = base_address + 0x1000;  /* TODO: Get from PE header */
    
    lsw_info("Executable loaded: base=0x%llx, entry=0x%llx",
             proc->image_base, proc->entry_point);
    
    /* Create kernel thread for this process */
    task = kthread_run(lsw_process_thread_func, proc,
                       "lsw_proc_%u", proc->win32_pid);
    if (IS_ERR(task)) {
        lsw_err("Failed to create process thread: %ld", PTR_ERR(task));
        lsw_dll_unload(base_address);
        kfree(proc);
        return PTR_ERR(task);
    }
    
    proc->task = task;
    proc->linux_pid = task->pid;
    
    /* Add to process list */
    mutex_lock(&lsw_process_mutex);
    list_add(&proc->list, &lsw_process_list);
    mutex_unlock(&lsw_process_mutex);
    
    atomic_inc(&lsw_process_count);
    
    lsw_info("Win32 process created: Win32 PID=%u, Linux PID=%u",
             proc->win32_pid, proc->linux_pid);
    
    if (win32_pid) {
        *win32_pid = proc->win32_pid;
    }
    
    return 0;
}

/**
 * lsw_thread_func - Kernel thread for Win32 thread
 */
static int lsw_thread_func(void *data)
{
    struct lsw_thread *thread = (struct lsw_thread *)data;
    
    lsw_info("Win32 thread started: TID=%u, start=0x%llx",
             thread->win32_tid, thread->start_address);
    
    /* TODO: Set up thread environment and jump to start address */
    /* For now, just sleep to demonstrate thread creation */
    msleep(3000);
    
    lsw_info("Win32 thread exiting: TID=%u", thread->win32_tid);
    
    return 0;
}

/**
 * lsw_thread_create - Create a Win32 thread
 */
int lsw_thread_create(__u32 win32_pid, __u64 start_address, 
                      __u64 parameter, __u32 *win32_tid)
{
    struct lsw_thread *thread;
    struct task_struct *task;
    __u32 tid;
    
    lsw_info("Creating Win32 thread: PID=%u, start=0x%llx, param=0x%llx",
             win32_pid, start_address, parameter);
    
    /* Allocate thread structure */
    thread = kmalloc(sizeof(*thread), GFP_KERNEL);
    if (!thread) {
        lsw_err("Failed to allocate thread structure");
        return -ENOMEM;
    }
    
    /* Assign Win32 TID */
    mutex_lock(&lsw_process_mutex);
    tid = next_win32_tid++;
    mutex_unlock(&lsw_process_mutex);
    
    thread->win32_tid = tid;
    thread->win32_pid = win32_pid;
    thread->start_address = start_address;
    
    /* Create kernel thread */
    task = kthread_run(lsw_thread_func, thread,
                       "lsw_thread_%u", thread->win32_tid);
    if (IS_ERR(task)) {
        lsw_err("Failed to create thread: %ld", PTR_ERR(task));
        kfree(thread);
        return PTR_ERR(task);
    }
    
    thread->task = task;
    thread->linux_tid = task->pid;
    
    /* Add to thread list */
    mutex_lock(&lsw_process_mutex);
    list_add(&thread->list, &lsw_thread_list);
    mutex_unlock(&lsw_process_mutex);
    
    atomic_inc(&lsw_thread_count);
    
    lsw_info("Win32 thread created: Win32 TID=%u, Linux TID=%u",
             thread->win32_tid, thread->linux_tid);
    
    if (win32_tid) {
        *win32_tid = thread->win32_tid;
    }
    
    return 0;
}

/**
 * lsw_process_terminate - Terminate a process
 */
int lsw_process_terminate(__u32 win32_pid, __u32 exit_code)
{
    struct lsw_process *proc, *tmp;
    int found = 0;
    
    lsw_info("Terminating Win32 process: PID=%u, exit_code=%u",
             win32_pid, exit_code);
    
    mutex_lock(&lsw_process_mutex);
    
    list_for_each_entry_safe(proc, tmp, &lsw_process_list, list) {
        if (proc->win32_pid == win32_pid) {
            found = 1;
            
            /* Stop the kernel thread */
            if (proc->task) {
                kthread_stop(proc->task);
            }
            
            /* Unload the executable */
            if (proc->image_base) {
                lsw_dll_unload(proc->image_base);
            }
            
            atomic_dec(&lsw_process_count);
            
            list_del(&proc->list);
            kfree(proc);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_process_mutex);
    
    if (!found) {
        lsw_warn("Process not found: PID=%u", win32_pid);
        return -ESRCH;
    }
    
    lsw_info("Process terminated successfully");
    
    return 0;
}

/**
 * lsw_thread_terminate - Terminate a thread
 */
int lsw_thread_terminate(__u32 win32_tid, __u32 exit_code)
{
    struct lsw_thread *thread, *tmp;
    int found = 0;
    
    lsw_info("Terminating Win32 thread: TID=%u, exit_code=%u",
             win32_tid, exit_code);
    
    mutex_lock(&lsw_process_mutex);
    
    list_for_each_entry_safe(thread, tmp, &lsw_thread_list, list) {
        if (thread->win32_tid == win32_tid) {
            found = 1;
            
            /* Stop the kernel thread */
            if (thread->task) {
                kthread_stop(thread->task);
            }
            
            atomic_dec(&lsw_thread_count);
            
            list_del(&thread->list);
            kfree(thread);
            
            break;
        }
    }
    
    mutex_unlock(&lsw_process_mutex);
    
    if (!found) {
        lsw_warn("Thread not found: TID=%u", win32_tid);
        return -ESRCH;
    }
    
    lsw_info("Thread terminated successfully");
    
    return 0;
}

/**
 * lsw_process_init - Initialize process system
 */
int lsw_process_init(void)
{
    lsw_info("Process/thread management system initialized");
    lsw_info("Ready to create Win32 processes and threads");
    return 0;
}

/**
 * lsw_process_exit - Cleanup process system
 */
void lsw_process_exit(void)
{
    struct lsw_process *proc, *ptmp;
    struct lsw_thread *thread, *ttmp;
    int proc_count = 0, thread_count = 0;
    
    mutex_lock(&lsw_process_mutex);
    
    /* Cleanup threads */
    list_for_each_entry_safe(thread, ttmp, &lsw_thread_list, list) {
        lsw_warn("Thread leak: TID=%u", thread->win32_tid);
        
        if (thread->task) {
            kthread_stop(thread->task);
        }
        
        thread_count++;
        list_del(&thread->list);
        kfree(thread);
    }
    
    /* Cleanup processes */
    list_for_each_entry_safe(proc, ptmp, &lsw_process_list, list) {
        lsw_warn("Process leak: PID=%u, exe='%s'",
                 proc->win32_pid, proc->executable);
        
        if (proc->task) {
            kthread_stop(proc->task);
        }
        
        if (proc->image_base) {
            lsw_dll_unload(proc->image_base);
        }
        
        proc_count++;
        list_del(&proc->list);
        kfree(proc);
    }
    
    mutex_unlock(&lsw_process_mutex);
    
    if (proc_count > 0 || thread_count > 0) {
        lsw_warn("Cleaned up %d processes and %d threads during exit",
                 proc_count, thread_count);
    }
    
    lsw_info("Process/thread management system cleaned up");
}
