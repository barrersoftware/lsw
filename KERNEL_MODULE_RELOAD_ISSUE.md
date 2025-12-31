# LSW Kernel Module Hot-Reload Issue

## The Problem
The LSW kernel module uses `__module_get(THIS_MODULE)` to prevent auto-unloading when configured with `module_persistent=true`. This creates a permanent reference that makes `rmmod` fail.

## Current State
```bash
$ lsmod | grep lsw
lsw                   131072  -1

$ cat /sys/module/lsw/refcnt
-1

$ cat /proc/modules | grep lsw  
lsw 131072 -1 - Unloading 0x0000000000000000 (OE-)
```

The module is stuck in "Unloading" state with refcount -1.

## Root Cause
In `kernel-module/lsw_main.c`:
```c
/* Increment module reference count to prevent auto-unload */
if (module_persistent) {
    __module_get(THIS_MODULE);  // <-- THIS INCREMENTS REFCOUNT
    lsw_info("Module persistence enabled - will remain loaded");
}
```

The `lsw_exit()` function tries to release it with `module_put(THIS_MODULE)`, but something is preventing clean exit.

## Solutions

### Option 1: Reboot (Cleanest)
```bash
sudo reboot
```
After reboot:
```bash
cd ~/lsw-project/kernel-module
sudo insmod lsw.ko
# Or with persistence disabled:
sudo insmod lsw.ko module_persistent=0
```

### Option 2: Change Default (Already Done)
Modified `kernel-module/lsw_main.c` to set `module_persistent = false` by default. This allows hot-reloading but module will unload when no PE processes are active.

### Option 3: Load Parameter Override
When loading fresh module after reboot:
```bash
sudo insmod lsw.ko module_persistent=0
```

### Option 4: Force Unload (DANGEROUS)
```bash
sudo rmmod -f lsw
# May crash the system if module is still in use
```

## Testing Workflow

### Development Workflow (Hot-Reload)
```bash
# 1. Load without persistence
sudo insmod kernel-module/lsw.ko module_persistent=0

# 2. Test
./lsw --launch hello.exe

# 3. Unload cleanly
sudo rmmod lsw

# 4. Make changes and rebuild
make clean && make

# 5. Reload
sudo insmod kernel-module/lsw.ko module_persistent=0
```

### Production Workflow (Persistent)
```bash
# Load with persistence (stays loaded)
sudo insmod kernel-module/lsw.ko module_persistent=1

# Module stays loaded even when no PEs running
# Requires reboot to reload
```

## reload-module.sh Script
Created helper script that:
- Checks if module is loaded
- Shows current refcount
- Attempts clean unload
- Loads new module if unload succeeds
- Verifies /dev/lsw creation
- Provides helpful error messages

Usage:
```bash
./reload-module.sh
```

## Long-Term Fix
Consider alternative approaches:
1. Remove `__module_get()` entirely - rely on device usage for refcounting
2. Add cleanup logic that force-releases all references during exit
3. Use proper device lifecycle management instead of artificial refcount bump

## Current Status
- Module stuck at refcount -1
- Need reboot to test userspace-to-kernel bridge
- Changed default to `module_persistent=false` for easier development
- Created `reload-module.sh` helper script

## Next Steps After Reboot
1. `cd ~/lsw-project/kernel-module`
2. `sudo insmod lsw.ko module_persistent=0`
3. `ls -la /dev/lsw` - verify device created
4. `./lsw --launch hello.exe` - test PE execution
5. Check kernel logs: `sudo dmesg | tail -50`

🏴‍☠️ **BFSL v1.2** - Even kernel modules fight us sometimes.
