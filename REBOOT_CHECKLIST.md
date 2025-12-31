# LSW Reboot Checklist

## Pre-Reboot Status ✅
- [x] LSW module blacklisted in `/etc/modprobe.d/blacklist-lsw.conf`
- [x] Initramfs updated with blacklist
- [x] No systemd auto-load services
- [x] Module not installed in `/lib/modules/`
- [x] No `/etc/modules` entry
- [x] Created `post-reboot-setup.sh` for clean module load

## What Will Happen During Reboot
1. System boots normally
2. LSW module will NOT load (blacklisted)
3. No `/dev/lsw` device node created
4. Module stays at refcount 0 (clean slate)

## After Reboot - Run This:
```bash
cd ~/lsw-project
./post-reboot-setup.sh
```

This script will:
1. ✅ Verify module is not loaded
2. ✅ Build latest kernel module
3. ✅ Load module with `module_persistent=0`
4. ✅ Verify `/dev/lsw` creation
5. ✅ Show kernel logs
6. ✅ Display refcount (should be 0)

## Then Test PE Execution:
```bash
cd ~/lsw-project
./lsw --launch hello.exe
```

Expected output:
```
[INFO] LSW starting - Linux Subsystem for Windows
[INFO] Target: hello.exe
[INFO] PE file loaded successfully
[INFO] Registering PE with kernel
[INFO] ✅ PE registered with kernel successfully
```

## If Module Needs Reload (During Development):
```bash
./reload-module.sh
```

This will:
- Check refcount (should be 0 now!)
- Safely unload old module
- Load new module
- Verify everything works

## Verification Commands
```bash
# Module status
lsmod | grep lsw

# Reference count (should be 0)
cat /sys/module/lsw/refcnt

# Device node
ls -l /dev/lsw

# Kernel logs
sudo dmesg | grep -i lsw | tail -20
```

## Why This Works Now
**Before:** `module_persistent=true` → `__module_get()` → refcount stuck at -1 → can't unload
**After:** `module_persistent=false` → normal refcounting → can unload cleanly → hot-reload works!

## Development Workflow (After Reboot)
```bash
# 1. Make changes to kernel module
vim kernel-module/lsw_syscall.c

# 2. Reload
./reload-module.sh

# 3. Test
./lsw --launch hello.exe

# 4. Repeat!
```

No more reboots needed! 🚀

## Blacklist Location
File: `/etc/modprobe.d/blacklist-lsw.conf`
```
blacklist lsw
```

To remove blacklist later (if you want auto-load):
```bash
sudo rm /etc/modprobe.d/blacklist-lsw.conf
sudo update-initramfs -u
```

🏴‍☠️ **Ready for reboot. Module will NOT auto-load. Run post-reboot-setup.sh to get started.**
