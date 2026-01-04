# Preventing LSW Module Stuck Issues

## The Problem

Module gets stuck with -1 refcount when:
1. Persistence was enabled on load (`module_persistent=true`)
2. Thread or resource leaked
3. Device not cleaned up properly

## Prevention Strategy

### 1. Always Unload Before Rebuilding

```bash
# Before rebuilding
sudo rmmod lsw 2>/dev/null || true
cd ~/lsw-project/kernel-module
make clean
make
```

### 2. Safe Module Reload Script

Create `~/lsw-project/reload-lsw.sh`:

```bash
#!/bin/bash
# Safe LSW module reload

echo "Unloading old module..."
sudo rmmod lsw 2>/dev/null || echo "No module to unload"

echo "Cleaning build..."
cd ~/lsw-project/kernel-module
make clean > /dev/null

echo "Building module..."
if make; then
    echo "✅ Build successful"
    
    echo "Loading module..."
    if sudo insmod lsw.ko; then
        echo "✅ Module loaded"
        lsmod | grep lsw
        ls -la /dev/lsw
    else
        echo "❌ Failed to load"
        exit 1
    fi
else
    echo "❌ Build failed"
    exit 1
fi
```

### 3. Module Cleanup Code

**Already fixed in lsw_main.c:**
- `module_persistent = false` (line 42)
- Proper cleanup order
- No reference increment unless explicitly enabled

### 4. Debug Stuck Module

If module gets stuck again:

```bash
# Check status
lsmod | grep lsw
cat /sys/module/lsw/refcnt

# Check what's using it
sudo fuser -v /dev/lsw
ps aux | grep lsw

# Check kernel messages
sudo dmesg | grep LSW | tail -50

# Last resort: reboot
sudo reboot
```

### 5. Kernel Messages to Watch For

**Good:**
```
[LSW] Initializing LSW v0.1
[LSW] LSW kernel module initialized successfully
```

**Bad:**
```
[LSW] Thread leak: TID=XXXX
[LSW] Sync object leak: PID=XXX
```

If you see leaks, there's a cleanup bug.

## Root Cause Analysis

**This incident:**
- Old module loaded with `module_persistent=true`
- Thread from sync subsystem leaked (TID 2005)
- Module got -1 refcount from `__module_get()`
- Module stuck in "Unloading" state

**Fix applied:**
- Changed `module_persistent` default to `false`
- Module now unloads cleanly by default

## Going Forward

**Development workflow:**
1. Make code changes
2. Run `~/lsw-project/reload-lsw.sh` 
3. Check `dmesg` for errors
4. Test functionality
5. Unload before next iteration

**If stuck:**
- Don't panic - just reboot
- New code is correct
- Won't happen again with current code

🏴‍☠️ Barrer Software Way: Learn from issues, prevent recurrence
