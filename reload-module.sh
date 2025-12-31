#!/bin/bash
# LSW Kernel Module Reload Script
# Safely unload and reload the LSW kernel module

set -e

MODULE_PATH="$(dirname "$0")/kernel-module/lsw.ko"

echo "🔄 LSW Kernel Module Reload"
echo "=============================="
echo ""

# Check if module is loaded
if lsmod | grep -q "^lsw "; then
    echo "📤 Unloading old module..."
    
    # Check refcount
    REFCNT=$(cat /sys/module/lsw/refcnt 2>/dev/null || echo "unknown")
    echo "   Current refcount: $REFCNT"
    
    # Try to remove device node first
    if [ -e /dev/lsw ]; then
        echo "   Removing /dev/lsw..."
        sudo rm -f /dev/lsw 2>/dev/null || true
    fi
    
    # Try to unload
    if sudo rmmod lsw 2>/dev/null; then
        echo "   ✅ Module unloaded successfully"
    else
        echo "   ❌ Failed to unload module"
        echo ""
        echo "Module is stuck (refcount=$REFCNT)"
        echo ""
        echo "Options:"
        echo "  1. Reboot the system (cleanest)"
        echo "  2. Try: sudo rmmod -f lsw (risky, may crash)"
        echo "  3. Wait for all processes using /dev/lsw to exit"
        echo ""
        exit 1
    fi
    
    sleep 1
else
    echo "📋 Module not loaded"
fi

echo ""
echo "📥 Loading new module..."
if [ ! -f "$MODULE_PATH" ]; then
    echo "   ❌ Module not found: $MODULE_PATH"
    echo "   Run: make clean && make build-module"
    exit 1
fi

if sudo insmod "$MODULE_PATH"; then
    echo "   ✅ Module loaded successfully"
else
    echo "   ❌ Failed to load module"
    sudo dmesg | tail -20
    exit 1
fi

echo ""
echo "📊 Module Status:"
lsmod | grep lsw || echo "   Module not in lsmod?"

echo ""
echo "📱 Device Status:"
if [ -e /dev/lsw ]; then
    ls -l /dev/lsw
    echo "   ✅ Device node created successfully"
else
    echo "   ❌ /dev/lsw not found"
    echo "   Check: sudo dmesg | tail -20"
fi

echo ""
echo "🎯 Ready to test!"
echo "   Try: ./lsw --launch hello.exe"
