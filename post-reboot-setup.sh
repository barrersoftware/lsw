#!/bin/bash
# LSW Post-Reboot Setup Script
# Run this after reboot to load LSW module cleanly

echo "🏴‍☠️ LSW Post-Reboot Setup"
echo "=========================="
echo ""

# Verify module is NOT loaded
echo "1️⃣ Checking current module state..."
if lsmod | grep -q "^lsw "; then
    echo "   ⚠️  WARNING: LSW module is already loaded!"
    echo "   This shouldn't happen. Module is blacklisted."
    lsmod | grep lsw
    exit 1
else
    echo "   ✅ Module not loaded (as expected)"
fi

echo ""
echo "2️⃣ Building latest module..."
cd ~/lsw-project/kernel-module
if make -j$(nproc) 2>&1 | tail -5; then
    echo "   ✅ Module built successfully"
else
    echo "   ❌ Build failed"
    exit 1
fi

echo ""
echo "3️⃣ Loading module (without persistence)..."
if sudo insmod lsw.ko module_persistent=0; then
    echo "   ✅ Module loaded successfully"
else
    echo "   ❌ Failed to load module"
    echo ""
    echo "Check kernel logs:"
    sudo dmesg | tail -20
    exit 1
fi

echo ""
echo "4️⃣ Verifying module status..."
lsmod | grep lsw
REFCNT=$(cat /sys/module/lsw/refcnt 2>/dev/null || echo "?")
echo "   Reference count: $REFCNT"

if [ "$REFCNT" = "0" ]; then
    echo "   ✅ Refcount is 0 - module can be unloaded anytime"
elif [ "$REFCNT" = "1" ]; then
    echo "   ⚠️  Refcount is 1 - check if device is open"
else
    echo "   ❌ Refcount is $REFCNT - unexpected!"
fi

echo ""
echo "5️⃣ Checking device node..."
if [ -e /dev/lsw ]; then
    ls -l /dev/lsw
    echo "   ✅ /dev/lsw created successfully"
else
    echo "   ❌ /dev/lsw not found!"
    echo ""
    echo "Check kernel logs:"
    sudo dmesg | grep -i lsw | tail -10
    exit 1
fi

echo ""
echo "6️⃣ Checking kernel logs..."
sudo dmesg | grep -i lsw | tail -15

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ LSW Module Ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🚀 Test PE Execution:"
echo "   cd ~/lsw-project"
echo "   ./lsw --launch hello.exe"
echo ""
echo "📊 Monitor Module:"
echo "   watch -n 1 'lsmod | grep lsw'"
echo ""
echo "🔄 Reload Module:"
echo "   ./reload-module.sh"
echo ""
echo "🏴‍☠️ Wine took 30 years. LSW has kernel integration from day 1."
