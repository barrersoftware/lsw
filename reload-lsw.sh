#!/bin/bash
# Safe LSW module reload

echo "🏴‍☠️ LSW Module Reload Script"
echo "=========================="
echo ""

echo "Unloading old module..."
sudo rmmod lsw 2>/dev/null && echo "✅ Unloaded" || echo "⚠️  No module to unload"

echo ""
echo "Cleaning build..."
cd ~/lsw-project/kernel-module
make clean > /dev/null 2>&1

echo "Building module..."
if make 2>&1 | tail -5; then
    echo ""
    echo "✅ Build successful"
    
    echo ""
    echo "Loading module..."
    if sudo insmod lsw.ko; then
        echo "✅ Module loaded"
        echo ""
        echo "Module status:"
        lsmod | grep lsw
        echo ""
        echo "Device:"
        ls -la /dev/lsw
        echo ""
        echo "Recent kernel messages:"
        sudo dmesg | grep "\[LSW\]" | tail -10
    else
        echo "❌ Failed to load"
        exit 1
    fi
else
    echo "❌ Build failed"
    exit 1
fi

echo ""
echo "🏴‍☠️ LSW module ready for testing!"
