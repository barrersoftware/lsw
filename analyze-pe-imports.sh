#!/bin/bash
# LSW PE Import Analyzer
# Shows what APIs a Windows executable needs

if [ $# -eq 0 ]; then
    echo "Usage: $0 <windows-exe-file>"
    echo ""
    echo "Example: $0 notepad.exe"
    echo "Example: $0 test_path_env.exe"
    exit 1
fi

EXE_FILE="$1"

if [ ! -f "$EXE_FILE" ]; then
    echo "Error: File '$EXE_FILE' not found"
    exit 1
fi

echo "=========================================="
echo "LSW PE Import Analyzer"
echo "=========================================="
echo "File: $EXE_FILE"
echo ""

# Extract imports using objdump
echo "Analyzing imports..."
echo ""

x86_64-w64-mingw32-objdump -p "$EXE_FILE" | grep -A 500 "DLL Name" | awk '
BEGIN {
    dll_count = 0
    total_funcs = 0
    in_dll = 0
}

/DLL Name:/ {
    if (current_dll != "") {
        print ""
        print "  Total: " func_count " functions"
        print ""
    }
    current_dll = $3
    dll_count++
    func_count = 0
    in_dll = 1
    print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print "DLL: " current_dll
    print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    next
}

in_dll && /^\t[0-9a-f]+\s+[0-9]+\s+\w/ {
    # Extract function name (3rd field)
    func_name = $3
    if (func_name != "" && func_name != "Member-Name" && func_name != "Bound-To") {
        print "  - " func_name
        func_count++
        total_funcs++
    }
}

/^$/ && in_dll {
    in_dll = 0
}

END {
    if (current_dll != "") {
        print ""
        print "  Total: " func_count " functions"
    }
    print ""
    print "=========================================="
    print "Summary:"
    print "  DLLs: " dll_count
    print "  Total Functions: " total_funcs
    print "=========================================="
}
'

echo ""
echo "✅ Analysis complete!"
echo ""
echo "Use this to prioritize LSW API implementation."
