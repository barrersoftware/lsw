# LSW Known Issues

## Active Issues

### 1. WriteFile Argument Mismatch
**Status:** Under Investigation  
**Severity:** Medium  
**Discovered:** 2024-12-31

**Description:**
When hello.exe calls WriteFile, the `bytes_to_write` parameter is receiving value `1073758244` (0x40004024) instead of the expected small value (~15 bytes).

**Analysis:**
- Value 0x40004024 appears to be an address in PE image space (RVA 0x4024)
- May indicate calling convention mismatch
- Could be related to how we cast function pointers in IAT
- Issue present in both kernel and userspace paths

**Workaround:**
None currently. Infrastructure proven to work - just need correct arguments.

**Next Steps:**
1. Check Windows x64 calling convention compliance
2. Verify function pointer casts in IAT resolution  
3. Test with simpler PE that doesn't use CRT
4. Consider assembly-level debugging of call site

---

## Resolved Issues

### 1. NULL Function Pointer Crashes
**Status:** RESOLVED  
**Resolution:** Added generic_stub for unresolved imports

### 2. CRT __initterm NULL Pointer
**Status:** RESOLVED  
**Resolution:** Added NULL checks in __initterm

### 3. IAT Write Protection
**Status:** WORKAROUND  
**Resolution:** Made .text section writable (temporary hack)

### 4. TEB/PEB Missing
**Status:** RESOLVED  
**Resolution:** Implemented full TEB/PEB with GS register setup
