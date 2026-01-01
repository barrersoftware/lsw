# LSW Optional Components System

## Overview

LSW provides a framework for installing **optional third-party components** that enhance functionality but are NOT required for core operation.

**CRITICAL:** These components are NOT part of LSW. They are third-party software with their own licenses.

---

## Legal Framework

### What LSW Does:
✅ Provides a convenient installer script  
✅ Shows license terms clearly  
✅ Requires explicit user acceptance  
✅ Downloads from original sources  
✅ Logs acceptance for user's records  

### What LSW Does NOT Do:
❌ Redistribute third-party components  
❌ Modify third-party components  
❌ Take responsibility for third-party components  
❌ Claim ownership of third-party components  

### User Responsibility:
When you run `lsw --install <component>`:
1. You see the component's license
2. You must explicitly type "yes" to accept
3. You download from the component's official source
4. You accept THEIR license, not LSW's BFSL
5. Your acceptance is logged to `~/.lsw/legal/`

---

## Usage

```bash
# Install DXVK (DirectX to Vulkan translation)
lsw --install dxvk

# Install vkd3d-proton (DirectX 12 to Vulkan)
lsw --install vkd3d
```

---

## Available Components

### DXVK
**Purpose:** Run DirectX 9/10/11 games using Vulkan  
**Developer:** Philip Rebohle and contributors  
**License:** zlib/libpng License  
**Source:** https://github.com/doitsujin/dxvk  
**Status:** Framework ready, implementation pending

**Why Not Part of LSW:**
- DXVK is a separate project with its own development
- Uses zlib/libpng license (different from BFSL)
- Better maintained as separate component

### vkd3d-proton
**Purpose:** Run DirectX 12 games using Vulkan  
**Developer:** Valve Corporation  
**License:** LGPL v2.1  
**Source:** https://github.com/ValveSoftware/vkd3d-proton  
**Status:** Framework ready, implementation pending

**Why Not Part of LSW:**
- Maintained by Valve with Proton ecosystem
- LGPL license (copyleft, incompatible with BFSL philosophy)
- Better as optional download

---

## Installation Process

When you run `lsw --install <component>`:

1. **Legal Notice Display:**
   - Shows what the component is
   - Shows who develops it
   - Explains it's NOT part of LSW
   - Shows the license text

2. **User Acceptance:**
   - User must type "yes" to proceed
   - Anything else cancels installation
   - Acceptance is explicit and informed

3. **Acceptance Logging:**
   - Logged to `~/.lsw/legal/<component>-acceptance.log`
   - Contains date, user, URLs, license info
   - Proof of user consent

4. **Download:**
   - From component's official source
   - No LSW redistribution
   - Direct from developers

5. **Installation:**
   - To `~/.lsw/optional/<component>/`
   - Isolated from LSW core
   - Can be removed without affecting LSW

---

## Legal Protection

### For BarrerSoftware/LSW:
✅ We don't redistribute third-party code  
✅ We require explicit license acceptance  
✅ We download from original sources  
✅ We log user consent  
✅ We clearly disclaim responsibility  

### For Users:
✅ Informed consent (see full license)  
✅ Know what they're accepting  
✅ Acceptance logged for their records  
✅ Optional (LSW works without them)  
✅ Isolated (can remove without breaking LSW)  

### For Third-Party Developers:
✅ Their license is shown and respected  
✅ Downloaded from their official sources  
✅ No modification or redistribution by LSW  
✅ Credit clearly given  
✅ Users directed to their project  

---

## Future Components (Planned)

- **Windows Fonts:** Arial, Times New Roman, etc. (Microsoft EULA)
- **Mono:** .NET Framework alternative (MIT License)
- **Gecko:** Firefox rendering for HTML apps (MPL License)
- **FAudio:** XAudio2 implementation (zlib License)

Each will follow the same legal framework:
1. Show license
2. Require acceptance
3. Log consent
4. Download from source
5. Install to ~/.lsw/optional/

---

## Implementation Status

**Current:** Framework complete, installer script ready  
**Next:** Implement actual downloads for DXVK and vkd3d  
**Future:** Add more components as needed

The infrastructure is READY. We just need to implement the actual download and installation logic for each component.

---

## Adding New Components

To add a new optional component:

1. Add case in `scripts/install/lsw-install.sh`
2. Create `install_<component>()` function
3. Include:
   - Component name and purpose
   - Developer information
   - License text (full or summary)
   - Source URL
   - License acceptance prompt
   - Acceptance logging
   - Download implementation

**Template:**
```bash
install_newcomponent() {
    show_header
    echo "Component: New Component Name"
    echo "Developer: Developer Name"
    echo "License: License Type"
    echo "Source: https://..."
    
    show_legal_notice
    
    echo "LICENSE TEXT HERE"
    
    read -p "Accept? (yes/no): " accept
    [ "$accept" != "yes" ] && exit 1
    
    log_acceptance "newcomponent" "license_url" "download_url"
    
    # Download and install
}
```

---

## Legal Compliance Checklist

Before adding any component:

- [ ] Is it truly optional? (LSW works without it)
- [ ] Is license compatible with user download? (not GPL for linking)
- [ ] Can we download from official source? (no piracy)
- [ ] Is license text available? (must show to user)
- [ ] Is developer okay with this? (check their docs)
- [ ] Do we clearly disclaim responsibility? (not our code)

---

## Comparison to Wine

**Wine's Approach (winetricks):**
- Downloads Microsoft DLLs
- Gray legal area
- Microsoft doesn't explicitly permit this
- Works for 30+ years without lawsuit

**LSW's Approach:**
- Downloads open-source alternatives (DXVK, vkd3d)
- Crystal clear legal position
- All components have permissive licenses
- User accepts each license explicitly
- No Microsoft binaries

**Result:** LSW is MORE legally defensible than Wine.

---

## Contact

Questions about optional components?
- Open an issue: https://github.com/barrersoftware/lsw/issues
- Label: [optional-components]

---

**Built by BarrerSoftware - Even our optional components are legal! 🏴‍☠️⚖️**
