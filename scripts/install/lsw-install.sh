#!/bin/bash
# LSW Optional Component Installer Framework
# 
# Usage: lsw --install <component>
# Example: lsw --install dxvk
#
# This script handles OPTIONAL third-party components that enhance LSW
# but are NOT required for core functionality.
#
# LEGAL NOTICE:
# These components are NOT part of LSW. They are third-party software
# with their own licenses. Users must accept those licenses.
# LSW does not redistribute these components - they are downloaded
# from their original sources with user consent.

set -e

COMPONENT="$1"
LSW_DATA_DIR="${HOME}/.lsw"
LSW_LEGAL_DIR="${LSW_DATA_DIR}/legal"
LSW_OPTIONAL_DIR="${LSW_DATA_DIR}/optional"

# Ensure directories exist
mkdir -p "${LSW_LEGAL_DIR}"
mkdir -p "${LSW_OPTIONAL_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  LSW Optional Component Installer                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

show_legal_notice() {
    echo -e "${YELLOW}⚠️  IMPORTANT LEGAL NOTICE:${NC}"
    echo ""
    echo "You are about to install a THIRD-PARTY component that is"
    echo "NOT part of LSW (Linux Subsystem for Windows)."
    echo ""
    echo "This component:"
    echo "  • Is NOT developed by BarrerSoftware"
    echo "  • Is NOT covered by LSW's BFSL license"
    echo "  • Has its own license terms (see below)"
    echo "  • Will be downloaded from its original source"
    echo ""
    echo "BarrerSoftware and LSW:"
    echo "  • Do NOT redistribute this component"
    echo "  • Do NOT modify this component"
    echo "  • Are NOT responsible for this component"
    echo "  • Provide this installer as a CONVENIENCE ONLY"
    echo ""
    echo "You are downloading directly from the component's official source."
    echo "By proceeding, you accept THEIR license, not ours."
    echo ""
}

log_acceptance() {
    local component="$1"
    local license_url="$2"
    local download_url="$3"
    
    local log_file="${LSW_LEGAL_DIR}/${component}-acceptance.log"
    
    {
        echo "COMPONENT: ${component}"
        echo "ACCEPTED_DATE: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "ACCEPTED_BY_USER: ${USER}"
        echo "SYSTEM: $(uname -a)"
        echo "LICENSE_URL: ${license_url}"
        echo "DOWNLOAD_URL: ${download_url}"
        echo "LSW_VERSION: $(cat VERSION 2>/dev/null || echo 'unknown')"
    } > "${log_file}"
    
    echo -e "${GREEN}✅ Acceptance logged to: ${log_file}${NC}"
}

# Component definitions
install_dxvk() {
    show_header
    echo -e "${BLUE}Component:${NC} DXVK (DirectX to Vulkan translation)"
    echo -e "${BLUE}Purpose:${NC} Run DirectX 9/10/11 games with Vulkan"
    echo -e "${BLUE}Developer:${NC} Philip Rebohle and contributors"
    echo -e "${BLUE}License:${NC} zlib/libpng License"
    echo -e "${BLUE}Source:${NC} https://github.com/doitsujin/dxvk"
    echo ""
    
    show_legal_notice
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "DXVK LICENSE (zlib/libpng):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Copyright (c) 2017-2024 Philip Rebohle"
    echo ""
    echo "This software is provided 'as-is', without any express or implied"
    echo "warranty. In no event will the authors be held liable for any damages"
    echo "arising from the use of this software."
    echo ""
    echo "Permission is granted to anyone to use this software for any purpose,"
    echo "including commercial applications, and to alter it and redistribute it"
    echo "freely, subject to the following restrictions:"
    echo ""
    echo "  1. The origin of this software must not be misrepresented;"
    echo "  2. Altered source versions must be plainly marked as such;"
    echo "  3. This notice may not be removed or altered from any source distribution."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    read -p "Do you accept the DXVK license? (yes/no): " accept
    
    if [ "$accept" != "yes" ]; then
        echo -e "${RED}❌ License not accepted. Installation cancelled.${NC}"
        exit 1
    fi
    
    log_acceptance "dxvk" \
        "https://github.com/doitsujin/dxvk/blob/master/LICENSE" \
        "https://github.com/doitsujin/dxvk/releases"
    
    echo ""
    echo -e "${GREEN}📦 Downloading DXVK...${NC}"
    
    # TODO: Implement actual download
    echo "🚧 DXVK installation coming soon!"
    echo "This framework is ready - implementation pending."
}

install_vkd3d() {
    show_header
    echo -e "${BLUE}Component:${NC} vkd3d-proton (DirectX 12 to Vulkan)"
    echo -e "${BLUE}Purpose:${NC} Run DirectX 12 games with Vulkan"
    echo -e "${BLUE}Developer:${NC} Valve Corporation"
    echo -e "${BLUE}License:${NC} LGPL v2.1"
    echo -e "${BLUE}Source:${NC} https://github.com/ValveSoftware/vkd3d-proton"
    echo ""
    
    show_legal_notice
    
    echo "This component uses LGPL v2.1 license."
    echo "View full license: https://github.com/ValveSoftware/vkd3d-proton/blob/master/LICENSE"
    echo ""
    
    read -p "Do you accept the vkd3d-proton LGPL license? (yes/no): " accept
    
    if [ "$accept" != "yes" ]; then
        echo -e "${RED}❌ License not accepted. Installation cancelled.${NC}"
        exit 1
    fi
    
    log_acceptance "vkd3d-proton" \
        "https://github.com/ValveSoftware/vkd3d-proton/blob/master/LICENSE" \
        "https://github.com/ValveSoftware/vkd3d-proton/releases"
    
    echo ""
    echo "🚧 vkd3d-proton installation coming soon!"
}

# Main script
if [ -z "$COMPONENT" ]; then
    echo "Usage: lsw --install <component>"
    echo ""
    echo "Available components:"
    echo "  dxvk      - DirectX 9/10/11 to Vulkan (gaming)"
    echo "  vkd3d     - DirectX 12 to Vulkan (gaming)"
    echo ""
    echo "Example: lsw --install dxvk"
    exit 1
fi

case "$COMPONENT" in
    dxvk)
        install_dxvk
        ;;
    vkd3d)
        install_vkd3d
        ;;
    *)
        echo -e "${RED}❌ Unknown component: $COMPONENT${NC}"
        echo ""
        echo "Available components: dxvk, vkd3d"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
