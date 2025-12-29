# LSW - Linux Subsystem for Windows
# Copyright (c) 2025 BarrerSoftware
# Licensed under BarrerSoftware License (BSL) v1.0

.PHONY: all clean shared pe-loader msi-installer test install help

# Compiler settings
CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -pedantic -O2 -fPIC
INCLUDES := -Iinclude -Iinclude/shared -Iinclude/pe-loader
DEBUG_FLAGS := -g -DDEBUG

# Directories
SRC_DIR := src
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
LIB_DIR := $(BUILD_DIR)/lib

# Shared library components
SHARED_SOURCES := $(wildcard $(SRC_DIR)/shared/*/*.c)
SHARED_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SHARED_SOURCES))

# PE loader
PE_SOURCES := $(wildcard $(SRC_DIR)/pe-loader/*.c)
PE_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PE_SOURCES))

# MSI installer
MSI_SOURCES := $(wildcard $(SRC_DIR)/msi-installer/*.c)
MSI_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(MSI_SOURCES))

# Output libraries
SHARED_LIB := $(LIB_DIR)/liblsw-shared.so
PE_LOADER_BIN := $(BIN_DIR)/lsw-pe-loader
MSI_INSTALLER_BIN := $(BIN_DIR)/lsw-msi-installer

# Colors for output
COLOR_RESET := \033[0m
COLOR_BLUE := \033[1;34m
COLOR_GREEN := \033[1;32m
COLOR_YELLOW := \033[1;33m

# Default target
all: directories shared pe-loader msi-installer
	@echo "$(COLOR_GREEN)✅ LSW build complete$(COLOR_RESET)"

# Help target
help:
	@echo "$(COLOR_BLUE)LSW - Linux Subsystem for Windows$(COLOR_RESET)"
	@echo ""
	@echo "Available targets:"
	@echo "  $(COLOR_YELLOW)make all$(COLOR_RESET)          - Build everything"
	@echo "  $(COLOR_YELLOW)make shared$(COLOR_RESET)       - Build shared libraries"
	@echo "  $(COLOR_YELLOW)make pe-loader$(COLOR_RESET)    - Build PE loader"
	@echo "  $(COLOR_YELLOW)make msi-installer$(COLOR_RESET) - Build MSI installer"
	@echo "  $(COLOR_YELLOW)make test$(COLOR_RESET)         - Run tests"
	@echo "  $(COLOR_YELLOW)make clean$(COLOR_RESET)        - Clean build artifacts"
	@echo "  $(COLOR_YELLOW)make install$(COLOR_RESET)      - Install LSW (requires root)"
	@echo "  $(COLOR_YELLOW)make debug$(COLOR_RESET)        - Build with debug symbols"
	@echo ""
	@echo "$(COLOR_BLUE)Philosophy: If it's free, it's free. Period.$(COLOR_RESET)"

# Create build directories
directories:
	@mkdir -p $(OBJ_DIR)/shared/{dll-loader,registry,filesystem,winapi,dos-support,utils}
	@mkdir -p $(OBJ_DIR)/pe-loader
	@mkdir -p $(OBJ_DIR)/msi-installer
	@mkdir -p $(LIB_DIR)
	@mkdir -p $(BIN_DIR)

# Build shared library
shared: directories $(SHARED_LIB)
	@echo "$(COLOR_GREEN)✅ Shared library built$(COLOR_RESET)"

$(SHARED_LIB): $(SHARED_OBJECTS)
	@echo "$(COLOR_BLUE)🔗 Linking shared library...$(COLOR_RESET)"
	$(CC) -shared -o $@ $^

# Build PE loader
pe-loader: shared $(PE_LOADER_BIN)
	@echo "$(COLOR_GREEN)✅ PE loader built$(COLOR_RESET)"

$(PE_LOADER_BIN): $(PE_OBJECTS) $(SHARED_LIB)
	@echo "$(COLOR_BLUE)🔗 Linking PE loader...$(COLOR_RESET)"
	$(CC) -o $@ $(PE_OBJECTS) -L$(LIB_DIR) -llsw-shared

# Build MSI installer
msi-installer: shared $(MSI_INSTALLER_BIN)
	@echo "$(COLOR_GREEN)✅ MSI installer built$(COLOR_RESET)"

$(MSI_INSTALLER_BIN): $(MSI_OBJECTS) $(SHARED_LIB)
	@echo "$(COLOR_BLUE)🔗 Linking MSI installer...$(COLOR_RESET)"
	$(CC) -o $@ $(MSI_OBJECTS) -L$(LIB_DIR) -llsw-shared

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "$(COLOR_BLUE)📦 Compiling $<$(COLOR_RESET)"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all
	@echo "$(COLOR_GREEN)✅ Debug build complete$(COLOR_RESET)"

# Run tests
test: all
	@echo "$(COLOR_BLUE)🧪 Running tests...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)⚠️  Tests not yet implemented$(COLOR_RESET)"

# Install (requires root)
install: all
	@echo "$(COLOR_BLUE)📦 Installing LSW...$(COLOR_RESET)"
	install -m 755 $(PE_LOADER_BIN) /usr/local/bin/lsw
	install -m 755 $(MSI_INSTALLER_BIN) /usr/local/bin/lsw-install
	install -m 644 $(SHARED_LIB) /usr/local/lib/
	ldconfig
	@echo "$(COLOR_GREEN)✅ LSW installed successfully$(COLOR_RESET)"
	@echo ""
	@echo "Try it:"
	@echo "  lsw --help"
	@echo "  lsw --launch yourapp.exe"

# Clean build artifacts
clean:
	@echo "$(COLOR_BLUE)🧹 Cleaning build artifacts...$(COLOR_RESET)"
	rm -rf $(BUILD_DIR)
	@echo "$(COLOR_GREEN)✅ Clean complete$(COLOR_RESET)"

# Project info
info:
	@echo "$(COLOR_BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)LSW - Linux Subsystem for Windows$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(COLOR_RESET)"
	@echo ""
	@echo "Project: Run Windows applications natively on Linux"
	@echo "License: BarrerSoftware License (BSL) v1.0"
	@echo "Philosophy: If it's free, it's free. Period."
	@echo ""
	@echo "Components:"
	@echo "  • Shared libraries (DLL loader, registry, filesystem)"
	@echo "  • PE loader (Windows executables)"
	@echo "  • MSI installer (Windows packages)"
	@echo ""
	@echo "Website: https://lsw.barrersoftware.com"
	@echo "GitHub: https://github.com/barrersoftware/lsw"
	@echo ""
	@echo "$(COLOR_BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(COLOR_RESET)"
