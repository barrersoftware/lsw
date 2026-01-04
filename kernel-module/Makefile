# LSW Kernel Module Makefile
# Copyright (c) 2025 BarrerSoftware
# Licensed under BarrerSoftware License (BSL) v1.0

# Module name
obj-m := lsw.o

# Source files  
lsw-objs := lsw_main.o lsw_device.o lsw_syscall.o lsw_memory.o lsw_file.o lsw_sync.o lsw_dll.o lsw_process.o lsw_console.o lsw_env.o

# Kernel source directory (can be overridden)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# Build directory
PWD := $(shell pwd)

# Compiler flags
ccflags-y := -I$(PWD)/include/kernel-module -DDEBUG

# Default target - build for current running kernel
all:
	@echo "Building LSW kernel module for kernel $(shell uname -r)"
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# Clean build artifacts
clean:
	@echo "Cleaning LSW kernel module build artifacts"
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

# Install module
install: all
	@echo "Installing LSW kernel module"
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a

# Uninstall module
uninstall:
	@echo "Uninstalling LSW kernel module"
	rm -f /lib/modules/$(shell uname -r)/extra/lsw.ko
	depmod -a

# Load module
load:
	@echo "Loading LSW kernel module"
	sudo insmod lsw.ko

# Unload module
unload:
	@echo "Unloading LSW kernel module"
	sudo rmmod lsw

# Reload module (unload + load)
reload: unload load

# Show module info
info:
	@echo "LSW Kernel Module Information:"
	@modinfo lsw.ko 2>/dev/null || echo "Module not built yet"

# Show kernel log
log:
	@echo "LSW Kernel Module Log (last 20 lines):"
	@dmesg | grep -i lsw | tail -20

# Build for specific kernel version
# Usage: make build-kernel KVER=6.6.119
build-kernel:
	@if [ -z "$(KVER)" ]; then \
		echo "Error: KVER not specified"; \
		echo "Usage: make build-kernel KVER=6.6.119"; \
		exit 1; \
	fi
	@echo "Building LSW for kernel $(KVER)"
	@if [ -d "$(HOME)/linux-kernels/linux-$(KVER)" ]; then \
		$(MAKE) KERNELDIR=$(HOME)/linux-kernels/linux-$(KVER) all; \
	else \
		echo "Error: Kernel source not found at $(HOME)/linux-kernels/linux-$(KVER)"; \
		echo "Extract kernel tarball first"; \
		exit 1; \
	fi

# Build for all available kernels
build-all:
	@echo "Building LSW for all available kernels..."
	@for tarball in $(HOME)/linux-kernels/*.tar.*; do \
		if [ -f "$$tarball" ]; then \
			kver=$$(basename $$tarball | sed 's/linux-//;s/.tar.*//'); \
			echo ""; \
			echo "========================================"; \
			echo "Building for kernel $$kver"; \
			echo "========================================"; \
			if [ ! -d "$(HOME)/linux-kernels/linux-$$kver" ]; then \
				echo "Extracting kernel source..."; \
				tar -xf "$$tarball" -C $(HOME)/linux-kernels/; \
			fi; \
			$(MAKE) KERNELDIR=$(HOME)/linux-kernels/linux-$$kver all || true; \
		fi; \
	done
	@echo ""
	@echo "Build complete for all kernels"

# Extract all kernel sources
extract-kernels:
	@echo "Extracting all kernel sources..."
	@for tarball in $(HOME)/linux-kernels/*.tar.*; do \
		if [ -f "$$tarball" ]; then \
			echo "Extracting $$tarball..."; \
			tar -xf "$$tarball" -C $(HOME)/linux-kernels/; \
		fi; \
	done
	@echo "All kernels extracted"

# Help
help:
	@echo "LSW Kernel Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make                - Build for current running kernel"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install        - Install module"
	@echo "  make uninstall      - Uninstall module"
	@echo "  make load           - Load module into kernel"
	@echo "  make unload         - Unload module from kernel"
	@echo "  make reload         - Reload module"
	@echo "  make info           - Show module information"
	@echo "  make log            - Show kernel log for LSW"
	@echo "  make build-kernel KVER=x.x.x - Build for specific kernel"
	@echo "  make build-all      - Build for all available kernels"
	@echo "  make extract-kernels - Extract all kernel tarballs"
	@echo ""
	@echo "Examples:"
	@echo "  make build-kernel KVER=6.6.119"
	@echo "  make build-all"

.PHONY: all clean install uninstall load unload reload info log build-kernel build-all extract-kernels help
