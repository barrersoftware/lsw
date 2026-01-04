/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_types.h"
#include "lsw_log.h"
#include "lsw_filesystem.h"
#include "pe-loader/pe_loader.h"
#include "pe-loader/pe_parser.h"
#include "pe-loader/pe_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

// ============================================================================
// SECTION: Help System (Friendly!)
// ============================================================================

/**
 * Show friendly help
 * 
 * What: Display user-friendly help
 * Why: People should understand how to use LSW
 * How: Clear sections, examples, welcoming tone
 */
void show_help(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  LSW - Linux Subsystem for Windows                          ║\n");
    printf("║  Run Windows programs on Linux (simple!)                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("👋 HELLO! WELCOME TO LSW!\n");
    printf("\n");
    printf("If this is your first time, don't worry - it's super simple.\n");
    printf("LSW lets you run Windows programs (.exe files) on Linux.\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
    printf("🚀 QUICK START (Get Running in 30 Seconds)\n");
    printf("\n");
    printf("Want to run a Windows program? Just type:\n");
    printf("\n");
    printf("  lsw --launch yourprogram.exe\n");
    printf("\n");
    printf("That's it! LSW will automatically:\n");
    printf("  • Figure out what Windows version the program needs\n");
    printf("  • Load the right libraries\n");
    printf("  • Run your program\n");
    printf("\n");
    printf("Example:\n");
    printf("  lsw --launch notepad.exe\n");
    printf("  lsw --launch game.exe\n");
    printf("  lsw --launch C:\\\\Windows\\\\notepad.exe\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
    printf("📖 MAIN COMMANDS (The Important Ones)\n");
    printf("\n");
    printf("  --launch [file]\n");
    printf("    Run a Windows program\n");
    printf("    Example: lsw --launch app.exe\n");
    printf("    \n");
    printf("  --help\n");
    printf("    Show this helpful guide (you're reading it!)\n");
    printf("    \n");
    printf("  --version\n");
    printf("    Check what version of LSW you're running\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
    printf("⚙️  EXTRA OPTIONS (When You Need More Control)\n");
    printf("\n");
    printf("  -version [windows-version]\n");
    printf("    Force a specific Windows version\n");
    printf("    Options: xp, vista, win7, win10, win11\n");
    printf("    Example: lsw --launch oldgame.exe -version xp\n");
    printf("    \n");
    printf("    Why use this? Some old programs need old Windows versions.\n");
    printf("    \n");
    printf("  -debug\n");
    printf("    See detailed information (helpful when things go wrong)\n");
    printf("    Example: lsw --launch app.exe -debug\n");
    printf("    \n");
    printf("    Why use this? To see what's happening behind the scenes.\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
    printf("💡 COMMON QUESTIONS\n");
    printf("\n");
    printf("Q: Where are my Windows files?\n");
    printf("A: Windows apps see C:\\ which maps to ~/.lsw/drives/c/\n");
    printf("   This keeps Windows apps isolated from your Linux system.\n");
    printf("   You can safely access this directory from Linux too!\n");
    printf("\n");
    printf("Q: My program won't run!\n");
    printf("A: Try adding -debug to see what's wrong:\n");
    printf("   lsw --launch app.exe -debug\n");
    printf("\n");
    printf("Q: Something's broken, help!\n");
    printf("A: Visit: https://lsw.barrersoftware.com/troubleshooting\n");
    printf("   Or report: https://github.com/barrersoftware/lsw/issues\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
    printf("Remember: LSW is designed to be simple!\n");
    printf("If you're confused, we probably made something unclear.\n");
    printf("Let us know: https://github.com/barrersoftware/lsw/issues\n");
    printf("\n");
    printf("Happy Windows-on-Linux! 🐧🪟\n");
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("\n");
}

/**
 * Show version
 */
void show_version(void) {
    printf("LSW (Linux Subsystem for Windows) v0.1.0-alpha\n");
    printf("Copyright (c) 2025 BarrerSoftware\n");
    printf("Licensed under BarrerSoftware License (BSL) v1.0\n");
    printf("\n");
    printf("If it's free, it's free. Period.\n");
    printf("\n");
    printf("Website: https://lsw.barrersoftware.com\n");
    printf("GitHub: https://github.com/barrersoftware/lsw\n");
}

/**
 * Show "no arguments" message
 */
void show_no_args(void) {
    printf("\n");
    printf("👋 Hi! You ran LSW but didn't tell it what to do.\n");
    printf("\n");
    printf("Need to run a Windows program? Try:\n");
    printf("  lsw --launch yourprogram.exe\n");
    printf("\n");
    printf("Want to see what you can do? Try:\n");
    printf("  lsw --help\n");
    printf("\n");
    printf("More help: https://lsw.barrersoftware.com\n");
    printf("\n");
}

// ============================================================================
// SECTION: Main Function
// ============================================================================

int main(int argc, char* argv[]) {
    // No arguments - show friendly message
    if (argc == 1) {
        show_no_args();
        return 0;
    }
    
    // Parse command line arguments
    bool debug_mode = false;
    bool verbose = false;
    lsw_windows_version_t win_version = LSW_WIN_AUTO;
    uint32_t cpu_speed_mhz = 0;  // 0 = native
    char* executable_path = NULL;
    int executable_index = -1; // Track where in argv the .exe is
    
    // Check for help requests (forgiving!)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 ||
            strcmp(argv[i], "--h") == 0 ||
            strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "-?") == 0 ||
            strcmp(argv[i], "?") == 0 ||
            strcmp(argv[i], "help") == 0 ||
            strcmp(argv[i], "what") == 0 ||
            strcmp(argv[i], "how") == 0) {
            show_help();
            return 0;
        }
        
        if (strcmp(argv[i], "--version") == 0 ||
            strcmp(argv[i], "-v") == 0) {
            show_version();
            return 0;
        }
    }
    
    // Parse options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--launch") == 0) {
            if (i + 1 < argc) {
                executable_index = ++i;
                executable_path = argv[i];
            } else {
                fprintf(stderr, "❌ Error: --launch requires a file path\n\n");
                fprintf(stderr, "Example: lsw --launch yourapp.exe\n");
                fprintf(stderr, "Need help? Run: lsw --help\n\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-debug") == 0) {
            debug_mode = true;
            lsw_log_set_level(LSW_LOG_DEBUG);
        } else if (strcmp(argv[i], "-verbose") == 0) {
            verbose = true;
            lsw_log_set_level(LSW_LOG_TRACE);
        } else if (strcmp(argv[i], "-version") == 0) {
            if (i + 1 < argc) {
                i++;
                if (strcmp(argv[i], "dos") == 0) {
                    win_version = LSW_WIN_XP;  // Use XP as placeholder for now
                } else if (strcmp(argv[i], "xp") == 0) {
                    win_version = LSW_WIN_XP;
                } else if (strcmp(argv[i], "vista") == 0) {
                    win_version = LSW_WIN_VISTA;
                } else if (strcmp(argv[i], "win7") == 0) {
                    win_version = LSW_WIN_7;
                } else if (strcmp(argv[i], "win10") == 0) {
                    win_version = LSW_WIN_10;
                } else if (strcmp(argv[i], "win11") == 0) {
                    win_version = LSW_WIN_11;
                } else {
                    fprintf(stderr, "⚠️  Hmm, that Windows version isn't recognized\n\n");
                    fprintf(stderr, "You used: %s\n", argv[i]);
                    fprintf(stderr, "\nValid options:\n");
                    fprintf(stderr, "  • xp      (Windows XP)\n");
                    fprintf(stderr, "  • vista   (Windows Vista)\n");
                    fprintf(stderr, "  • win7    (Windows 7)\n");
                    fprintf(stderr, "  • win10   (Windows 10)\n");
                    fprintf(stderr, "  • win11   (Windows 11)\n");
                    fprintf(stderr, "\nExample: lsw --launch app.exe -version win7\n\n");
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "-cpu") == 0) {
            if (i + 1 < argc) {
                i++;
                // Parse CPU speed: "25mhz", "100mhz", "500mhz"
                char* speed_str = argv[i];
                int parsed = sscanf(speed_str, "%umhz", &cpu_speed_mhz);
                if (parsed != 1) {
                    // Try without "mhz" suffix
                    parsed = sscanf(speed_str, "%u", &cpu_speed_mhz);
                }
                if (parsed != 1 || cpu_speed_mhz == 0) {
                    fprintf(stderr, "⚠️  Invalid CPU speed: %s\n\n", speed_str);
                    fprintf(stderr, "Examples:\n");
                    fprintf(stderr, "  5mhz    (IBM PC - 4.77 MHz)\n");
                    fprintf(stderr, "  25mhz   (486 - 25 MHz)\n");
                    fprintf(stderr, "  100mhz  (Pentium - 100 MHz)\n");
                    fprintf(stderr, "  500mhz  (Pentium III)\n\n");
                    fprintf(stderr, "Example: lsw --launch game.exe -cpu 25mhz\n\n");
                    return 1;
                }
                LSW_LOG_INFO("CPU throttling enabled: %u MHz", cpu_speed_mhz);
            }
        }
    }
    
    // If no executable specified, show help
    if (!executable_path) {
        fprintf(stderr, "❌ No Windows program specified\n\n");
        fprintf(stderr, "You need to tell LSW which program to run.\n\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  lsw --launch yourapp.exe\n\n");
        fprintf(stderr, "Need help? Run: lsw --help\n\n");
        return 1;
    }
    
    // Log startup info
    LSW_LOG_INFO("LSW starting - Linux Subsystem for Windows");
    LSW_LOG_INFO("Target: %s", executable_path);
    
    // Initialize LSW prefix (create ~/.lsw/drives/c/ if needed)
    lsw_status_t init_result = lsw_fs_init_prefix();
    if (init_result != LSW_SUCCESS) {
        LSW_LOG_WARN("Failed to initialize LSW prefix directories");
    }
    
    // Check if file exists
    if (!lsw_fs_path_exists(executable_path)) {
        fprintf(stderr, "\n");
        fprintf(stderr, "❌ Oops! File not found\n\n");
        fprintf(stderr, "LSW couldn't find: %s\n\n", executable_path);
        fprintf(stderr, "💡 Tips:\n");
        fprintf(stderr, "  • Make sure you spelled the filename correctly\n");
        fprintf(stderr, "  • Make sure the file is in the current directory\n");
        fprintf(stderr, "  • Try using the full path to the file\n");
        fprintf(stderr, "  • Use 'ls' to see files in current directory\n\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  lsw --launch ./app.exe              # Current directory\n");
        fprintf(stderr, "  lsw --launch ~/Downloads/game.exe   # Full Linux path\n");
        fprintf(stderr, "  lsw --launch C:\\\\Windows\\\\notepad.exe  # Windows path\n\n");
        fprintf(stderr, "Need help? Run: lsw --help\n\n");
        return 1;
    }
    
    LSW_LOG_INFO("File found: %s", executable_path);
    
    // Load and execute PE file
    pe_image_t image;
    if (!pe_load_image(&image, executable_path)) {
        fprintf(stderr, "\n❌ Failed to load PE file\n\n");
        return 1;
    }
    
    // Display PE info
    printf("\n");
    printf("✅ PE file loaded successfully\n\n");
    printf("Architecture: %s\n", image.pe.is_64bit ? "x64 (64-bit)" : "x86 (32-bit)");
    printf("Subsystem: %s\n", 
           pe_get_subsystem(&image.pe) == PE_SUBSYSTEM_WINDOWS_GUI ? "GUI" :
           pe_get_subsystem(&image.pe) == PE_SUBSYSTEM_WINDOWS_CUI ? "Console" : "Other");
    printf("Type: %s\n", pe_is_dll(&image.pe) ? "DLL" : "Executable");
    printf("Image Base: 0x%llx\n", (unsigned long long)pe_get_image_base(&image.pe));
    printf("Entry Point: %p (RVA: 0x%08x)\n", image.entry_point, pe_get_entry_point(&image.pe));
    printf("Image Size: 0x%lx bytes\n", image.image_size);
    printf("Sections: %u\n", image.pe.num_sections);
    printf("\n");
    
    // Build PE-specific argc/argv (starting from executable, including all args after)
    int pe_argc = 0;
    char** pe_argv = NULL;
    
    if (executable_index >= 0) {
        // Count remaining args after executable
        pe_argc = argc - executable_index;
        pe_argv = &argv[executable_index];
    } else {
        // No arguments - just executable
        pe_argc = 1;
        pe_argv = &executable_path;
    }
    
    // Execute
    int exit_code = pe_execute(&image, pe_argc, pe_argv);
    
    // Clean up
    pe_unload_image(&image);
    
    return exit_code;
}
