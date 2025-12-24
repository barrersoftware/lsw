/*
 * Copyright (c) 2025 BarrerSoftware
 * Licensed under BarrerSoftware License (BSL) v1.0
 * If it's free, it's free. Period.
 */

#include "lsw_types.h"
#include "lsw_log.h"
#include "lsw_filesystem.h"
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
    printf("  lsw --launch /mnt/c/Games/game.exe\n");
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
    printf("A: Your C: drive is at /mnt/c\n");
    printf("   Your D: drive is at /mnt/d\n");
    printf("   (Same as WSL if you've used that!)\n");
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
    char* executable_path = NULL;
    
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
                executable_path = argv[++i];
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
                if (strcmp(argv[i], "xp") == 0) {
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
    
    // Check if file exists
    if (!lsw_fs_path_exists(executable_path)) {
        fprintf(stderr, "\n");
        fprintf(stderr, "❌ Oops! File not found\n\n");
        fprintf(stderr, "LSW couldn't find: %s\n\n", executable_path);
        fprintf(stderr, "💡 Tips:\n");
        fprintf(stderr, "  • Make sure you spelled the filename correctly\n");
        fprintf(stderr, "  • Try using the full path: /mnt/c/path/to/file.exe\n");
        fprintf(stderr, "  • Your C: drive is at /mnt/c on Linux\n");
        fprintf(stderr, "  • Use 'ls' to see files in current directory\n\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  lsw --launch /mnt/c/Windows/notepad.exe\n\n");
        fprintf(stderr, "Need help? Run: lsw --help\n\n");
        return 1;
    }
    
    LSW_LOG_INFO("File found: %s", executable_path);
    
    // TODO: Actually load and execute the PE file
    fprintf(stderr, "\n");
    fprintf(stderr, "🚧 LSW is still in early development\n\n");
    fprintf(stderr, "The foundation is built, but PE loading isn't implemented yet.\n");
    fprintf(stderr, "Check back soon, or contribute on GitHub!\n\n");
    fprintf(stderr, "https://github.com/barrersoftware/lsw\n\n");
    
    return 0;
}
