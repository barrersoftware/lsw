# LSW Friendly Help System Design

**Philosophy:** Help should HELP, not gatekeep.

---

## Core Principles

1. **Assume NO prior knowledge**
2. **Explain WHY not just WHAT**
3. **Provide examples for everything**
4. **Welcome beginners warmly**
5. **No gatekeeping, no assumptions**

---

## Help Access (Forgiving)

All of these should show help:

```bash
lsw --help        # Standard
lsw --h           # Short
lsw -h            # Single dash
lsw -?            # Question mark
lsw ?             # Just question mark
lsw help          # Natural language
lsw --help me     # Natural variation
lsw what          # Confused user
lsw how           # Confused user
```

**Philosophy:** If user is asking for help, HELP THEM.

---

## Help Content Structure

### 1. General Help (lsw --help)

```
╔══════════════════════════════════════════════════════════════╗
║  LSW - Linux Subsystem for Windows                          ║
║  Run Windows programs on Linux (simple!)                    ║
╚══════════════════════════════════════════════════════════════╝

👋 HELLO! WELCOME TO LSW!

If this is your first time, don't worry - it's super simple.
LSW lets you run Windows programs (.exe files) on Linux.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 QUICK START (Get Running in 30 Seconds)

Want to run a Windows program? Just type:

  lsw --launch yourprogram.exe

That's it! LSW will automatically:
  • Figure out what Windows version the program needs
  • Load the right libraries
  • Run your program

Example:
  lsw --launch notepad.exe
  lsw --launch /mnt/c/Games/game.exe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📖 MAIN COMMANDS (The Important Ones)

  --launch [file]
    Run a Windows program
    Example: lsw --launch app.exe
    
  --install [file]
    Install Windows software (MSI files)
    Example: lsw --install setup.msi
    
  --list
    See what Windows programs you've installed
    Example: lsw --list
    
  --help
    Show this helpful guide (you're reading it!)
    
  --version
    Check what version of LSW you're running

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️  EXTRA OPTIONS (When You Need More Control)

  -version [windows-version]
    Force a specific Windows version
    Options: xp, vista, win7, win10, win11
    Example: lsw --launch oldgame.exe -version xp
    
    Why use this? Some old programs need old Windows versions.
    
  -debug
    See detailed information (helpful when things go wrong)
    Example: lsw --launch app.exe -debug
    
    Why use this? To see what's happening behind the scenes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 COMMON QUESTIONS

Q: Where are my Windows files?
A: Your C: drive is at /mnt/c
   Your D: drive is at /mnt/d
   (Same as WSL if you've used that!)

Q: My program won't run!
A: Try adding -debug to see what's wrong:
   lsw --launch app.exe -debug
   
Q: Can I run games?
A: Yes! Try: lsw --launch game.exe -version win7

Q: How do I install software?
A: Use: lsw --install setup.msi

Q: Something's broken, help!
A: Visit: https://lsw.barrersoftware.com/troubleshooting
   Or report: https://github.com/barrersoftware/lsw/issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📚 NEED MORE HELP?

  Full Documentation: https://lsw.barrersoftware.com
  Quick Start Guide:  https://lsw.barrersoftware.com/quickstart
  Troubleshooting:    https://lsw.barrersoftware.com/troubleshooting
  Examples:           https://lsw.barrersoftware.com/examples

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Remember: LSW is designed to be simple!
If you're confused, we probably made something unclear.
Let us know: https://github.com/barrersoftware/lsw/issues

Happy Windows-on-Linux! 🐧🪟

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 2. Command-Specific Help (lsw --help --launch)

```
╔══════════════════════════════════════════════════════════════╗
║  LSW --launch Command                                        ║
║  Run Windows programs on Linux                               ║
╚══════════════════════════════════════════════════════════════╝

📖 WHAT DOES THIS DO?

The --launch command runs Windows programs (.exe files) on Linux.
It's like double-clicking an .exe file on Windows, but from Linux!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 BASIC USAGE

Simplest form (LSW auto-detects everything):
  lsw --launch yourprogram.exe

With full path:
  lsw --launch /mnt/c/Program\ Files/App/program.exe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️  OPTIONS YOU CAN USE

-version [windows-version]
  Tell LSW which Windows version to pretend to be
  
  Options: xp, vista, win7, win8, win10, win11
  
  Example: lsw --launch oldgame.exe -version xp
  
  When to use:
    • Old programs that need old Windows (use xp or win7)
    • New programs (usually auto-detect works fine)
    • Program says "Requires Windows 7" (use -version win7)

-debug
  Show detailed information about what's happening
  
  Example: lsw --launch app.exe -debug
  
  When to use:
    • Program won't start (see what's wrong)
    • Curious about what LSW is doing
    • Reporting a bug (include this output!)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 REAL-WORLD EXAMPLES

Run Notepad:
  lsw --launch notepad.exe

Run a game that needs Windows XP:
  lsw --launch /mnt/c/Games/OldGame.exe -version xp

Debug why a program won't start:
  lsw --launch broken.exe -debug

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤔 TROUBLESHOOTING

Problem: "File not found"
Solution: Use the full path to your .exe file
  Example: lsw --launch /mnt/c/path/to/file.exe

Problem: Program won't start
Solution: Try with -debug to see what's wrong
  Example: lsw --launch app.exe -debug

Problem: Program says "wrong Windows version"
Solution: Specify the version it needs
  Example: lsw --launch app.exe -version win7

Still stuck? Visit: https://lsw.barrersoftware.com/troubleshooting

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 3. No Arguments (lsw)

```
👋 Hi! You ran LSW but didn't tell it what to do.

Need to run a Windows program? Try:
  lsw --launch yourprogram.exe

Want to see what you can do? Try:
  lsw --help

Quick examples:
  lsw --launch app.exe              Run a program
  lsw --install setup.msi           Install software
  lsw --list                        See installed programs

More help: https://lsw.barrersoftware.com
```

---

## Error Messages (Friendly)

### File Not Found

```
❌ Oops! File not found

LSW couldn't find: nonexistent.exe

💡 Tips:
  • Make sure you spelled the filename correctly
  • Try using the full path: /mnt/c/path/to/file.exe
  • Your C: drive is at /mnt/c on Linux
  • Use 'ls' to see files in current directory

Example:
  lsw --launch /mnt/c/Program\ Files/App/app.exe

Need help? Run: lsw --help
```

### Invalid Option

```
⚠️  Hmm, that Windows version isn't recognized

You used: windows7
Did you mean: win7 ?

Valid options:
  • xp      (Windows XP)
  • vista   (Windows Vista)
  • win7    (Windows 7)
  • win8    (Windows 8)
  • win10   (Windows 10)
  • win11   (Windows 11)

Example:
  lsw --launch app.exe -version win7

Need help? Run: lsw --help
```

### Command Typo

```
❓ Command not recognized: --launche

Did you mean: --launch ?

Common LSW commands:
  lsw --launch [file]   - Run a Windows program
  lsw --install [file]  - Install Windows software
  lsw --list            - See installed programs
  lsw --help            - Show help guide

Example:
  lsw --launch app.exe

Need help? Run: lsw --help
```

---

## Implementation Notes

### Help Request Detection (C)

```c
bool is_help_request(char* arg) {
    // Standard help flags
    if (strcmp(arg, "--help") == 0) return true;
    if (strcmp(arg, "--h") == 0) return true;
    if (strcmp(arg, "-h") == 0) return true;
    if (strcmp(arg, "-?") == 0) return true;
    if (strcmp(arg, "?") == 0) return true;
    
    // Natural language variations
    if (strcmp(arg, "help") == 0) return true;
    if (strstr(arg, "help") != NULL) return true;
    
    // Confused users
    if (strcmp(arg, "what") == 0) return true;
    if (strcmp(arg, "how") == 0) return true;
    
    return false;
}
```

### Visual Elements

- Box drawing: `╔══╗ ╚══╝`
- Dividers: `━━━`
- Emojis: `👋 🚀 📖 💡 ❌ ⚠️ ✅`
- Clear sections with whitespace

### Tone Guidelines

- **Welcoming:** "Hi!" not "ERROR"
- **Encouraging:** "Oops!" not "FAILED"  
- **Helpful:** "Try this:" not "See manual"
- **Patient:** Explain, don't assume
- **Friendly:** Conversational, not corporate

---

## Success Metrics

User should be able to:
1. Run their first Windows program within **5 minutes** of seeing LSW
2. Understand what went wrong when something fails
3. Feel welcomed, not intimidated
4. Know where to get more help

**Goal:** Anyone can use LSW. No prior knowledge required.

---

🏴‍☠️ **Help that actually helps.**
