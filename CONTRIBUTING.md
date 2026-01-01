# Contributing to LSW

Thank you for your interest in contributing to LSW (Linux Subsystem for Windows)!

## 🏴‍☠️ Our Philosophy

**"If it's free, it's free. Period."**

LSW is licensed under the BarrerSoftware License (BSL) v1.0, which means:
- ✅ Free forever, cannot be sold
- ✅ Open source, community-driven
- ✅ Welcoming to all contributors
- ✅ No gatekeeping, just help

## 🚀 How to Contribute

### 1. Code Contributions

**Areas that need help:**
- PE format parsing
- Windows API implementation
- Registry emulation
- Filesystem translation
- Testing and bug fixes
- Documentation

**Process:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write tests if applicable
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### 2. Documentation

Help us make LSW accessible:
- Improve installation guides
- Add usage examples
- Write tutorials
- Fix typos or unclear explanations
- Translate documentation

### 3. Testing

- Test LSW with different Windows applications
- Report bugs with detailed reproduction steps
- Test on different Linux distributions
- Performance testing and benchmarking

### 4. Design and UX

- Improve error messages (make them friendly!)
- Design better help output
- Create diagrams for documentation
- Improve project website

## 📋 Code Style

**Keep it simple and readable:**

```c
// Good: Clear, commented, obvious
int lsw_load_dll(const char* dll_path) {
    // What: Load a Windows DLL
    // Why: Application needs this library
    // How: Parse PE format, map to memory
    
    if (!dll_path) {
        return LSW_ERROR_INVALID_PARAMETER;
    }
    
    // ... implementation
}

// Bad: Cryptic, uncommented
int ldd(char* p) {
    if(!p)return-1;
    // ... what does this do?
}
```

**Our conventions:**
- Use `lsw_` prefix for all public functions
- Comment with What/Why/How for complex logic
- Keep functions focused (one job per function)
- Use descriptive variable names
- Add examples in header files

## 🐛 Reporting Bugs

**Good bug report includes:**
- LSW version
- Linux distribution and version
- Windows application you're trying to run
- Full error message or output
- Steps to reproduce

**Use this template:**
```
**LSW Version:** 0.1.0
**OS:** Ubuntu 22.04 LTS
**Application:** notepad.exe (Windows 11)

**What happened:**
Tried to run notepad.exe but got error...

**Expected:**
Notepad should open

**Steps to reproduce:**
1. lsw --launch notepad.exe
2. See error message
3. ...

**Output:**
```
<paste full error here>
```
```

## 💡 Feature Requests

We love ideas! Open an issue with:
- Clear description of the feature
- Why it would be useful
- Example use cases
- Any implementation thoughts (optional)

## ❓ Questions

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Open an Issue
- **Security issues:** Email security@barrersoftware.com
- **License questions:** Email legal@barrersoftware.com

## 🎯 Project Goals

Keep these in mind when contributing:

1. **Native performance** - No emulation overhead
2. **Universal compatibility** - Works on any Linux distro
3. **User-friendly** - Easy to use, great error messages
4. **Well-documented** - Clear explanations for everything
5. **Free forever** - Protected by BSL from commercialization

## 🤝 Code of Conduct

**Be excellent to each other:**
- ✅ Welcoming and friendly
- ✅ Respectful of different viewpoints
- ✅ Constructive criticism
- ✅ Help newcomers learn
- ❌ No harassment or hostility
- ❌ No gatekeeping or elitism

We're building something for everyone. Act like it.

## 📜 License

By contributing to LSW, you agree that your contributions will be licensed under the BarrerSoftware License (BSL) v1.0.

**This means:**
- Your code will be free forever
- It cannot be sold by anyone
- It helps everyone access Windows software on Linux
- Community over commerce

## 🎉 Recognition

Contributors are listed in:
- CONTRIBUTORS.md file
- Release notes
- Project website

Thank you for helping make Windows apps accessible to Linux users! 🐧🪟

---

🏴‍☠️ **BarrerSoftware - Building bridges, not walls**

*Questions? Open an issue or start a discussion.*

---

## ⚖️ Legal Compliance - CRITICAL

### LSW Legal Purity Standards

**We are MORE legally pure than Wine.**

Wine allows users to download Microsoft DLLs (via winetricks). This is a gray area.
LSW implements EVERYTHING ourselves. This is crystal clear legally.

### Absolute Rules (Violations = Immediate PR Rejection)

#### ❌ NEVER EVER:
1. Include Microsoft DLLs in any commit
2. Download Microsoft binaries in code
3. Redistribute Microsoft CAB files
4. Copy Microsoft source code
5. Use decompiled Microsoft code
6. Include Microsoft fonts/icons/resources
7. Package Microsoft redistributables
8. Ship Wine DLLs containing MS code

#### ✅ ALWAYS:
1. Implement from public documentation
2. Write original code only
3. Add source attribution in comments
4. Reference learn.microsoft.com
5. Document clean-room methodology
6. Check against LEGAL.md
7. Update SOURCES.md for new APIs

### Example - The Right Way:

```c
/**
 * lsw_CreateFileA - Create or open a file
 * 
 * Reference: Microsoft Learn Documentation
 * https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
 * 
 * Implementation: BarrerSoftware clean-room implementation
 * Behavior: Matches documented Win32 API CreateFileA behavior
 * 
 * NO Microsoft source code used
 * NO Microsoft binaries required
 */
```

### If an App Needs a Missing DLL:

**Wrong Way (Wine's approach):**
- Use winetricks to download Microsoft's DLL ⚠️

**Right Way (LSW's approach):**
- Implement the DLL functions ourselves ✅
- Add to our win32_api.c ✅
- Document in SOURCES.md ✅
- Test against learn.microsoft.com spec ✅

### Legal Review Checklist for All PRs:

- [ ] No Microsoft binaries included
- [ ] No proprietary code copied
- [ ] All new APIs documented in SOURCES.md
- [ ] Source attribution in code comments
- [ ] Clean-room implementation verified
- [ ] No decompilation or reverse engineering
- [ ] References public documentation only

**Violation of these rules = PERMANENT CONTRIBUTOR BAN**

We are building something LEGENDARY and LEGAL. Don't fuck it up.

🏴‍☠️ **BarrerSoftware: 100% pure, 100% legal, 100% ours.**

