# 🎯 LSW DEVELOPMENT PRIORITIES
## Based on Real App Requirements

---

## ✅ COMPLETED (Day 1)
1. **File I/O** - Apps can read/write files ✅
2. **Threading** - Apps can spawn workers ✅

---

## 🔥 TOP PRIORITIES (Next 3 Function Groups)

### Priority 1: DIRECTORIES (Days 2-3)
**Why:** Apps need to search for config files, DLLs, and dependencies

**Critical APIs:**
- `FindFirstFileA` - Start searching directory
- `FindNextFileA` - Continue search
- `FindClose` - Close search handle
- `CreateDirectoryA` - Create folders
- `RemoveDirectoryA` - Delete folders
- `GetCurrentDirectoryA` - Get working directory
- `SetCurrentDirectoryA` - Change working directory

**What This Enables:**
- ✅ Apps can search for DLL files
- ✅ Apps can find configuration files
- ✅ Apps can enumerate directories
- ✅ Apps can create folder structures

**Example:** App looks for `config.ini` in current directory or searches for `user32.dll`

---

### Priority 2: PROCESS OPERATIONS (Days 4-6)
**Why:** Apps need to load DLLs and launch child processes

**Critical APIs:**

**DLL Loading:**
- `LoadLibraryA` - Load DLL into process
- `GetProcAddress` - Get function pointer from DLL
- `FreeLibrary` - Unload DLL

**Process Management:**
- `CreateProcessA` - Launch child process
- `GetCurrentProcess` - Get process handle
- `GetCurrentThread` - Get thread handle
- `TerminateProcess` - Kill process
- `GetExitCodeProcess` - Get process exit code

**What This Enables:**
- ✅ Apps can load plugin DLLs
- ✅ Apps can call DLL functions
- ✅ Apps can launch child programs
- ✅ Apps can manage subprocesses

**Example:** App loads `user32.dll` and calls `MessageBoxA`, or launches `notepad.exe`

---

### Priority 3: NETWORK STACK (Days 7-10)
**Why:** Network apps need TCP/IP connectivity

**Critical APIs (Winsock → Linux sockets):**

**Socket Creation:**
- `WSAStartup` - Initialize Winsock
- `socket` - Create socket
- `bind` - Bind to port
- `listen` - Listen for connections
- `accept` - Accept connection
- `connect` - Connect to server

**Socket I/O:**
- `send` - Send data
- `recv` - Receive data
- `closesocket` - Close socket

**Socket Options:**
- `setsockopt` - Set socket options
- `getsockopt` - Get socket options
- `select` - Wait for socket events

**Address/Name:**
- `getaddrinfo` - Resolve hostname
- `gethostbyname` - Get host by name
- `inet_addr` - Convert IP string

**What This Enables:**
- ✅ Apps can connect to TCP servers
- ✅ Apps can create TCP servers
- ✅ Apps can send/receive data
- ✅ Apps can resolve hostnames
- ✅ HTTP clients work
- ✅ SSH clients work
- ✅ FTP clients work

**Example:** HTTP client connects to web server, SSH client connects to remote host

---

## 📊 IMPLEMENTATION APPROACH

### Directories (Easiest)
- Translate to Linux `opendir()`, `readdir()`, `closedir()`
- Convert WIN32_FIND_DATA to Linux `struct dirent`
- Map Windows paths to Linux paths
- **Estimated:** 2-3 days

### Process Operations (Medium)
- LoadLibrary: Use Linux `dlopen()`
- GetProcAddress: Use Linux `dlsym()`
- CreateProcess: Use Linux `fork()` + `execve()`
- **Estimated:** 3-4 days

### Network Stack (Complex)
- Winsock types → Linux socket types
- Windows socket handles → Linux file descriptors
- WSA error codes → Linux errno
- Async socket operations via epoll/select
- **Estimated:** 4-5 days

---

## 🎯 WEEK 1-2 GOAL

**Week 1 (Days 1-7):**
- ✅ Day 1: File I/O + Threading
- 🎯 Days 2-3: Directories
- 🎯 Days 4-6: Process Ops
- 🎯 Day 7: Testing/Integration

**Week 2 (Days 8-14):**
- 🎯 Days 8-10: Network Stack (Winsock basics)
- 🎯 Days 11-12: Network I/O (send/recv)
- 🎯 Days 13-14: Testing with real apps

---

## 💡 WHY THIS ORDER?

**1. Directories First:**
- Simplest to implement
- Unlocks app initialization (finding config files)
- Required before DLL loading (apps search for DLLs)

**2. Process Ops Second:**
- Builds on directory support (finding DLLs)
- Enables plugin systems
- Enables multi-process apps

**3. Network Last:**
- Most complex translation layer
- Requires careful handle management
- Benefits from stable File I/O + Threading

---

## 🎮 WHAT APPS WILL WORK AFTER THESE?

### After Directories (Day 3):
- ✅ Console apps that need config files
- ✅ Apps that search for files
- ✅ File management utilities

### After Process Ops (Day 6):
- ✅ Apps with plugin systems
- ✅ Apps that launch child processes
- ✅ Shell-like programs
- ✅ Compilers/interpreters

### After Network (Day 14):
- ✅ HTTP clients (curl, wget)
- ✅ SSH clients (PuTTY)
- ✅ FTP clients
- ✅ IRC clients
- ✅ Simple web servers
- ✅ Network utilities (netstat, ping)

---

## 📈 ESTIMATED TIMELINE

```
Day 1:  ████████████████████ File I/O + Threading ✅
Day 2:  ████████░░░░░░░░░░░░ Directory ops (50%)
Day 3:  ████████████████████ Directory ops (100%)
Day 4:  ████████░░░░░░░░░░░░ DLL loading (50%)
Day 5:  ████████████████████ DLL loading (100%)
Day 6:  ████████████████████ Process management
Day 7:  ████████████████████ Integration testing
Day 8:  ████████░░░░░░░░░░░░ Winsock basics (50%)
Day 9:  ████████████████████ Winsock basics (100%)
Day 10: ████████████████████ Socket I/O
Day 11: ████████████████████ Socket options
Day 12: ████████████████████ Address resolution
Day 13: ████████████████████ Real app testing
Day 14: ████████████████████ Network utilities working!
```

---

## 🏴‍☠️ THE GOAL

**By Day 14 (January 15, 2026):**
- File I/O ✅
- Threading ✅
- Directories ✅
- Process Ops ✅
- Network Stack ✅

**= COMPLETE CONSOLE + NETWORK APPS WORKING!**

PuTTY, curl, wget, network utilities, file managers - ALL RUNNING!

---

💙 Built by BarrerSoftware  
🏴‍☠️ If it's free, it's free. Period.  
⚡ One function group at a time = Real apps THIS MONTH!
