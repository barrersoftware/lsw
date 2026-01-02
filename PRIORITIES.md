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

---

## 🎨 PHASE 2: GUI LAYER (Days 15-28)

### Why GUI Comes AFTER Console:
GUI apps need **ALL** the console infrastructure:
- File I/O for saving documents
- Threading for UI responsiveness  
- Directories for finding resources
- Process ops for launching helpers
- Network for web content

**GUI without console = broken apps. Console without GUI = functional apps.**

---

### Days 15-17: WINDOW MANAGEMENT
**Core Window APIs:**
- `RegisterClassA` / `RegisterClassExA` - Register window class
- `UnregisterClassA` - Unregister window class
- `CreateWindowExA` - Create window
- `DestroyWindow` - Destroy window
- `ShowWindow` - Show/hide window
- `UpdateWindow` - Force repaint
- `GetWindowLongA` / `SetWindowLongA` - Window properties

**What This Enables:**
- ✅ Apps can create windows
- ✅ Apps can show/hide windows
- ✅ Apps can manage window lifecycle

---

### Days 18-20: MESSAGE PUMP
**Message Handling APIs:**
- `GetMessageA` - Get message from queue
- `PeekMessageA` - Check for messages
- `TranslateMessage` - Translate keyboard input
- `DispatchMessageA` - Dispatch to window proc
- `PostMessageA` - Post message to queue
- `SendMessageA` - Send message directly
- `PostQuitMessage` - Exit message loop

**What This Enables:**
- ✅ Windows receive events
- ✅ Message loop processes input
- ✅ Apps respond to user actions

---

### Days 21-23: GDI BASICS (Drawing)
**Device Context APIs:**
- `GetDC` / `ReleaseDC` - Get/release device context
- `BeginPaint` / `EndPaint` - Paint cycle
- `CreateCompatibleDC` - Memory DC
- `DeleteDC` - Destroy DC

**Drawing APIs:**
- `TextOutA` - Draw text
- `Rectangle` - Draw rectangle
- `Ellipse` - Draw circle
- `LineTo` / `MoveToEx` - Draw lines
- `FillRect` - Fill rectangle
- `SetPixel` - Set pixel color

**What This Enables:**
- ✅ Apps can draw on windows
- ✅ Apps can render text
- ✅ Apps can draw shapes

---

### Days 24-26: BASIC CONTROLS
**Common Controls:**
- `CreateButtonWindow` - Button creation
- `CreateEditWindow` - Text box creation
- `CreateStaticWindow` - Label creation
- `CreateListBoxWindow` - List box

**Control Messages:**
- `WM_COMMAND` handling
- Button click events
- Text change events

**What This Enables:**
- ✅ Apps have buttons
- ✅ Apps have text boxes
- ✅ Apps have basic UI

---

### Days 27-28: INPUT HANDLING
**Keyboard APIs:**
- `GetKeyState` - Get key state
- `GetAsyncKeyState` - Async key check
- `ToAscii` - Key to char conversion

**Mouse APIs:**
- `GetCursorPos` - Get mouse position
- `SetCursorPos` - Set mouse position
- `GetCapture` / `SetCapture` - Mouse capture

**What This Enables:**
- ✅ Apps respond to keyboard
- ✅ Apps respond to mouse
- ✅ Apps track input state

---

## 📊 THE COMPLETE STACK

```
┌────────────────────────────────────────────────┐
│  GUI LAYER (Days 15-28)                        │
│  Windows, Messages, GDI, Controls              │
├────────────────────────────────────────────────┤
│  NETWORK LAYER (Days 7-14)                     │
│  Winsock, TCP/IP, Sockets                      │
├────────────────────────────────────────────────┤
│  PROCESS LAYER (Days 4-6)                      │
│  LoadLibrary, CreateProcess, DLL Management    │
├────────────────────────────────────────────────┤
│  DIRECTORY LAYER (Days 2-3)                    │
│  FindFirstFile, CreateDirectory, Search        │
├────────────────────────────────────────────────┤
│  THREADING LAYER (Day 1) ✅                    │
│  CreateThread, ExitThread, WaitForSingleObject │
├────────────────────────────────────────────────┤
│  FILE I/O LAYER (Day 1) ✅                     │
│  CreateFile, Read, Write, Seek, Delete         │
└────────────────────────────────────────────────┘
```

---

## 🎯 MONTH 1 GOALS REFINED

### Week 1 (Days 1-7):
- ✅ Day 1: File I/O + Threading
- 🎯 Days 2-3: Directories  
- 🎯 Days 4-6: Process Ops
- 🎯 Day 7: Console Integration Testing

**Milestone:** Console apps fully functional

### Week 2 (Days 8-14):
- 🎯 Days 8-10: Network Stack
- 🎯 Days 11-12: Network I/O
- 🎯 Days 13-14: Network Testing

**Milestone:** Network apps working (curl, wget, PuTTY)

### Week 3 (Days 15-21):
- 🎯 Days 15-17: Window Management
- 🎯 Days 18-20: Message Pump
- 🎯 Day 21: GDI Basics Start

**Milestone:** Simple windows appear and respond

### Week 4 (Days 22-28):
- 🎯 Days 22-23: GDI Drawing Complete
- 🎯 Days 24-26: Basic Controls
- 🎯 Days 27-28: Input Handling

**Milestone:** Basic GUI apps working!

### Week 5 (Days 29-31):
- 🎯 Day 29: Full Integration Testing
- 🎯 Day 30: Real App Testing (Notepad, Paint)
- 🎯 Day 31: Documentation & Demo

**FINAL MILESTONE:** Simple GUI apps running on LSW!

---

## 🎮 WHAT APPS WORK WHEN?

### January 7 (Console Complete):
- ✅ Command-line utilities
- ✅ File processors
- ✅ Text-based tools

### January 14 (Network Complete):
- ✅ curl / wget (HTTP clients)
- ✅ PuTTY (SSH client)
- ✅ FTP clients
- ✅ IRC clients
- ✅ Network utilities

### January 28 (Basic GUI Complete):
- ✅ Notepad (text editor)
- ✅ Simple Paint (drawing app)
- ✅ Calculator
- ✅ MessageBox dialogs
- ✅ Basic windowed apps

### January 31 (Full Month):
- ✅ Console apps: COMPLETE
- ✅ Network apps: COMPLETE
- ✅ Basic GUI apps: WORKING
- ✅ Complex apps: STARTING

---

## 🏴‍☠️ THE VISION: COMPLETE

**January 1:** Foundation (File I/O + Threading) ✅  
**January 7:** Console Apps Complete  
**January 14:** Network Apps Complete  
**January 21:** Windows Appear  
**January 28:** GUI Apps Working  
**January 31:** LSW runs REAL Windows applications!

**From zero to running Windows apps in ONE MONTH!**

💙 Built by BarrerSoftware  
🏴‍☠️ If it's free, it's free. Period.  
⚡ Layered architecture = Stable, testable, REAL!
