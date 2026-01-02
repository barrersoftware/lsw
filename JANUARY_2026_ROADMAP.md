# LSW January 2026 Roadmap
## "One Function Group Per Day = Real Apps By Month End"

🏴‍☠️ **Started:** January 1, 2026 (PST)  
📊 **Current Status:** Day 1 Complete - File I/O Working  
🎯 **Goal:** Basic Win32 apps running + Complex apps starting by Jan 31

---

## Week 1: Core APIs (Jan 1-7)
- ✅ **Day 1 (Jan 1):** File I/O Complete
  - CreateFileA, ReadFile, WriteFile, GetFileSize, SetFilePointer, DeleteFileA
- **Day 2:** Threading APIs
  - CreateThread, ExitThread, GetExitCodeThread, TerminateThread
- **Day 3:** Directory Operations
  - CreateDirectoryA, RemoveDirectoryA, FindFirstFileA, FindNextFileA, FindClose
- **Day 4:** Synchronization Objects
  - CreateMutexA, ReleaseMutex, WaitForSingleObject (wrapper)
- **Day 5:** Process Management
  - CreateProcessA, GetCurrentProcess, GetCurrentThread
- **Day 6:** Time Functions
  - GetSystemTime, GetLocalTime, Sleep (enhance), GetTickCount
- **Day 7:** Environment/Registry Basics
  - GetEnvironmentVariableA, SetEnvironmentVariableA

**Milestone:** Console applications fully functional

---

## Week 2: Extended File & Process (Jan 8-14)
- **Day 8:** Advanced File Ops
  - MoveFileA, CopyFileA, GetFileAttributesA, SetFileAttributesA
- **Day 9:** File Searching
  - GetFullPathNameA, GetCurrentDirectoryA, SetCurrentDirectoryA
- **Day 10:** Process Communication
  - CreatePipe, ReadFile/WriteFile for pipes
- **Day 11:** Thread Synchronization
  - CreateEventA (enhance), SetEvent, ResetEvent, WaitForMultipleObjects
- **Day 12:** DLL Loading
  - LoadLibraryA, GetProcAddress, FreeLibrary (route through kernel)
- **Day 13:** Error Handling
  - SetLastError, GetLastError (enhance), FormatMessageA
- **Day 14:** Console I/O
  - GetConsoleMode, SetConsoleMode, ReadConsoleA, WriteConsoleA

**Milestone:** File utilities working (dir, copy, move commands)

---

## Week 3: Networking & IPC (Jan 15-21)
- **Day 15:** Socket Basics
  - socket, bind, listen, accept, connect (Winsock translation)
- **Day 16:** Socket I/O
  - send, recv, closesocket, WSAGetLastError
- **Day 17:** Named Pipes
  - CreateNamedPipeA, ConnectNamedPipe, DisconnectNamedPipe
- **Day 18:** Memory Mapped Files
  - CreateFileMappingA, MapViewOfFile, UnmapViewOfFile
- **Day 19:** Heap Management
  - HeapCreate, HeapAlloc, HeapFree, HeapDestroy
- **Day 20:** String Operations
  - lstrcpyA, lstrcatA, lstrlenA (enhance), CompareStringA
- **Day 21:** Character Conversion
  - CharUpperA, CharLowerA, MultiByteToWideChar (enhance)

**Milestone:** Network client apps working (curl-like tools)

---

## Week 4: GUI Foundation (Jan 22-28)
- **Day 22:** Window Classes
  - RegisterClassA, UnregisterClassA
- **Day 23:** Window Creation
  - CreateWindowExA, DestroyWindow, ShowWindow
- **Day 24:** Message Queue
  - GetMessageA, PeekMessageA, DispatchMessageA, PostQuitMessage
- **Day 25:** Device Context Basics
  - GetDC, ReleaseDC, CreateCompatibleDC, DeleteDC
- **Day 26:** GDI Drawing
  - TextOutA, Rectangle, Ellipse, LineTo, MoveToEx
- **Day 27:** Bitmap Operations
  - CreateBitmap, BitBlt, StretchBlt, DeleteObject
- **Day 28:** Input Handling
  - GetKeyState, GetAsyncKeyState, GetCursorPos, SetCursorPos

**Milestone:** Simple GUI apps starting (MessageBox, basic windows)

---

## Week 5: Integration & Testing (Jan 29-31)
- **Day 29:** Integration Testing
  - Test suite for all implemented APIs
  - Fix compatibility issues
- **Day 30:** Real App Testing
  - Run actual Win32 console utilities
  - Run simple GUI applications
  - Document what works / what needs work
- **Day 31:** Documentation & Showcase
  - Update README with supported APIs
  - Create demo videos
  - Write blog post: "LSW: One Month, 200+ APIs"

**Final Milestone:** Basic Win32 apps fully working, complex apps starting!

---

## API Count Goal
- **Start (Jan 1):** 28 APIs
- **Week 1 End:** ~50 APIs
- **Week 2 End:** ~100 APIs
- **Week 3 End:** ~150 APIs
- **Week 4 End:** ~200 APIs
- **Month End:** 200+ Win32 APIs functional!

---

## Testing Strategy
- Daily: Add test program for new APIs
- Weekly: Run existing Win32 utilities
- Month End: Showcase real applications running

---

## Win32 Apps Target By Jan 31
✅ **Console Apps:**
- dir, copy, move, del commands
- findstr, fc (file compare)
- Simple text processors

✅ **File Utilities:**
- 7-Zip (command line)
- WinRAR (command line)
- Notepad (if GUI ready)

✅ **Network Tools:**
- netstat, ping equivalents
- Simple HTTP clients
- FTP clients

✅ **Starting Complex Apps:**
- Visual Studio Code (parts working)
- PuTTY (SSH client)
- Basic games (if graphics ready)

---

**🏴‍☠️ Built by BarrerSoftware**  
**If it's free, it's free. Period.**  
**💙 One function group per day = Windows on Linux this month!**
