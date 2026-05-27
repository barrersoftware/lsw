# testapps/

Test applications for lsw (Linux Subsystem for Windows).

## Source files

These `.c` files are compiled on Windows (with MinGW or MSVC) to produce `.exe` test
binaries that are then run under the lsw PE loader on Linux.

| Source | Purpose |
|--------|---------|
| `test.c` | Basic hello-world smoke test |
| `test_args.c` | Command-line argument passing |
| `test_cmdline.c` | GetCommandLineW / CommandLineToArgvW |
| `test_console.c` | Console I/O (WriteConsoleW / ReadFile) |
| `test_console_and_file.c` | Mixed console + file I/O |
| `test_directories.c` | Directory enumeration (FindFirstFile etc.) |
| `test_env.c` | Environment variable access |
| `test_exit.c` | ExitProcess / exit codes |
| `test_file_cdrive.c` | File access via C:\\ path translation |
| `test_fileops.c` | CreateFile / ReadFile / WriteFile / CloseHandle |
| `test_handle.c` | Handle duplication / inheritance |
| `test_hello.c` | Minimal printf test |
| `test_minimal.c` | Minimal PE entry point |
| `test_network.c` | Winsock2 networking stubs |
| `test_noop.asm` | No-op PE (assembly) |
| `test_readwrite.c` | ReadFile / WriteFile round-trip |
| `test_readwrite_full.c` | Extended read/write coverage |
| `test_registry.c` | Registry key open / query |
| `test_registry_env.c` | Registry + environment interaction |
| `test_thread.c` | CreateThread / WaitForSingleObject |
| `test_threading_complete.c` | Full threading scenario |
| `test_widechar_files.c` | Wide-char (Unicode) file paths |
| `test_write.c` | WriteFile to stdout |
| `test_attributes.c` | GetFileAttributes / SetFileAttributes |
| `test_comprehensive.c` | Full API coverage smoke test |

## Pre-built binaries

`.exe` binaries are **not tracked in git** (see `.gitignore`).  
Rebuild them on Windows with MinGW:

```bash
x86_64-w64-mingw32-gcc -o test_hello.exe test_hello.c
```

Or cross-compile from Linux:

```bash
x86_64-w64-mingw32-gcc -o test_hello.exe test_hello.c -lkernel32
```

## Running tests

From the lsw build directory on Linux:

```bash
./lsw-pe-loader testapps/test_hello.exe
./lsw-pe-loader testapps/test_console.exe
```

Or use the test runner:

```bash
bash run_all_tests.sh
```
