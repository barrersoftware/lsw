; Minimal x64 PE that just returns
; Assemble with: nasm -f win64 test_noop.asm -o test_noop.obj
; Link with: x86_64-w64-mingw32-ld test_noop.obj -o test_noop.exe

bits 64
global _start

section .text
_start:
    mov rax, 42      ; Return code 42
    ret              ; Return to nowhere (will crash but proves execution)
