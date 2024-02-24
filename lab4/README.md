# Debugger
A debugger built from scratch using ptrace syscall.
It can use debug symbols produced by previous program to
inspect local variables and step over one source line.

Usage:
```bash
./a.out compiled
```
It is an interactive console application, it supports the following commands:
 - `b`, `breakpoint` - set breakpoint at a given address
 - `regs`, `registers` - display current data in registers
 - `ni`, `nexti` - execute one instruction
 - `n`, `next` - execute one source line
 - `r`, `read` - read process memory at a given address in hexadecimal format
 - `disas`, `disassemble` - disassemble instructions at a given address (using intelxed library)
 - `l`, `locals` - display current values of local variables
