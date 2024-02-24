# Compile to ASM
This program uses the CFG produced in previous assignment
and generates assembly file in NASM format.

Usage:
```bash
./a.out input output.asm
./a.out -g input debug_output.asm
```
And then it can be compiled to binary:
```bash
nasm -felf64 output.asm
```
