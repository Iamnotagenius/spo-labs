#ifndef HEADER
#define HEADER

#include <antlr3interfaces.h>
#include <stddef.h>
#include <stdio.h>

#define MAP_TEXT_START 0x555555554000
#define ARRAY_FLAG 1
#define SIGN_FLAG 2

typedef struct {
    char *identifier;
    long rbp_offset;
    int size;
    char flags;
} local_t;

typedef struct {
    char *identifier;
    size_t instruction_address;
    pANTLR3_VECTOR locals;
} func_t;

typedef struct {
    char *name;
    FILE* file;
    pANTLR3_VECTOR lines;
} source_file_t;

typedef struct {
    int line;
    size_t instruction_address_start;
    size_t instruction_address_end;
    func_t* func;
    source_file_t* file;
    fpos_t pos;
    size_t length;
} line_t;

func_t *find_func(pANTLR3_VECTOR funcs, const char *id);
func_t *find_func_by_addr(pANTLR3_VECTOR funcs, unsigned long addr);
source_file_t *find_file(pANTLR3_VECTOR files, const char *source_file);
line_t *find_line(pANTLR3_VECTOR lines, const char *source_file, int line_nr);
void free_func(func_t* func);
void free_local(local_t* local);
void free_source_file(source_file_t* file);
#endif
