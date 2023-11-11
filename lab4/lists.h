#ifndef HEADER_LISTS_H
#define HEADER_LISTS_H

#include <antlr3interfaces.h>
#include <stddef.h>
#include <stdio.h>

#include "../lab3/lib3.h"

typedef struct {
    char *identifier;
    long rbp_offset;
    int size;
    type_flags flags;
    struct_t* type;
} local_t;

typedef struct {
    char *identifier;
    size_t instruction_address;
    pANTLR3_VECTOR locals;
} dbg_func_t;

typedef struct {
    char *name;
    FILE* file;
    pANTLR3_VECTOR lines;
} source_file_t;

typedef struct {
    int line;
    size_t instruction_address_start;
    size_t instruction_address_end;
    dbg_func_t* func;
    source_file_t* file;
    fpos_t pos;
    size_t length;
} line_t;

dbg_func_t *find_func(pANTLR3_VECTOR funcs, const char *id);
dbg_func_t *find_func_by_addr(pANTLR3_VECTOR funcs, unsigned long addr);
source_file_t *find_file(pANTLR3_VECTOR files, const char *source_file);
line_t *find_line(pANTLR3_VECTOR lines, const char *source_file, int line_nr);
void free_func(dbg_func_t* func);
void free_local(local_t* local);
void free_source_file(source_file_t* file);
void free_struct(struct_t *s);
#endif
