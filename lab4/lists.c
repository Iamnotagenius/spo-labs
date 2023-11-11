#include "lists.h"
#include <antlr3collections.h>
#include <antlr3interfaces.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lab3/lib3.h"

dbg_func_t *find_func(pANTLR3_VECTOR funcs, const char *id) {
    for (int i = 0; i < funcs->count; i++) {
        dbg_func_t* func = funcs->get(funcs, i);
        if (strcmp(func->identifier, id) == 0) {
            return func;
        }
    }
    return NULL;
}

dbg_func_t *find_func_by_addr(pANTLR3_VECTOR funcs, unsigned long addr) {
    for (int i = 0; i < funcs->count; i++) {
        dbg_func_t *func = funcs->get(funcs, i);
        if (func->instruction_address == addr) {
            return func;
        }
    }
    return NULL;
}

source_file_t *find_file(pANTLR3_VECTOR files, const char *source_file) {
    for (int i = 0; i < files->count; i++) {
        source_file_t* file = files->get(files, i);
        if (strcmp(file->name, source_file) == 0) {
            return file;
        }
    }
    return NULL;
}

line_t *find_line(pANTLR3_VECTOR lines, const char *source_file, int line_nr) {
    for (int i = 0; i < lines->count; i++) {
        line_t* line = lines->get(lines, i);
        if (strcmp(line->file->name, source_file) == 0 && line->line == line_nr) {
            return line;
        }
    }
    return NULL;
}

void free_func(dbg_func_t* func) {
    if (func == NULL) {
        return;
    }
    free(func->identifier);
    func->locals->free(func->locals);
    free(func);
}

void free_source_file(source_file_t* file) {
    free(file->name);
    fclose(file->file);
    file->lines->free(file->lines);
    free(file);
}

void free_local(local_t* local) {
    free(local->identifier);
    free(local);
}

void free_struct(struct_t* s) {
    free(s->members);
    free(s);
}
