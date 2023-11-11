#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib3.h"
#include "../lab2/lib2.h"
#include "../lab1/lib1.h"
#include "../macros.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-g, --debug-symbols] INPUT OUTPUT\n", argv[0]);
        return 1;
    }
    bool generateDebugSymbols = false;
    if (strncmp(argv[1], "-g", 2) == 0 || strncmp(argv[1], "--debug-symbols", 15) == 0) {
        generateDebugSymbols = true;
    }
    ast_t* ast = parseFile((pANTLR3_UINT8)argv[1 + generateDebugSymbols]);
    if (ast->errors->count > 0) {
        fprintf(stderr, "There were %d errors while parsing a file\n", ast->errors->count);
        for (ANTLR3_UINT32 i = 0; i < ast->errors->count; i++) {
            pANTLR3_STRING err = CALL(ast->errors, get, i);
            fprintf(stderr, "%s\n", err->chars);
        }
        return 1;
    }
    source_info_t info = createCfgs(ast, (pANTLR3_UINT8)argv[1 + generateDebugSymbols]);
    for (ANTLR3_UINT32 i = 0; i < info.cfgs->count; i++) {
        cfg_t* cfg = CALL(info.cfgs, get, i);
        if (cfg->errors->count > 0) {
            fprintf(stderr, "There were %d errors:\n", cfg->errors->count);
            for (ANTLR3_UINT32 i = 0; i < cfg->errors->count; i++) {
                pANTLR3_STRING err = CALL(cfg->errors, get, i);
                fprintf(stderr, "%s\n", err->chars);
            }
        }
    }

    asm_res_t asmRes = assemble(info, generateDebugSymbols);
    FILE* output = fopen(argv[argc - 1], "w+");
    fputs("default rel\n\n", output);
    for (ANTLR3_UINT32 i = 0; i < asmRes.externs->count; i++) {
        fprintf(output, "extern %s\n", CAST_CALL(pANTLR3_UINT8, asmRes.externs, get, i));
    }
    fputc('\n', output);
    for (ANTLR3_UINT32 i = 0; i < asmRes.asms->count; i++) {
        asm_t* a = CALL(asmRes.asms, get, i);
        fprintf(output, "global %s:function\n", a->funcName);
    }

    fputs("\nsection .data\n", output);
    if (generateDebugSymbols) {
        for (ANTLR3_UINT32 i = 0; i < asmRes.structs.count; i++) {
            struct_t* s = &asmRes.structs.structs[i];
            fprintf(output, "_STRUCTSZ$%s equ %ld\n", s->identifier->chars, s->totalSize);
            fprintf(output, "_STRUCTNMEMB$%s equ %ld\n", s->identifier->chars, s->memberCount);
            for (ANTLR3_UINT32 j = 0; j < s->memberCount; j++) {
                member_t* member = &s->members[j];
                fprintf(output, "_STRUCTMEMBOFF$%s$%s equ %ld\n", s->identifier->chars, member->identifier->chars, member->offset);
                fprintf(output, "_STRUCTMEMBSZ$%s$%s equ %ld\n", s->identifier->chars, member->identifier->chars, member->size);
            }
        }
    }
    for (ANTLR3_UINT32 i = 0; i < asmRes.asms->count; i++){
        asm_t* a = CALL(asmRes.asms, get, i);
        for (ANTLR3_UINT32 i = 0; i < a->strings->count; i++) {
            string_t* str = a->strings->get(a->strings, i);
            pANTLR3_STRING addr = CALL(str->addr, subString, 1, str->addr->len - 1);
            fprintf(output, "%s\tdb\t\"", addr->chars);
            unsigned char *cursor = str->string->chars;
            bool closed = false;
            while (*cursor != '\0') {
                if (*cursor == '"') {
                    cursor++;
                    continue;
                }
                if (*cursor != '\\') {
                    fputc(*cursor, output);
                }
                else {
                    cursor++;
                    switch (*cursor) {
                        case '0': fprintf(output, "\", 0"); closed = true; break;
                        case 'n': fprintf(output, "\", 10"); closed = true; break;
                        case 'r': fprintf(output, "\", 13"); closed = true; break;
                        case '"': fprintf(output, "\\\""); break;
                        case '\0':
                          cursor--;
                          break;
                    }
                    if (*(cursor + 1) != '\0' && *(cursor + 1) != '"') {
                        fprintf(output, ", \"");
                        closed = false;
                    }
                }
                cursor++;
            }
            if (!closed) {
                fputc('"', output);
            }
            fprintf(output, ", 0\n");
        }
        if (generateDebugSymbols) {
            for (ANTLR3_UINT32 i = 0; i < a->localAndArgOffsetMap->count; i++) {
                arg_offset_t* off = CALL(a->localAndArgOffsetMap, get, i);
                fprintf(output, "_LOCALOFF$%s@%s@%s equ %ld\n", off->identifier->chars, off->funcName, off->sourceFile, off->rbpOffset);
                fprintf(output, "_LOCALSZ$%s@%s@%s equ %d\n", off->identifier->chars, off->funcName, off->sourceFile, off->size);
                fprintf(output, "_LOCALPROPS$%s@%s@%s equ %d\n", off->identifier->chars, off->funcName, off->sourceFile, off->flags);
                if ((off->flags & PRIMITIVE_TYPE) == 0) {
                    fprintf(output, "_LOCALTYPE$%s@%s@%s$%s equ 0\n", off->identifier->chars, off->funcName, off->sourceFile, off->typeIdentifier);
                }
            }
        }
    }

    fputs("\nsection .text\n", output);
    for (ANTLR3_UINT32 i = 0; i < asmRes.asms->count; i++) {
        fputs("\n", output);
        asm_t* a = CALL(asmRes.asms, get, i);
        for (ANTLR3_UINT32 j = 0; j < a->instructions->count; j++) {
            asm_line_t* line = CALL(a->instructions, get, j);
            if (line->isLabel) {
                fprintf(output, "%s:\n", line->cmd);
                continue;
            }
            fprintf(
                    output,
                    "\t%-8s%s%s%s\n",
                    line->cmd,
                    line->dest ? line->dest : (pANTLR3_UINT8)"",
                    line->src ? ", " : "",
                    line->src ? line->src : (pANTLR3_UINT8)""
                   );
        }
    }
    fclose(output);
    freeAst(ast);
    CALL(info.cfgs, free);
    CALL(asmRes.asms, free);
    CALL(asmRes.externs, free);
}
