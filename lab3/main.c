#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib3.h"
#include "../lab2/lib2.h"
#include "../lab1/lib1.h"

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
            pANTLR3_STRING err = ast->errors->get(ast->errors, i);
            fprintf(stderr, "%s\n", err->chars);
        }
        return 1;
    }
    pANTLR3_VECTOR cfgs = createCfgs(ast, (pANTLR3_UINT8)argv[1 + generateDebugSymbols]);
    pANTLR3_VECTOR asms = antlr3VectorNew(cfgs->count);
    for (ANTLR3_UINT32 i = 0; i < cfgs->count; i++) {
        cfg_t* cfg = cfgs->get(cfgs, i);
        if (cfg->errors->count > 0) {
            fprintf(stderr, "There were %d errors:\n", cfg->errors->count);
            for (ANTLR3_UINT32 i = 0; i < cfg->errors->count; i++) {
                pANTLR3_STRING err = cfg->errors->get(cfg->errors, i);
                fprintf(stderr, "%s\n", err->chars);
            }
        }
        asm_t *a = compileToAssembly(cfg, generateDebugSymbols);
        asms->add(asms, a, (void (*))freeAsm);

    }
    FILE* output = fopen(argv[argc - 1], "w+");
    fputs("default rel\n\n", output);
    for (ANTLR3_UINT32 i = 0; i < cfgs->count; i++) {
        cfg_t* cfg = cfgs->get(cfgs, i);
        fprintf(output, "global %s:function\n", cfg->name);
    }

    fputs("\nsection .data\n", output);
    for (ANTLR3_UINT32 i = 0; i < asms->count; i++){
        asm_t* a = asms->get(asms, i);
        for (ANTLR3_UINT32 i = 0; i < a->strings->count; i++) {
            string_t* str = a->strings->get(a->strings, i);
            pANTLR3_STRING addr = str->addr->subString(str->addr, 1, str->addr->len - 1);
            fprintf(output, "%s\tdb\t%s\n", addr->chars, str->string->chars);
        }
        if (generateDebugSymbols) {
            for (ANTLR3_UINT32 i = 0; i < a->localAndArgOffsetMap->count; i++) {
                arg_offset_t* off = a->localAndArgOffsetMap->get(a->localAndArgOffsetMap, i);
                fprintf(output, "_LOCALOFF$%s@%s@%s equ %ld\n", off->identifier->chars, off->funcName, off->sourceFile, off->rbpOffset);
                fprintf(output, "_LOCALSZ$%s@%s@%s equ %d\n", off->identifier->chars, off->funcName, off->sourceFile, off->size);
                fprintf(output, "_LOCALPROPS$%s@%s@%s equ %d\n", off->identifier->chars, off->funcName, off->sourceFile, off->isArray | (off->isSigned << 1));
            }
        }
    }

    fputs("\nsection .text\n", output);
    for (ANTLR3_UINT32 i = 0; i < asms->count; i++) {
        fputs("\n", output);
        asm_t* a = asms->get(asms, i);
        for (ANTLR3_UINT32 j = 0; j < a->instructions->count; j++) {
            asm_line_t* line = a->instructions->get(a->instructions, j);
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
    cfgs->free(cfgs);
    asms->free(asms);
}
