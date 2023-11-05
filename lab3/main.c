#include <antlr3defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib3.h"
#include "../lab2/lib2.h"
#include "../lab1/lib1.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s INPUT1 [INPUT2...]\n", argv[0]);
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        ast_t* ast = parseFile((pANTLR3_UINT8)argv[i]);
        if (ast->errors->count > 0) {
            fprintf(stderr, "There were %d errors while parsing a file\n", ast->errors->count);
            for (ANTLR3_UINT32 i = 0; i < ast->errors->count; i++) {
                pANTLR3_STRING err = ast->errors->get(ast->errors, i);
                fprintf(stderr, "%s\n", err->chars);
            }
            return 1;
        }
        pANTLR3_VECTOR cfgs = createCfgs(ast, (pANTLR3_UINT8)argv[i]);
        for (ANTLR3_UINT32 i = 0; i < cfgs->count; i++) {
            cfg_t* cfg = cfgs->get(cfgs, i);
            printf("Cfg for %s from %s\n", cfg->name, cfg->sourceFile);
            if (cfg->errors->count > 0) {
                fprintf(stderr, "There were %d errors:\n", cfg->errors->count);
                for (ANTLR3_UINT32 i = 0; i < cfg->errors->count; i++) {
                    pANTLR3_STRING err = cfg->errors->get(cfg->errors, i);
                    fprintf(stderr, "%s\n", err->chars);
                }
            }
            asm_t a = compileToAssembly(cfg);
            for (ANTLR3_UINT32 j = 0; j < a.instructions->count; j++) {
                asm_line_t* line = a.instructions->get(a.instructions, j);
                if (line->isLabel) {
                    printf("%s:\n", line->cmd);
                    continue;
                }
                printf("%-8c%-12s%-12s%s\n", ' ', line->cmd, line->dest ? line->dest : (pANTLR3_UINT8)"", line->src ? line->src : (pANTLR3_UINT8)"");
            }
        }
        freeAst(ast);
        cfgs->free(cfgs);
    }
}
