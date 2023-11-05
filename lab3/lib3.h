#ifndef HEADER
#define HEADER
#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include "../lab2/lib2.h"
typedef struct {
    const unsigned char* cmd;
    const unsigned char* dest;
    const unsigned char* src;
    bool isLabel;
} asm_line_t;

typedef struct {
    pANTLR3_VECTOR instructions;
    pANTLR3_STRING_FACTORY strFactory;
    pANTLR3_VECTOR strings;
} asm_t;

typedef struct {
    pANTLR3_STRING identifier;
    pANTLR3_UINT8 type;
} arg_t;

typedef struct {
    pANTLR3_UINT8 identifier;
    pANTLR3_VECTOR args;
} func_t;

asm_t compileToAssembly(cfg_t* cfg);
#endif
