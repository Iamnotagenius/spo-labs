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
    pANTLR3_STRING identifier;
    pANTLR3_UINT8 sourceFile;
    pANTLR3_UINT8 funcName;
    bool isSigned;
    bool isArray;
    ANTLR3_UINT32 size;
    ANTLR3_INT64 rbpOffset;
} arg_offset_t;

typedef struct {
    pANTLR3_VECTOR instructions;
    pANTLR3_STRING_FACTORY strFactory;
    pANTLR3_VECTOR strings;
    pANTLR3_VECTOR localAndArgOffsetMap;
} asm_t;

typedef struct {
    pANTLR3_STRING identifier;
    pANTLR3_UINT8 type;
} arg_t;

typedef struct {
    pANTLR3_UINT8 identifier;
    pANTLR3_VECTOR args;
} func_t;

typedef struct {
    pANTLR3_STRING string;
    pANTLR3_STRING addr;
} string_t;

asm_t* compileToAssembly(cfg_t* cfg, bool generateDebugSymbols);
void freeAsm(asm_t* a);
#endif
