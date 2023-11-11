#ifndef HEADER_LIB3_H
#define HEADER_LIB3_H
#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include <stddef.h>
#include "../lab2/lib2.h"

typedef enum {
    ARRAY_TYPE = 1<<0,
    SIGNED_TYPE = 1<<1,
    PRIMITIVE_TYPE = 1<<2,
    POINTER = 1<<3
} type_flags;

typedef struct {
    const unsigned char* cmd;
    const unsigned char* dest;
    const unsigned char* src;
    bool isLabel;
} asm_line_t;

typedef struct {
    pANTLR3_STRING identifier;
    ANTLR3_UINT64 size;
    ANTLR3_UINT64 offset;
} member_t;

typedef struct {
    pANTLR3_STRING identifier;
    ANTLR3_UINT64 totalSize;
    member_t* members;
    size_t memberCount;
} struct_t;

typedef struct {
    struct_t* structs;
    size_t count;
} structs_t;

typedef struct {
    pANTLR3_STRING identifier;
    pANTLR3_UINT8 sourceFile;
    pANTLR3_UINT8 funcName;
    pANTLR3_UINT8 typeIdentifier;
    type_flags flags;
    ANTLR3_UINT32 size;
    ANTLR3_INT64 rbpOffset;
} arg_offset_t;

typedef struct {
    pANTLR3_UINT8 funcName;
    pANTLR3_VECTOR instructions;
    pANTLR3_STRING_FACTORY strFactory;
    pANTLR3_VECTOR strings;
    pANTLR3_VECTOR localAndArgOffsetMap;
} asm_t;

typedef struct {
    pANTLR3_VECTOR asms;
    pANTLR3_VECTOR externs;
    structs_t structs;
} asm_res_t;

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

asm_res_t assemble(source_info_t cfgs, bool generateDebugSymbols);
asm_t* compileToAssembly(cfg_t* cfg, structs_t structs, bool generateDebugSymbols, pANTLR3_VECTOR externFuncs);
pANTLR3_VECTOR collectExternFuncs(pANTLR3_VECTOR cfgs);
void freeAsm(asm_t* a);
void freeStruct(struct_t* s);
#endif
