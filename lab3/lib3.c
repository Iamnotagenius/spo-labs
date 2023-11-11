#include <antlr3interfaces.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <antlr3defs.h>
#include "../lab2/lib2.h"
#include "lib3.h"
#include "../macros.h"

#define DEFAULT_TYPE (pANTLR3_UINT8)"long"
#define CALL_STACK_ALIGNMENT 16
#define STACK_ALIGN(bytes) (usedStack / CALL_STACK_ALIGNMENT + \
        (usedStack % CALL_STACK_ALIGNMENT != 0)) * CALL_STACK_ALIGNMENT

typedef struct {
    pANTLR3_STRING id;
    pANTLR3_STRING addr;
    ANTLR3_UINT32 size;
    type_flags flags;
    struct_t *type;
} var_t;

typedef struct {
    cfg_node_t* node;
    pANTLR3_STRING label;
} label_t;

typedef struct {
    pANTLR3_VECTOR addrMap;
    pANTLR3_VECTOR instructions;
    pANTLR3_VECTOR strings;
    pANTLR3_VECTOR externFuncs;
    structs_t structs;
    pANTLR3_STRING_FACTORY strFactory;
    ANTLR3_UINT32 usedStack;
    pANTLR3_VECTOR labels;
    pANTLR3_UINT8 sourceFile;
    pANTLR3_UINT8 funcName;
    bool generateDebugSymbols;
} asm_info_t;

typedef enum {
    NO, E, NE, G, GE, L, LE
} comp_res;

typedef enum {
    RAX, RCX, RDX, RDI, RSI, R8, R9, R10, R11, /* caller saved */
    RBX, R12, R13, R14, R15 /* callee saved */
} REG;

void addInstruction(pANTLR3_VECTOR as, const char* cmd, const unsigned char* dest, const unsigned char* src);
void addLabel(pANTLR3_VECTOR as, pANTLR3_UINT8 cmd);
void linkLabel(pANTLR3_VECTOR labels, cfg_node_t* node, pANTLR3_STRING label);
pANTLR3_UINT8 getAddrS(pANTLR3_VECTOR map, pANTLR3_STRING id);
ANTLR3_UINT32 moveArgsToStack(pANTLR3_VECTOR addrMap, pANTLR3_VECTOR offsetMap, asm_info_t* info, pANTLR3_BASE_TREE signature);
ANTLR3_UINT32 getSize(pANTLR3_STRING intType, structs_t structs);
void compileStatement(cfg_node_t* node, asm_info_t* info);
comp_res computeExpression(pANTLR3_BASE_TREE expr, ANTLR3_UINT32 usedRegisters, asm_info_t* info);
bool isSigned(pANTLR3_STRING intType);
void initializeStruct(var_t* var, pANTLR3_BASE_TREE initializer, asm_info_t* info);
var_t* createVarFromTree(pANTLR3_VECTOR map, pANTLR3_STRING id, pANTLR3_STRING addr, pANTLR3_BASE_TREE type, structs_t structs);
var_t* createVar(pANTLR3_VECTOR map, pANTLR3_STRING id, pANTLR3_STRING addr, type_t* type, structs_t structs);
var_t* getVar(pANTLR3_VECTOR map, pANTLR3_UINT8 id);
var_t* getVarS(pANTLR3_VECTOR map, pANTLR3_STRING id);
void labelLoopTail(cfg_node_t* node, asm_info_t* info);
pANTLR3_STRING createNumericString(pANTLR3_STRING_FACTORY strFactory, ANTLR3_INT32 n);
pANTLR3_STRING createSizedPtr(pANTLR3_STRING_FACTORY strFactory, pANTLR3_STRING addr, ANTLR3_UINT32 size);
void setCompRes(comp_res res, REG reg, asm_info_t* info);
comp_res invertCompRes(comp_res comp);
void addLineNumberLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber);
void addLineNumberEndLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber);
const char* getSet(comp_res comp);
const char* getJump(comp_res comp);

static REG argumentRegisters[] = {RDI, RSI, RDX, RCX, R8, R9};

const unsigned char* getGPRegisterInOrder(REG reg, ANTLR3_UINT32 size) {
    static const char* registers[][4] = {
        [RAX] = {"rax", "eax",  "ax",   "al"},
        [RBX] = {"rbx", "ebx",  "bx",   "bl"},
        [RCX] = {"rcx", "ecx",  "cx",   "cl"},
        [RDX] = {"rdx", "edx",  "dx",   "dl"},
        [RDI] = {"rdi", "edi",  "di",   "dil"},
        [RSI] = {"rsi", "esi",  "si",   "sil"},
        [R8]  = {"r8",  "r8d",  "r8w",  "r8b"},
        [R9]  = {"r9",  "r9d",  "r9w",  "r9b"},
        [R10] = {"r10", "r10d", "r10w", "r10b"},
        [R11] = {"r11", "r11d", "r11w", "r11b"},
        [R12] = {"r12", "r12d", "r12w", "r12b"},
        [R13] = {"r13", "r13d", "r13w", "r13b"},
        [R14] = {"r14", "r14d", "r14w", "r14b"},
        [R15] = {"r15", "r15d", "r15w", "r15b"},
    };
    ANTLR3_UINT32 regSizeIdx;
    switch (size) {
        case sizeof(long): regSizeIdx = 0; break;
        case sizeof(int): regSizeIdx = 1; break;
        case sizeof(short): regSizeIdx = 2; break;
        case sizeof(char): regSizeIdx = 3; break;
    }
    return (const unsigned char*)registers[reg][regSizeIdx];
}

var_t* createVarFromTree(pANTLR3_VECTOR addrMap, pANTLR3_STRING id, pANTLR3_STRING addr, pANTLR3_BASE_TREE type, structs_t structs) {
    var_t* entry = malloc(sizeof(var_t));
    entry->id = id;
    entry->addr = addr;
    entry->type = NULL;
    if (type != NULL) {
        entry->size = getSize(CALL(type, getText), structs);
        entry->flags = 0;
        SET_FLAG(
            entry->flags,
            ARRAY_TYPE,
            CALL(type, getFirstChildWithType, Array) != NULL || CHAIN2(type, getText, compare, "string") == 0
        );
        SET_FLAG(
            entry->flags,
            SIGNED_TYPE,
            isSigned(CALL(type, getText))
        );
        SET_FLAG(entry->flags, PRIMITIVE_TYPE, CALL(type, getType) == BuiltinType);
        if (CALL(type, getType) != BuiltinType) {
            entry->flags |= POINTER; /* pass structs by reference */
            for (int i = 0; i < structs.count; i++) {
                if (CHAIN2(type, getText, compareS, structs.structs[i].identifier) == 0) {
                    entry->type = &structs.structs[i];
                    break;
                }
            }
            if (entry->type == NULL) {
                fprintf(stderr, "Error: type '%s' is not defined.\n", CALL(type, getText)->chars);
            }
        }
    }
    else {
        entry->size = sizeof(long);
        entry->flags = SIGNED_TYPE | PRIMITIVE_TYPE;
    }

    CALL(addrMap, add, entry, free);
    return entry;
}

var_t* createVar(pANTLR3_VECTOR addrMap, pANTLR3_STRING id, pANTLR3_STRING addr, type_t* type, structs_t structs) {
    var_t* entry = malloc(sizeof(var_t));
    entry->id = id;
    entry->addr = addr;
    entry->type = NULL;
    if (type != NULL) {
        entry->size = getSize(type->identifier, structs);
        entry->flags = 0;
        SET_FLAG(entry->flags, ARRAY_TYPE, type->isArray);
        SET_FLAG(entry->flags, SIGNED_TYPE, isSigned(type->identifier));
        SET_FLAG(entry->flags, PRIMITIVE_TYPE, type->isPrimitive);
        if (!type->isPrimitive) {
            for (int i = 0; i < structs.count; i++) {
                if (CALL(type->identifier, compareS, structs.structs[i].identifier) == 0) {
                    entry->type = &structs.structs[i];
                    break;
                }
            }
            if (entry->type == NULL) {
                fprintf(stderr, "Error: type '%s' is not defined.\n", type->identifier->chars);
            }
        }
    }
    else {
        entry->size = sizeof(long);
        entry->flags = SIGNED_TYPE | PRIMITIVE_TYPE;
    }
    CALL(addrMap, add, entry, free);
    return entry;
}

structs_t parseStructs(pANTLR3_VECTOR structs) {
    struct_t *new = calloc(structs->count, sizeof(struct_t));
    for (int i = 0; i < structs->count; i++) {
        struct_def_t *def = CALL(structs, get, i);
        new[i].identifier = def->identifier;
        new[i].members = calloc(def->members->count, sizeof(member_t));
        new[i].memberCount = def->members->count;
        member_t* members = new[i].members;
        ANTLR3_UINT64 accOffset = 0;
        for (int j = 0; j < def->members->count; j++) {
            member_def_t* member = CALL(def->members, get, j);
            ANTLR3_UINT32 size = getSize(member->type, (structs_t){new, i});
            members[j] = (member_t){member->identifier, size, accOffset};
            accOffset += size;
        }
        new[i].totalSize = accOffset;
    }
    return (structs_t){new, structs->count};
}

ANTLR3_UINT32 moveArgsToStack(pANTLR3_VECTOR addrMap, pANTLR3_VECTOR offsetMap, asm_info_t* info, pANTLR3_BASE_TREE signature) {
    static ANTLR3_UINT32 lenArgRegs = sizeof(argumentRegisters)/sizeof(argumentRegisters[0]);
    pANTLR3_STRING_FACTORY strFactory = signature->strFactory;
    ANTLR3_INT64 usedStack = 0;
    ANTLR3_UINT32 i;
    bool hasReturnType = CALL(signature, getFirstChildWithType, ReturnType) != NULL;

    for (i = hasReturnType; i < signature->children->count && i < lenArgRegs; i++) {
        pANTLR3_BASE_TREE argNode = CALL(signature, getChild, i);
        pANTLR3_BASE_TREE id = CALL(argNode, getChild, 0);
        pANTLR3_BASE_TREE type = CALL(argNode, getChild, 1);
        var_t* var = createVarFromTree(addrMap, CALL(id, getText), NULL, type, info->structs);
        usedStack += var->flags & (ARRAY_TYPE | POINTER) ? sizeof(long) : var->size;
        pANTLR3_STRING addr = CALL(strFactory, newStr, (pANTLR3_UINT8)"[rbp-");
        CALL(addr, addi, usedStack);
        CALL(addr, addc, ']');
        var->addr = addr;
        addInstruction(
            info->instructions,
            "mov",
            addr->chars,
            getGPRegisterInOrder(
                argumentRegisters[i - hasReturnType],
                var->flags & (ARRAY_TYPE | POINTER) ? sizeof(long) : var->size
            )
        );
        arg_offset_t* off = malloc(sizeof(arg_offset_t));
        *off = (arg_offset_t){
            .identifier = CALL(id, getText),
            .rbpOffset = -usedStack,
            .sourceFile = info->sourceFile,
            .funcName = info->funcName,
            .size = var->size,
            .flags = var->flags,
            .typeIdentifier = var->type != NULL ? var->type->identifier->chars : NULL
        };
        CALL(offsetMap, add, off, free);
    }
    for (; i < signature->children->count; i++) {
        pANTLR3_BASE_TREE argNode = CALL(signature, getChild, i);
        pANTLR3_BASE_TREE id = CALL(argNode, getChild, 0);
        pANTLR3_BASE_TREE type = CALL(argNode, getChild, 1);
        var_t* var = createVarFromTree(addrMap, CALL(id, getText), NULL, type, info->structs);
        pANTLR3_STRING addr = CALL(strFactory, newStr, (pANTLR3_UINT8)"[rbp+");
        CALL(addr, addi, (i - lenArgRegs + 2) * sizeof(long));
        CALL(addr, addc, ']');
        var->addr = addr;
        arg_offset_t* off = malloc(sizeof(arg_offset_t));
        *off = (arg_offset_t){
            .identifier = CALL(id, getText),
            .rbpOffset = (i - lenArgRegs + 2) * sizeof(long),
            .sourceFile = info->sourceFile,
            .funcName = info->funcName,
            .size = var->size,
            .flags = var->flags,
            .typeIdentifier = var->type != NULL ? var->type->identifier->chars : NULL
        };
        CALL(offsetMap, add, off, free);
    }
    return usedStack;
}

pANTLR3_VECTOR collectExternFuncs(pANTLR3_VECTOR cfgs) {
    pANTLR3_VECTOR new = antlr3VectorNew(ANTLR3_SIZE_HINT);
    for (int i = 0; i < cfgs->count; i++) {
        cfg_t* cfg = CALL(cfgs, get, i);
        if (cfg->cfgRoot == NULL) {
            CALL(new, add, cfg->name, NULL);
        }
    }
    return new;
}

asm_res_t assemble(source_info_t sourceInfo, bool generateDebugSymbols) {
    pANTLR3_VECTOR externs = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR asms = antlr3VectorNew(ANTLR3_SIZE_HINT);
    structs_t structs = parseStructs(sourceInfo.structs);
    for (int i = 0; i < sourceInfo.cfgs->count; i++) {
        cfg_t* cfg = CALL(sourceInfo.cfgs, get, i);
        if (cfg->cfgRoot == NULL) {
            CALL(externs, add, cfg->name, NULL);
            continue;
        }
        CALL(asms, add, compileToAssembly(cfg, structs, generateDebugSymbols, externs), (void (*))freeAsm);
    }
    return (asm_res_t){asms, externs, structs};
}

asm_t* compileToAssembly(cfg_t* cfg, structs_t structs, bool generateDebugSymbols, pANTLR3_VECTOR externFuncs) {
    pANTLR3_STRING_FACTORY strFactory = antlr3StringFactoryNew(ANTLR3_ENC_UTF8);
    pANTLR3_VECTOR instructions = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR strings = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR labels = antlr3VectorNew(ANTLR3_SIZE_HINT);
    ANTLR3_INT64 usedStack = 0;
    pANTLR3_VECTOR addrMap = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR offsetMap = antlr3VectorNew(ANTLR3_SIZE_HINT);
    asm_info_t info = {
        addrMap,
        instructions,
        strings,
        externFuncs,
        structs,
        strFactory,
        usedStack,
        labels,
        cfg->sourceFile,
        cfg->name,
        generateDebugSymbols
    };
    addLabel(instructions, cfg->name);
    addInstruction(instructions, "push", (pANTLR3_UINT8)"rbp", NULL);
    addInstruction(instructions, "mov", (pANTLR3_UINT8)"rbp", (pANTLR3_UINT8)"rsp");

    if (cfg->signature != NULL) {
        usedStack = moveArgsToStack(addrMap, offsetMap, &info, cfg->signature);
    }
    for (ANTLR3_UINT32 i = 0; i < cfg->vars->count; i++) {
        vars_t* vars = CALL(cfg->vars, get, i);
        ANTLR3_UINT32 size = getSize(vars->type.identifier, structs);
        for (ANTLR3_UINT32 i = 0; i < vars->identifiers->count; i++) {
            pANTLR3_STRING id = CALL(vars->identifiers, get, i);
            pANTLR3_STRING addr = CALL(strFactory, newStr, (pANTLR3_UINT8)"[rbp-");
            usedStack += vars->type.isArray ? sizeof(long) : size;
            CALL(addr, addi, usedStack);
            CALL(addr, addc, ']');
            var_t* var = createVar(addrMap, id, addr, &vars->type, structs);
            arg_offset_t* off = malloc(sizeof(arg_offset_t));
            *off = (arg_offset_t){
                .identifier = id,
                .rbpOffset = -usedStack,
                .sourceFile = cfg->sourceFile,
                .funcName = cfg->name,
                .size = var->size,
                .flags = var->flags,
                .typeIdentifier = var->type != NULL ? var->type->identifier->chars : NULL
            };
            CALL(offsetMap, add, off, free);
        }
    }
    ANTLR3_UINT32 toSub = STACK_ALIGN(usedStack);
    pANTLR3_STRING bytes = createNumericString(strFactory, toSub);
    addInstruction(instructions, "sub", (pANTLR3_UINT8)"rsp", bytes->chars);
#ifdef DEBUG
    fprintf(stderr, "AddrMap:\n");
    for (ANTLR3_UINT32 i = 0; i < addrMap->count; i++) {
        var_t* entry = CALL(addrMap, get, i);
        fprintf(stderr, "%s -> %s\n", entry->id->chars, entry->addr->chars);
    }
#endif
    walkCfg(cfg->cfgRoot, (void (*))compileStatement, &info, (void (*))labelLoopTail);

    for (ANTLR3_UINT32 i = 0; i < labels->count; i++) {
        label_t* label = CALL(labels, get, i);
        if (label->node == NULL) {
            addLabel(instructions, label->label->chars);
        }
    }

    addInstruction(instructions, "add", (pANTLR3_UINT8)"rsp", bytes->chars);
    addInstruction(instructions, "pop", (pANTLR3_UINT8)"rbp", NULL);
    addInstruction(instructions, "ret", NULL, NULL);
    asm_t* a = malloc(sizeof(asm_t));
    *a = (asm_t){
        cfg->name,
        instructions,
        strFactory,
        strings,
        offsetMap,
    };
    CALL(addrMap, free);
    CALL(labels, free);
    return a;
}

void handleCall(pANTLR3_BASE_TREE call, ANTLR3_UINT32 usedRegisters, asm_info_t* info) {
    pANTLR3_BASE_TREE lParen = CALL(call, getChild, 0);
    if (usedRegisters > 0) {
        for (ANTLR3_UINT32 i = 0; i < usedRegisters; i++) {
            addInstruction(info->instructions, "push", getGPRegisterInOrder(i, sizeof(long)), NULL);
        }
        if (usedRegisters % 2 == 1) {
            addInstruction(info->instructions, "sub", (pANTLR3_UINT8)"rsp", createNumericString(info->strFactory, sizeof(long))->chars);
        }
    }
    ANTLR3_UINT32 argCount = CALL(lParen, getChildCount);
    ANTLR3_UINT32 i;
    for (i = 0; i < argCount && i <= (R15 - RBX); i++) {
        setCompRes(computeExpression(CALL(lParen, getChild, i), RAX, info), RAX, info);
        addInstruction(info->instructions, "push", getGPRegisterInOrder(i + RBX, sizeof(long)), NULL);
        addInstruction(info->instructions, "mov", getGPRegisterInOrder(i + RBX, sizeof(long)), getGPRegisterInOrder(RAX, sizeof(long)));
    }
    for (; i < argCount; i++) {
        setCompRes(computeExpression(CALL(lParen, getChild, argCount - i + (R15 - RBX)), RAX, info), RAX, info);
        addInstruction(info->instructions, "push", getGPRegisterInOrder(RAX, sizeof(long)), NULL);
    }
    ANTLR3_UINT32 usedCalleeSavedRegisters = argCount > R15 - RBX + 1 ? R15 - RBX + 1 : argCount;

    for (i = 0; i < usedCalleeSavedRegisters; i++) {
        addInstruction(
                info->instructions,
                "mov",
                getGPRegisterInOrder(argumentRegisters[i], sizeof(long)),
                getGPRegisterInOrder(i + RBX, sizeof(long))
              );
    }
    if (argCount > R15 - RBX + 1) {
        addInstruction(info->instructions, "pop", getGPRegisterInOrder(R9, sizeof(long)), NULL);
    }

    bool isExtern = false;
    for (int i = 0; i < info->externFuncs->count; i++) {
        if (CHAIN2(call, getText, compare, CALL2(info->externFuncs, get, i)) == 0) {
            isExtern = true;
            break;
        }
    }
    pANTLR3_STRING operand = CALL(call, getText);
    if (isExtern) {
        operand = CALL(info->strFactory, newStr, operand->chars);
        CALL(operand, append, " WRT ..plt");
        addInstruction(info->instructions, "mov", (pANTLR3_UINT8)"rax", (pANTLR3_UINT8)"0");
    }

    addInstruction(info->instructions, "call", operand->chars, NULL);
    if (argCount > R15 - RBX + 2) {
        pANTLR3_STRING bytes = CALL(info->strFactory, newRaw);
        CALL(bytes, addi, (argCount - (R15 - RBX + 2)) * sizeof(long));
        addInstruction(info->instructions, "add", (pANTLR3_UINT8)"rsp", bytes->chars);
    }
    for (i = 0; i < usedCalleeSavedRegisters; i++) {
        addInstruction(info->instructions, "pop", getGPRegisterInOrder(usedCalleeSavedRegisters - i - 1 + RBX, sizeof(long)), NULL);
    }
    if (usedRegisters > 0) {
        addInstruction(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(RAX, sizeof(long)));

        if (usedRegisters % 2 == 1) {
            addInstruction(info->instructions, "add", (pANTLR3_UINT8)"rsp", createNumericString(info->strFactory, sizeof(long))->chars);
        }

        for (ANTLR3_INT32 i = usedRegisters - 1; i >= 0; i--) {
            addInstruction(info->instructions, "pop", getGPRegisterInOrder(i, sizeof(long)), NULL);
        }
    }
}

void initializeStruct(var_t* var, pANTLR3_BASE_TREE initializer, asm_info_t* info) {
    if (CALL(initializer, getFirstChildWithType, LParen) == NULL) {
        fprintf(stderr, "Error: initializer must have the form %s(", var->type->identifier->chars);
        for (int i = 0; i < var->type->memberCount - 1; i++) {
            fprintf(stderr, "%s, ", var->type->members[i].identifier->chars);
        }
        fprintf(stderr, "%s)", var->type->members[var->type->memberCount - 1].identifier->chars);
        return;
    }
    if (CHAIN2(initializer, getText, compareS, var->type->identifier) != 0) {
        fprintf(stderr, "Error: initializer's name must be identical to one of assignee's.\n");
        return;
    }
    pANTLR3_VECTOR initExpressions = CAST_CALL(pANTLR3_BASE_TREE, initializer, getFirstChildWithType, LParen)->children;
    if (initExpressions->count == 0) {
        fprintf(stderr, "Error: initializer has not been provided with arguments\n");
        return;
    }
    if (initExpressions->count != var->type->memberCount) {
        fprintf(stderr, "Error: amount of arguments did not match. %zu expected, %d got.\n", var->type->memberCount, initExpressions->count);
        return;
    }

    const char *addrPrefix = "[rbp";
    int offset = 0;
    if (var->flags & POINTER) {
        addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", var->addr->chars);
        addrPrefix = "[rbx";
    }
    else {
        sscanf((const char *)var->addr->chars, "[rbp%d]", &offset);
    }
    for (int i = 0; i < initExpressions->count; i++) {
        pANTLR3_BASE_TREE expr = CALL(initExpressions, get, i);
        member_t* member = &var->type->members[i];
        pANTLR3_STRING addr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)addrPrefix);
        if (offset + member->offset > 0) {
            CALL(addr, addc, '+');
        }
        if (offset + member->offset != 0) {
            CALL(addr, addi, offset + member->offset);
        }
        CALL(addr, addc, ']');
        setCompRes(computeExpression(expr, RAX, info), RAX, info);
        addInstruction(
            info->instructions,
            "mov",
            createSizedPtr(info->strFactory, addr, member->size)->chars,
            getGPRegisterInOrder(RAX, member->size)
        );
    }
    if (var->flags & POINTER) {
        addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", var->addr->chars);
    }
}

comp_res computeExpression(pANTLR3_BASE_TREE expr, ANTLR3_UINT32 usedRegisters, asm_info_t* info) {
    if (usedRegisters > R11) {
        fprintf(stderr, "Error: temp var count exceeded.\n");
        return NO;
    }
    switch (CALL(expr, getType)) {
        case CharLiteral:
        case HexLiteral:
        case BitsLiteral:
        case Integer:
            {
                addInstruction(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), CALL(expr, getText)->chars);
                return NO;
            }
        case Bool:
            {
                addInstruction(
                        info->instructions,
                        "mov",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        (pANTLR3_UINT8)(CHAIN2(expr, getText, compare, "true") ? "1" : "0")
                      );
                return NO;
            }
        case String:
            {
                string_t* s = NULL;
                for (ANTLR3_INT32 i = 0; i < info->strings->count; i++) {
                    string_t* str = CALL(info->strings, get, i);
                    if (CALL(str->string, compareS, CALL2(expr, getText)) == 0) {
                        s = str;
                        break;
                    }
                }

                if (s == NULL) {
                    pANTLR3_STRING addr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[S");
                    CALL(addr, addi, info->strings->count);
                    CALL(addr, addc, ']');
                    s = malloc(sizeof(string_t));
                    s->string = CALL(expr, getText);
                    s->addr = addr;
                    CALL(info->strings, add, s, free);
                }

                addInstruction(info->instructions, "lea", getGPRegisterInOrder(usedRegisters, sizeof(long)), s->addr->chars);
                return NO;
            }
        case Identifier:
            {
                var_t* entry = getVarS(info->addrMap, CALL(expr, getText));
                if (entry == NULL) {
                    if (CALL(expr, getChildCount) == 1) {
                        handleCall(expr, usedRegisters, info);
                    }
                    return NO;
                }
                pANTLR3_STRING addr = entry->addr;
                ANTLR3_UINT32 size = entry->size;
                if (entry->flags & ARRAY_TYPE) {
                    pANTLR3_BASE_TREE arrayAccess = CALL(expr, getFirstChildWithType, LParen);
                    if (arrayAccess == NULL) {
                        addInstruction(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), entry->addr->chars);
                        return NO;
                    }
                    if (CALL(arrayAccess, getChildCount) > 1) {
                        fputs("Error: only one-dimensional arrays are supported", stderr);
                        return NO;
                    }
                    if (CALL(arrayAccess, getChildCount) == 0) {
                        fputs("Error: index for an array is not specified", stderr);
                        return NO;
                    }
                    comp_res res = computeExpression(CALL(arrayAccess, getChild, 0), usedRegisters, info);
                    if (res != NO) {
                        setCompRes(res, usedRegisters, info);
                        addInstruction(info->instructions, "movzx", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(usedRegisters, sizeof(char)));
                    }
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                    pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbx+");
                    CALL(accessAddr, append, (const char *)getGPRegisterInOrder(usedRegisters, sizeof(long)));
                    if (entry->size > 1) {
                        CALL(accessAddr, addc, '*');
                        CALL(accessAddr, addi, entry->size);
                    }
                    CALL(accessAddr, addc, ']');
                    addr = accessAddr;
                }
                else if ((entry->flags & PRIMITIVE_TYPE) == 0) {
                    if (CALL(expr, getFirstChildWithType, Identifier) == NULL) {
                        addInstruction(
                            info->instructions,
                            entry->flags & POINTER ? "mov" : "lea",
                            getGPRegisterInOrder(usedRegisters, sizeof(long)),
                            entry->addr->chars
                        );
                        return NO;
                    }
                    pANTLR3_STRING memberId = CALL(CAST_CALL(pANTLR3_BASE_TREE, expr, getFirstChildWithType, Identifier), getText);
                    member_t* member = NULL;
                    for (int i = 0; i < entry->type->memberCount; i++) {
                        if (CALL(entry->type->members[i].identifier, compareS, memberId) == 0) {
                            member = &entry->type->members[i];
                            break;
                        }
                    }
                    if (member == NULL) {
                        fprintf(stderr, "Error: type '%s' has no member '%s'.\n", entry->type->identifier->chars, memberId->chars);
                        return NO;
                    }
                    if (entry->flags & POINTER) {
                        addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                        pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbx+");
                        CALL(accessAddr, addi, member->offset);
                        CALL(accessAddr, addc, ']');
                        addr = accessAddr;
                    }
                    else {
                        int memberAddr;
                        sscanf((const char *)entry->addr->chars, "[rbp%d]", &memberAddr);
                        memberAddr += member->offset;
                        pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbp");
                        if (memberAddr > 0) {
                            CALL(accessAddr, addc, '+');
                        }
                        CALL(accessAddr, addi, memberAddr);
                        CALL(accessAddr, addc, ']');
                        addr = accessAddr;
                    }
                    size = member->size;
                }
                if (size == sizeof(long)) {
                    addInstruction(
                        info->instructions,
                        "mov",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        addr->chars
                    );
                } else if (size == sizeof(int)) {
                    addInstruction(
                            info->instructions,
                            entry->flags & SIGNED_TYPE ? "movsx" : "mov",
                            getGPRegisterInOrder(usedRegisters, entry->flags & SIGNED_TYPE ? sizeof(long) : sizeof(int)),
                            createSizedPtr(info->strFactory, addr, size)->chars
                          );
                } else {
                    addInstruction(
                            info->instructions,
                            entry->flags & SIGNED_TYPE ? "movsx" : "movzx",
                            getGPRegisterInOrder(usedRegisters, sizeof(long)),
                            createSizedPtr(info->strFactory, addr, size)->chars
                          );
                }
                if (entry->flags & (ARRAY_TYPE | POINTER)) {
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                }
                return NO;
            }
        case Plus:
        case Minus:
            {
                setCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info), usedRegisters, info);
                if (CALL(expr, getChildCount) == 1) {
                    addInstruction(info->instructions, "neg", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                    return NO;
                }
                setCompRes(computeExpression(CALL(expr, getChild, 1), usedRegisters + 1, info), usedRegisters, info);
                addInstruction(
                        info->instructions,
                        CALL(expr, getType) == Plus ? "add" : "sub",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                      );
                return NO;
            }
        case MultOp:
            {
                setCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(CALL(expr, getChild, 1), usedRegisters + 1, info), usedRegisters, info);
                if (CALL(expr, getText)->chars[0] == '*') {
                    addInstruction(
                            info->instructions,
                            "imul",
                            getGPRegisterInOrder(usedRegisters, sizeof(long)),
                            getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                          );
                    return NO;
                }
                usedRegisters += 2;
                addInstruction(info->instructions, "push", getGPRegisterInOrder(RAX, sizeof(long)), NULL);
                if (usedRegisters > RDX) {
                    addInstruction(info->instructions, "push", getGPRegisterInOrder(RDX, sizeof(long)), NULL);
                }
                addInstruction(
                        info->instructions,
                        "mov",
                        getGPRegisterInOrder(RAX, sizeof(long)),
                        getGPRegisterInOrder(usedRegisters, sizeof(long))
                      );
                addInstruction(info->instructions, "mov", getGPRegisterInOrder(RDX, sizeof(long)), (pANTLR3_UINT8)"0");
                addInstruction(info->instructions, "idiv", getGPRegisterInOrder(usedRegisters + 1, sizeof(long)), NULL);
                if (usedRegisters - 2 != (CALL(expr, getText)->chars[0] == '/' ? RAX : RDX)) {
                    addInstruction(
                            info->instructions,
                            "mov",
                            getGPRegisterInOrder(usedRegisters - 2, sizeof(long)),
                            getGPRegisterInOrder(CALL(expr, getText)->chars[0] == '/' ? RAX : RDX, sizeof(long))
                          );
                }
                if (usedRegisters > RDX) {
                    addInstruction(info->instructions, "pop", getGPRegisterInOrder(RDX, sizeof(long)), NULL);
                }
                addInstruction(info->instructions, "pop", getGPRegisterInOrder(RAX, sizeof(long)), NULL);
                usedRegisters -= 2;
                return NO;
            }
        case Tilde:
            {
                setCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info), usedRegisters, info);
                addInstruction(info->instructions, "not", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                return NO;
            }
        case BitOp:
            {
                setCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(CALL(expr, getChild, 1), usedRegisters + 1, info), usedRegisters, info);
                const char* op;
                switch (CALL(expr, getText)->chars[0]) {
                    case '^': op = "xor"; break;
                    case '|': op = "or"; break;
                    case '&': op = "and"; break;
                }
                addInstruction(
                        info->instructions,
                        op,
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                      );
                return NO;
            }
        case CompOp:
            {
                setCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(CALL(expr, getChild, 1), usedRegisters + 1, info), usedRegisters, info);
                addInstruction(info->instructions, "cmp", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(usedRegisters + 1, sizeof(long)));
                pANTLR3_STRING op = CALL(expr, getText);
                if (CALL(op, compare, ">") == 0) {
                    return G;
                }
                if (CALL(op, compare, "<") == 0) {
                    return L;
                }
                if (CALL(op, compare, ">=") == 0) {
                    return GE;
                }
                if (CALL(op, compare, "<=") == 0) {
                    return LE;
                }
                if (CALL(op, compare, "==") == 0) {
                    return E;
                }
                if (CALL(op, compare, "!=") == 0) {
                    return NE;
                }
            }
        case Not:
            {
                return invertCompRes(computeExpression(CALL(expr, getChild, 0), usedRegisters, info));
            }
        case And:
        case Or:
            {
                addInstruction(
                        info->instructions,
                        getSet(computeExpression(CALL(expr, getChild, 0), usedRegisters, info)),
                        getGPRegisterInOrder(usedRegisters, sizeof(char)),
                        NULL
                      );
                addInstruction(
                        info->instructions,
                        getSet(computeExpression(CALL(expr, getChild, 0), usedRegisters + 1, info)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(char)),
                        NULL
                      );
                addInstruction(
                        info->instructions,
                        CALL(expr, getType) == And ? "and" : "or",
                        getGPRegisterInOrder(usedRegisters, sizeof(char)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(char))
                      );
                addInstruction(info->instructions, "cmp", getGPRegisterInOrder(usedRegisters, sizeof(char)), (pANTLR3_UINT8)"0");
                return NE;
            }
    }
    return NO;
}

void compileStatement(cfg_node_t* node, asm_info_t* info) {
    for (ANTLR3_UINT32 i = 0; i < info->labels->count; i++) {
        label_t* label = CALL(info->labels, get, i);
        if (label->node == node) {
            addLabel(info->instructions, label->label->chars);
        }
    }
    switch (node->type) {
        case EXPR:
            {
                expr_t e = node->u.expr;
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, CALL(e.tree, getLine));
                }
                setCompRes(computeExpression(e.tree, RAX, info), RAX, info);
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, CALL(e.tree, getLine));
                }
                break;
            }
        case DIM:
            break;
        case IF:
            {
                if_t i = node->u.cond;
                step_t step = getCfgStep(node);
                if (!step.conditional) {
                    break;
                }
                pANTLR3_STRING label = CALL(info->strFactory, newStr, (pANTLR3_UINT8)".L");
                CALL(label, addi, info->labels->count);
                linkLabel(info->labels, getNextNode(node), label);
                if (i.elseNode != NULL) {
                    label = CALL(info->strFactory, newStr, (pANTLR3_UINT8)".L");
                    CALL(label, addi, info->labels->count);
                    linkLabel(info->labels, i.elseNode, label);
                }
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, i.condExpr->getLine(i.condExpr));
                }
                addInstruction(info->instructions, getJump(invertCompRes(computeExpression(i.condExpr, RAX, info))), label->chars, NULL);
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, i.condExpr->getLine(i.condExpr));
                }
                break;
            }
        case BREAK:
            {
                break_t b = node->u.breakNode;
                pANTLR3_STRING label = CALL(info->strFactory, newStr, (pANTLR3_UINT8)".L");
                CALL(label, addi, info->labels->count);
                linkLabel(info->labels, b.loopExit, label);
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, b.line);
                }
                addInstruction(info->instructions, "jmp", label->chars, NULL);
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, b.line);
                }
                break;
            }
        case WHILE:
            {
                pANTLR3_STRING label = CALL(info->strFactory, newStr, (pANTLR3_UINT8)".L");
                CALL(label, addi, info->labels->count);
                linkLabel(info->labels, node, label);
                addInstruction(info->instructions, "jmp", label->chars, NULL);
            }
        case DO_UNTIL:
        case DO_WHILE:
            {
                loop_t l = node->u.loop;
                pANTLR3_STRING label = CALL(info->strFactory, newStr, (pANTLR3_UINT8)".L");
                CALL(label, addi, info->labels->count);
                linkLabel(info->labels, l.body, label);
                break;
            }
        case ASSIGNMENT:
            {
                assignment_t a = node->u.assignment;
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, CALL(a.expr, getLine));
                }

                var_t* entry = getVar(info->addrMap, a.identifier);
                if (entry == NULL) {
                    fprintf(stderr, "Error: '%s' is not defined.\n", a.identifier);
                    return;
                }
                if ((entry->flags & ARRAY_TYPE) == 0 && (entry->flags & PRIMITIVE_TYPE) == 0 && a.arrayIndexExpr == NULL) {
                    initializeStruct(entry, a.expr, info);
                    if (info->generateDebugSymbols) {
                        addLineNumberEndLabel(info, CALL(a.expr, getLine));
                    }
                    return;
                }
                setCompRes(computeExpression(a.expr, RAX, info), RAX, info);
                pANTLR3_STRING addr = entry->addr;
                ANTLR3_UINT32 size = entry->size;
                if (a.arrayIndexExpr == NULL && entry->flags & (ARRAY_TYPE | POINTER)) {
                    addInstruction(info->instructions, "mov", entry->addr->chars, getGPRegisterInOrder(RAX, sizeof(long)));
                    return;
                }
                if (entry->flags & ARRAY_TYPE) {
                    comp_res res = computeExpression(CALL(a.arrayIndexExpr, getChild, 0), RCX, info);
                    if (res != NO) {
                        setCompRes(res, RCX, info);
                        addInstruction(info->instructions, "movzx", getGPRegisterInOrder(RCX, sizeof(long)), getGPRegisterInOrder(RCX, sizeof(char)));
                    }
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                    pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbx+");
                    CALL(accessAddr, append, (const char *)getGPRegisterInOrder(RCX, sizeof(long)));
                    if (entry->size > 1) {
                        CALL(accessAddr, addc, '*');
                        CALL(accessAddr, addi, entry->size);
                    }
                    CALL(accessAddr, addc, ']');
                    addr = accessAddr;
                }
                else if ((entry->flags & PRIMITIVE_TYPE) == 0) {
                    pANTLR3_STRING memberId = CALL(a.arrayIndexExpr, getText);
                    member_t* member = NULL;
                    for (int i = 0; i < entry->type->memberCount; i++) {
                        if (CALL(entry->type->members[i].identifier, compareS, memberId) == 0) {
                            member = &entry->type->members[i];
                            break;
                        }
                    }
                    if (member == NULL) {
                        fprintf(stderr, "Error: type '%s' has no member '%s'.\n", entry->type->identifier->chars, memberId->chars);
                        return;
                    }
                    if (entry->flags & POINTER) {
                        addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                        pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbx+");
                        CALL(accessAddr, addi, member->offset);
                        CALL(accessAddr, addc, ']');
                        addr = accessAddr;
                    }
                    else {
                        int memberAddr;
                        sscanf((const char *)entry->addr->chars, "[rbp%d]", &memberAddr);
                        memberAddr += member->offset;
                        pANTLR3_STRING accessAddr = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"[rbp");
                        if (memberAddr > 0) {
                            CALL(accessAddr, addc, '+');
                        }
                        CALL(accessAddr, addi, memberAddr);
                        CALL(accessAddr, addc, ']');
                        addr = accessAddr;
                    }
                    size = member->size;
                }
                addInstruction(
                    info->instructions,
                    "mov",
                    createSizedPtr(info->strFactory, addr, size)->chars,
                    getGPRegisterInOrder(RAX, size)
                );
                if (entry->flags & (ARRAY_TYPE | POINTER)) {
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                }
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, CALL(a.expr, getLine));
                }
            break;
        }
    }
}

void labelLoopTail(cfg_node_t* node, asm_info_t* info) {
    if (node->next == NULL && node->parent != NULL) {
        label_t* bodyLabel, *nextNodeLabel;
        for (ANTLR3_UINT32 i = 0; i < info->labels->count; i++) {
            label_t* label = CALL(info->labels, get, i);
            if (label->node == node->parent && (node->parent->type == WHILE || node->parent->type == DO_WHILE || node->parent->type == DO_UNTIL)) {
                addLabel(info->instructions, label->label->chars);
            }
            if (label->node == node->parent->u.loop.body) {
                bodyLabel = label;
            }
            cfg_node_t* next = getNextNode(node->parent);
            if (label->node == next) {
                nextNodeLabel = label;
            }
        }
        switch (node->parent->type) {
            case WHILE:
            case DO_WHILE:
                {
                    if (info->generateDebugSymbols) {
                        addLineNumberLabel(info, node->parent->u.loop.cond->getLine(node->parent->u.loop.cond));
                    }
                    addInstruction(
                        info->instructions,
                        getJump(computeExpression(node->parent->u.loop.cond, RAX, info)),
                        bodyLabel->label->chars,
                        NULL
                    );
                    if (info->generateDebugSymbols) {
                        addLineNumberEndLabel(info, node->parent->u.loop.cond->getLine(node->parent->u.loop.cond));
                    }
                    break;
                }
            case DO_UNTIL:
                {
                    if (info->generateDebugSymbols) {
                        addLineNumberLabel(info, node->parent->u.loop.cond->getLine(node->parent->u.loop.cond));
                    }
                    addInstruction(
                        info->instructions,
                        getJump(invertCompRes(computeExpression(node->parent->u.loop.cond, RAX, info))),
                        bodyLabel->label->chars,
                        NULL
                    );
                    if (info->generateDebugSymbols) {
                        addLineNumberEndLabel(info, node->parent->u.loop.cond->getLine(node->parent->u.loop.cond));
                    }
                    break;
                }
            case IF:
                {
                    if (node->parent->u.cond.elseNode == NULL) {
                        break;
                    }
                    cfg_node_t* elseBody = node->parent->u.cond.elseNode;
                    while (elseBody->next != NULL) {
                        elseBody = elseBody->next;
                    }
                    if (elseBody == node) {
                        break;
                    }
                    addInstruction(
                        info->instructions,
                        "jmp",
                        nextNodeLabel->label->chars,
                        NULL
                    );
                    break;
                }
            default:
                break;
        }
    }
}

void addInstruction(pANTLR3_VECTOR as, const char* cmd, const unsigned char* dest, const unsigned char* src) {
    asm_line_t* line = malloc(sizeof(asm_line_t));
    line->cmd = (pANTLR3_UINT8)cmd;
    line->dest = dest;
    line->src = src;
    line->isLabel = false;
    CALL(as, add, line, free);
}

void addLabel(pANTLR3_VECTOR as, pANTLR3_UINT8 cmd) {
    asm_line_t* line = malloc(sizeof(asm_line_t));
    line->cmd = (pANTLR3_UINT8)cmd;
    line->isLabel = true;
    CALL(as, add, line, free);
}

void linkLabel(pANTLR3_VECTOR labels, cfg_node_t* node, pANTLR3_STRING labelStr) {
    label_t* label = malloc(sizeof(label_t));
    label->label = labelStr;
    label->node = node;
    CALL(labels, add, label, free);
}

bool isSigned(pANTLR3_STRING intType) {
    return ONE_OF_CALL(intType, compare, "int", "long", "short", "byte");
}

ANTLR3_UINT32 getSize(pANTLR3_STRING type, structs_t structs) {
    if (ONE_OF_CALL(type, compare, "int", "uint")) {
        return sizeof(int);
    }
    if (ONE_OF_CALL(type, compare, "long", "ulong")) {
        return sizeof(long);
    }
    if (ONE_OF_CALL(type, compare, "byte", "char", "bool", "string")) {
        return sizeof(char);
    }
    for (int i = 0; i < structs.count; i++) {
        if (CALL(type, compareS, structs.structs[i].identifier) == 0) {
            return structs.structs[i].totalSize;
        }
    }
    fprintf(stderr, "Error: type '%s' is not defined\n", type->chars);
    return sizeof(long);
}

var_t* getVar(pANTLR3_VECTOR map, pANTLR3_UINT8 id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        var_t* entry = CALL(map, get, i);
        if (CALL(entry->id, compare, (const char *)id) == 0) {
            return entry;
        }
    }
    return NULL;
}

var_t* getVarS(pANTLR3_VECTOR map, pANTLR3_STRING id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        var_t* entry = CALL(map, get, i);
        if (CALL(id, compareS, entry->id) == 0) {
            return entry;
        }
    }
    return NULL;
}

pANTLR3_UINT8 getAddrS(pANTLR3_VECTOR map, pANTLR3_STRING id) {
    var_t* entry = getVarS(map, id);
    return entry != NULL ? entry->addr->chars : NULL;
}

pANTLR3_STRING createNumericString(pANTLR3_STRING_FACTORY strFactory, ANTLR3_INT32 n) {
    pANTLR3_STRING str = CALL(strFactory, newRaw);
    CALL(str, addi, n);
    return str;
}

pANTLR3_STRING createSizedPtr(pANTLR3_STRING_FACTORY strFactory, pANTLR3_STRING addr, ANTLR3_UINT32 size) {
    pANTLR3_STRING ptr = CALL(strFactory, newRaw);
    switch (size) {
        case sizeof(long): CALL(ptr, append, "QWORD"); break;
        case sizeof(int): CALL(ptr, append, "DWORD"); break;
        case sizeof(short): CALL(ptr, append, "WORD"); break;
        case sizeof(char): CALL(ptr, append, "BYTE"); break;
    }
    CALL(ptr, addc, ' ');
    CALL(ptr, appendS, addr);
    return ptr;
}

void addLineNumberLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber) {
    pANTLR3_STRING dbgLabel = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"..@LN");
    CALL(dbgLabel, addi, lineNumber);
    CALL(dbgLabel, addc, '@');
    CALL(dbgLabel, append, (const char *)info->funcName);
    CALL(dbgLabel, addc, '@');
    CALL(dbgLabel, append, (const char *)info->sourceFile);
    addLabel(info->instructions, dbgLabel->chars);
}

void addLineNumberEndLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber) {
    pANTLR3_STRING dbgLabel = CALL(info->strFactory, newStr, (pANTLR3_UINT8)"..@LNEND");
    CALL(dbgLabel, addi, lineNumber);
    CALL(dbgLabel, addc, '@');
    CALL(dbgLabel, append, (const char *)info->funcName);
    CALL(dbgLabel, addc, '@');
    CALL(dbgLabel, append, (const char *)info->sourceFile);
    addLabel(info->instructions, dbgLabel->chars);
}

void setCompRes(comp_res res, REG reg, asm_info_t* info) {
    if (res != NO) {
        addInstruction(info->instructions, getSet(res), getGPRegisterInOrder(reg, sizeof(char)), NULL);
    }
}

comp_res invertCompRes(comp_res comp) {
    switch (comp) {
    case NO: return NO;
    case E:  return NE;
    case NE: return E;
    case G:  return LE;
    case GE: return L;
    case L:  return GE;
    case LE: return G;
    }
}

const char* getJump(comp_res comp) {
    switch (comp) {
    case NO: return "jnz";
    case E:  return "je";
    case NE: return "jne";
    case G:  return "jg";
    case GE: return "jge";
    case L:  return "jl";
    case LE: return "jle";
    }
}

const char* getSet(comp_res comp) {
    switch (comp) {
    case NO: return "setnz";
    case E:  return "sete";
    case NE: return "setne";
    case G:  return "setg";
    case GE: return "setge";
    case L:  return "setl";
    case LE: return "setle";
    }
}

void freeAsm(asm_t* a) {
    a->strings->free(a->strings);
    a->instructions->free(a->instructions);
    a->strFactory->close(a->strFactory);
    a->localAndArgOffsetMap->free(a->localAndArgOffsetMap);
    free(a);
}

void freeStruct(struct_t* s) {
    free(s->members);
    free(s);
}
