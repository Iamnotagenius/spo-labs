#include <antlr3interfaces.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <antlr3defs.h>
#include "../lab2/lib2.h"
#include "lib3.h"

#define DEFAULT_TYPE (pANTLR3_UINT8)"long"
#define CALL_STACK_ALIGNMENT 16
#define STACK_ALIGN(bytes) (usedStack / CALL_STACK_ALIGNMENT + (usedStack % CALL_STACK_ALIGNMENT != 0)) * CALL_STACK_ALIGNMENT

typedef struct {
    pANTLR3_STRING id;
    pANTLR3_STRING addr;
    ANTLR3_UINT32 size;
    bool isSigned;
    bool isArray;
} var_t;

typedef struct {
    cfg_node_t* node;
    pANTLR3_STRING label;
} label_t;

typedef struct {
    pANTLR3_VECTOR addrMap;
    pANTLR3_VECTOR instructions;
    pANTLR3_VECTOR strings;
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
ANTLR3_UINT32 getSize(pANTLR3_STRING intType);
void compileStatement(cfg_node_t* node, asm_info_t* info);
comp_res computeExpression(pANTLR3_BASE_TREE expr, ANTLR3_UINT32 usedRegisters, asm_info_t* info);
bool isSigned(pANTLR3_STRING intType);
var_t* createVarFromTree(pANTLR3_VECTOR map, pANTLR3_STRING id, pANTLR3_STRING addr, pANTLR3_BASE_TREE type);
var_t* createVar(pANTLR3_VECTOR map, pANTLR3_STRING id, pANTLR3_STRING addr, type_t* type);
var_t* getVar(pANTLR3_VECTOR map, pANTLR3_UINT8 id);
var_t* getVarS(pANTLR3_VECTOR map, pANTLR3_STRING id);
void labelLoopTail(cfg_node_t* node, asm_info_t* info);
pANTLR3_STRING createNumericString(pANTLR3_STRING_FACTORY strFactory, ANTLR3_INT32 n);
pANTLR3_STRING createSizedPtr(pANTLR3_STRING_FACTORY strFactory, pANTLR3_STRING addr, ANTLR3_UINT32 size);
void freeFunc(func_t* func);
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

var_t* createVarFromTree(pANTLR3_VECTOR addrMap, pANTLR3_STRING id, pANTLR3_STRING addr, pANTLR3_BASE_TREE type) {
    var_t* entry = malloc(sizeof(var_t));
    entry->id = id;
    entry->addr = addr;
    entry->isArray = type != NULL ? type->getFirstChildWithType(type, Array) != NULL || id->compare(type->getText(type), "string") == 0 : false;
    entry->size = type != NULL ? getSize(type->getText(type)) : sizeof(long);
    entry->isSigned = type != NULL ? isSigned(type->getText(type)) : true;
    addrMap->add(addrMap, entry, free);
    return entry;
}

var_t* createVar(pANTLR3_VECTOR addrMap, pANTLR3_STRING id, pANTLR3_STRING addr, type_t* type) {
    var_t* entry = malloc(sizeof(var_t));
    entry->id = id;
    entry->addr = addr;
    entry->isArray = type != NULL ? type->isArray : false;
    entry->size = type != NULL ? getSize(type->identifier) : sizeof(long);
    entry->isSigned = type != NULL ? isSigned(type->identifier) : true;
    addrMap->add(addrMap, entry, free);
    return entry;
}

ANTLR3_UINT32 moveArgsToStack(pANTLR3_VECTOR addrMap, pANTLR3_VECTOR offsetMap, asm_info_t* info, pANTLR3_BASE_TREE signature) {
    static ANTLR3_UINT32 lenArgRegs = sizeof(argumentRegisters)/sizeof(argumentRegisters[0]);
    pANTLR3_STRING_FACTORY strFactory = signature->strFactory;
    ANTLR3_INT64 usedStack = 0;
    ANTLR3_UINT32 i;
    bool hasReturnType = signature->getFirstChildWithType(signature, ReturnType) != NULL;

    for (i = hasReturnType; i < signature->children->count && i < lenArgRegs; i++) {
        pANTLR3_BASE_TREE argNode = signature->getChild(signature, i);
        pANTLR3_BASE_TREE id = argNode->getChild(argNode, 0);
        pANTLR3_BASE_TREE type = argNode->getChild(argNode, 1);
        var_t* var = createVarFromTree(addrMap, id->getText(id), NULL, type);
        usedStack += var->isArray ? sizeof(long) : var->size;
        pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp-");
        addr->addi(addr, usedStack);
        addr->addc(addr, ']');
        var->addr = addr;
        addInstruction(
            info->instructions,
            "mov",
            addr->chars,
            getGPRegisterInOrder(
                argumentRegisters[i - hasReturnType],
                var->isArray ? sizeof(long) : var->size
            )
        );
        arg_offset_t* off = malloc(sizeof(arg_offset_t));
        off->identifier = id->getText(id);
        off->rbpOffset = -usedStack;
        off->sourceFile = info->sourceFile;
        off->funcName = info->funcName;
        off->size = var->size;
        off->isArray = var->isArray;
        off->isSigned = var->isSigned;
        offsetMap->add(offsetMap, off, free);
    }
    for (; i < signature->children->count; i++) {
        pANTLR3_BASE_TREE argNode = signature->getChild(signature, i);
        pANTLR3_BASE_TREE id = argNode->getChild(argNode, 0);
        pANTLR3_BASE_TREE type = argNode->getChild(argNode, 1);
        var_t* var = createVarFromTree(addrMap, id->getText(id), NULL, type);
        pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp+");
        addr->addi(addr, (i - lenArgRegs + 2) * sizeof(long));
        addr->addc(addr, ']');
        var->addr = addr;
        arg_offset_t* off = malloc(sizeof(arg_offset_t));
        off->identifier = id->getText(id);
        off->rbpOffset = (i - lenArgRegs + 2) * sizeof(long);
        off->sourceFile = info->sourceFile;
        off->funcName = info->funcName;
        off->size = var->size;
        off->isArray = var->isArray;
        off->isSigned = var->isSigned;
        offsetMap->add(offsetMap, off, free);
    }
    return usedStack;
}

asm_t* compileToAssembly(cfg_t* cfg, bool generateDebugSymbols) {
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
        vars_t* vars = cfg->vars->get(cfg->vars, i);
        ANTLR3_UINT32 size = getSize(vars->type.identifier);
        for (ANTLR3_UINT32 i = 0; i < vars->identifiers->count; i++) {
            pANTLR3_STRING id = vars->identifiers->get(vars->identifiers, i);
            pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp-");
            usedStack += vars->type.isArray ? sizeof(long) : size;
            addr->addi(addr, usedStack);
            addr->addc(addr, ']');
            var_t* var = createVar(addrMap, id, addr, &vars->type);
            arg_offset_t* off = malloc(sizeof(arg_offset_t));
            off->identifier = id;
            off->rbpOffset = -usedStack;
            off->funcName = cfg->name;
            off->sourceFile = cfg->sourceFile;
            off->size = var->size;
            off->isArray = var->isArray;
            off->isSigned = var->isSigned;
            offsetMap->add(offsetMap, off, free);
        }
    }
    ANTLR3_UINT32 toSub = STACK_ALIGN(usedStack);
    pANTLR3_STRING bytes = createNumericString(strFactory, toSub);
    addInstruction(instructions, "sub", (pANTLR3_UINT8)"rsp", bytes->chars);
#ifdef DEBUG
    fprintf(stderr, "AddrMap:\n");
    for (ANTLR3_UINT32 i = 0; i < addrMap->count; i++) {
        var_t* entry = addrMap->get(addrMap, i);
        fprintf(stderr, "%s -> %s\n", entry->id->chars, entry->addr->chars);
    }
#endif
    walkCfg(cfg->cfgRoot, (void (*))compileStatement, &info, (void (*))labelLoopTail);

    for (ANTLR3_UINT32 i = 0; i < labels->count; i++) {
        label_t* label = labels->get(labels, i);
        if (label->node == NULL) {
            addLabel(instructions, label->label->chars);
        }
    }

    addInstruction(instructions, "add", (pANTLR3_UINT8)"rsp", bytes->chars);
    addInstruction(instructions, "pop", (pANTLR3_UINT8)"rbp", NULL);
    addInstruction(instructions, "ret", NULL, NULL);
    asm_t* a = malloc(sizeof(asm_t));
    a->instructions = instructions;
    a->strFactory = strFactory;
    a->strings = strings;
    a->localAndArgOffsetMap = offsetMap;
    addrMap->free(addrMap);
    labels->free(labels);
    return a;
}

void handleCall(pANTLR3_BASE_TREE call, ANTLR3_UINT32 usedRegisters, asm_info_t* info) {
    pANTLR3_BASE_TREE lParen = call->getChild(call, 0);
    if (usedRegisters > 0) {
        ANTLR3_UINT32 pushes = usedRegisters - 1;
        for (ANTLR3_UINT32 i = 0; i < usedRegisters - 1; i++) {
            addInstruction(info->instructions, "push", getGPRegisterInOrder(i, sizeof(long)), NULL);
        }
        if (pushes % 2 == 1) {
            addInstruction(info->instructions, "add", (pANTLR3_UINT8)"rsp", createNumericString(info->strFactory, sizeof(long))->chars);
        }
    }
    ANTLR3_UINT32 argCount = lParen->getChildCount(lParen);
    ANTLR3_UINT32 i;
    for (i = 0; i < argCount && i <= (R15 - RBX); i++) {
        setCompRes(computeExpression(lParen->getChild(lParen, i), RAX, info), RAX, info);
        addInstruction(info->instructions, "push", getGPRegisterInOrder(i + RBX, sizeof(long)), NULL);
        addInstruction(info->instructions, "mov", getGPRegisterInOrder(i + RBX, sizeof(long)), getGPRegisterInOrder(RAX, sizeof(long)));
    }
    for (; i < argCount; i++) {
        setCompRes(computeExpression(lParen->getChild(lParen, argCount - i + (R15 - RBX)), RAX, info), RAX, info);
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
    if (argCount > R15 - RBX) {
        addInstruction(info->instructions, "pop", getGPRegisterInOrder(R9, sizeof(long)), NULL);
    }

    /* NOTE: clear RAX? */

    addInstruction(info->instructions, "call", call->getText(call)->chars, NULL);
    if (argCount > R15 - RBX + 1) {
        pANTLR3_STRING bytes = info->strFactory->newRaw(info->strFactory);
        bytes->addi(bytes, (argCount - (R15 - RBX + 1)) * sizeof(long));
        addInstruction(info->instructions, "add", (pANTLR3_UINT8)"rsp", bytes->chars);
    }
    for (i = 0; i < usedCalleeSavedRegisters; i++) {
        addInstruction(info->instructions, "pop", getGPRegisterInOrder(usedCalleeSavedRegisters - i - 1 + RBX, sizeof(long)), NULL);
    }
    if (usedRegisters > 0) {
        ANTLR3_UINT32 pushes = usedRegisters - 1;
        if (pushes % 2 == 1) {
            addInstruction(info->instructions, "sub", (pANTLR3_UINT8)"rsp", createNumericString(info->strFactory, sizeof(long))->chars);
        }

        for (ANTLR3_INT32 i = usedRegisters - 1; i >= 0; i--) {
            addInstruction(info->instructions, "pop", getGPRegisterInOrder(i, sizeof(long)), NULL);
        }
    }
}

comp_res computeExpression(pANTLR3_BASE_TREE expr, ANTLR3_UINT32 usedRegisters, asm_info_t* info) {
    if (usedRegisters > R11) {
        fprintf(stderr, "Error: temp var count exceeded.\n");
        return NO;
    }
    switch (expr->getType(expr)) {
        case CharLiteral:
        case HexLiteral:
        case BitsLiteral:
        case Integer:
            {
                addInstruction(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), expr->getText(expr)->chars);
                return NO;
            }
        case Bool:
            {
                addInstruction(
                        info->instructions,
                        "mov",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        (pANTLR3_UINT8)(expr->getText(expr)->compare(expr->getText(expr), "true") ? "1" : "0")
                      );
                return NO;
            }
        case String:
            {
                string_t* s = NULL;
                for (ANTLR3_INT32 i = 0; i < info->strings->count; i++) {
                    string_t* str = info->strings->get(info->strings, i);
                    if (str->string->compareS(str->string, expr->getText(expr)) == 0) {
                        s = str;
                        break;
                    }
                }

                if (s == NULL) {
                    pANTLR3_STRING addr = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)"[S");
                    addr->addi(addr, info->strings->count);
                    addr->addc(addr, ']');
                    s = malloc(sizeof(string_t));
                    s->string = expr->getText(expr);
                    s->addr = addr;
                    info->strings->add(info->strings, s, free);
                }

                addInstruction(info->instructions, "lea", getGPRegisterInOrder(usedRegisters, sizeof(long)), s->addr->chars);
                return NO;
            }
        case Identifier:
            {
                var_t* entry = getVarS(info->addrMap, expr->getText(expr));
                if (entry == NULL) {
                    if (expr->getChildCount(expr) == 1) {
                        handleCall(expr, usedRegisters, info);
                    }
                    return NO;
                }
                pANTLR3_STRING addr = entry->addr;
                if (entry->isArray) {
                    pANTLR3_BASE_TREE arrayAccess = expr->getFirstChildWithType(expr, LParen);
                    if (arrayAccess == NULL) {
                        addInstruction(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), entry->addr->chars);
                        return NO;
                    }
                    if (arrayAccess->getChildCount(arrayAccess) > 1) {
                        fputs("Error: only one-dimensional arrays are supported", stderr);
                        return NO;
                    }
                    if (arrayAccess->getChildCount(arrayAccess) == 0) {
                        fputs("Error: index for an array is not specified", stderr);
                        return NO;
                    }
                    comp_res res = computeExpression(arrayAccess->getChild(arrayAccess, 0), usedRegisters, info);
                    if (res != NO) {
                        setCompRes(res, usedRegisters, info);
                        addInstruction(info->instructions, "movzx", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(usedRegisters, sizeof(char)));
                    }
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                    pANTLR3_STRING accessAddr = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)"[rbx+");
                    accessAddr->append(accessAddr, (const char *)getGPRegisterInOrder(usedRegisters, sizeof(long)));
                    if (entry->size > 1) {
                        accessAddr->addc(accessAddr, '*');
                        accessAddr->addi(accessAddr, entry->size);
                    }
                    accessAddr->addc(accessAddr, ']');
                    addr = accessAddr;
                }
                if (entry->size == sizeof(long)) {
                    addInstruction(
                        info->instructions,
                        "mov",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        addr->chars
                    );
                } else if (entry->size == sizeof(int)) {
                    addInstruction(
                            info->instructions,
                            "mov",
                            getGPRegisterInOrder(usedRegisters, sizeof(int)),
                            createSizedPtr(info->strFactory, addr, entry->size)->chars
                          );
                } else {
                    addInstruction(
                            info->instructions,
                            entry->isSigned ? "movsx" : "movzx",
                            getGPRegisterInOrder(usedRegisters, sizeof(long)),
                            createSizedPtr(info->strFactory, addr, entry->size)->chars
                          );
                }
                if (entry->isArray) {
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                }
                return NO;
            }
        case Plus:
        case Minus:
            {
                setCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info), usedRegisters, info);
                if (expr->getChildCount(expr) == 1) {
                    addInstruction(info->instructions, "neg", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                    return NO;
                }
                setCompRes(computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info), usedRegisters, info);
                addInstruction(
                        info->instructions,
                        expr->getType(expr) == Plus ? "add" : "sub",
                        getGPRegisterInOrder(usedRegisters, sizeof(long)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                      );
                return NO;
            }
        case MultOp:
            {
                setCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info), usedRegisters, info);
                if (expr->getText(expr)->chars[0] == '*') {
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
                if (usedRegisters - 2 != (expr->getText(expr)->chars[0] == '/' ? RAX : RDX)) {
                    addInstruction(
                            info->instructions,
                            "mov",
                            getGPRegisterInOrder(usedRegisters - 2, sizeof(long)),
                            getGPRegisterInOrder(expr->getText(expr)->chars[0] == '/' ? RAX : RDX, sizeof(long))
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
                setCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info), usedRegisters, info);
                addInstruction(info->instructions, "not", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                return NO;
            }
        case BitOp:
            {
                setCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info), usedRegisters, info);
                const char* op;
                switch (expr->getText(expr)->chars[0]) {
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
                setCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info), usedRegisters, info);
                setCompRes(computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info), usedRegisters, info);
                addInstruction(info->instructions, "cmp", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(usedRegisters + 1, sizeof(long)));
                pANTLR3_STRING op = expr->getText(expr);
                if (op->compare(op, ">") == 0) {
                    return G;
                }
                if (op->compare(op, "<") == 0) {
                    return L;
                }
                if (op->compare(op, ">=") == 0) {
                    return GE;
                }
                if (op->compare(op, "<=") == 0) {
                    return LE;
                }
                if (op->compare(op, "==") == 0) {
                    return E;
                }
                if (op->compare(op, "!=") == 0) {
                    return NE;
                }
            }
        case Not:
            {
                return invertCompRes(computeExpression(expr->getChild(expr, 0), usedRegisters, info));
            }
        case And:
        case Or:
            {
                addInstruction(
                        info->instructions,
                        getSet(computeExpression(expr->getChild(expr, 0), usedRegisters, info)),
                        getGPRegisterInOrder(usedRegisters, sizeof(char)),
                        NULL
                      );
                addInstruction(
                        info->instructions,
                        getSet(computeExpression(expr->getChild(expr, 0), usedRegisters + 1, info)),
                        getGPRegisterInOrder(usedRegisters + 1, sizeof(char)),
                        NULL
                      );
                addInstruction(
                        info->instructions,
                        expr->getType(expr) == And ? "and" : "or",
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
        label_t* label = info->labels->get(info->labels, i);
        if (label->node == node) {
            addLabel(info->instructions, label->label->chars);
        }
    }
    switch (node->type) {
        case EXPR:
            {
                expr_t e = node->u.expr;
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, e.tree->getLine(e.tree));
                }
                setCompRes(computeExpression(e.tree, RAX, info), RAX, info);
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, e.tree->getLine(e.tree));
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
                pANTLR3_STRING label = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)".L");
                label->addi(label, info->labels->count);
                linkLabel(info->labels, getNextNode(node), label);
                if (i.elseNode != NULL) {
                    label = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)".L");
                    label->addi(label, info->labels->count);
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
                pANTLR3_STRING label = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)".L");
                label->addi(label, info->labels->count);
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
                pANTLR3_STRING label = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)".L");
                label->addi(label, info->labels->count);
                linkLabel(info->labels, node, label);
                addInstruction(info->instructions, "jmp", label->chars, NULL);
            }
        case DO_UNTIL:
        case DO_WHILE:
            {
                loop_t l = node->u.loop;
                pANTLR3_STRING label = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)".L");
                label->addi(label, info->labels->count);
                linkLabel(info->labels, l.body, label);
                break;
            }
        case ASSIGNMENT:
            {
                assignment_t a = node->u.assignment;
                if (info->generateDebugSymbols) {
                    addLineNumberLabel(info, a.expr->getLine(a.expr));
                }
                setCompRes(computeExpression(a.expr, RAX, info), RAX, info);
                var_t* entry = getVar(info->addrMap, a.identifier);
                if (entry == NULL) {
                    fprintf(stderr, "Error: '%s' is not defined.\n", a.identifier);
                }
                pANTLR3_STRING addr = entry->addr;
                if (entry->isArray) {
                    if (a.arrayIndexExpr == NULL) {
                        addInstruction(info->instructions, "mov", getGPRegisterInOrder(RCX, sizeof(long)), entry->addr->chars);
                        addInstruction(info->instructions, "mov", (pANTLR3_UINT8)"[rcx]", (pANTLR3_UINT8)"rax");
                        return;
                    }
                    comp_res res = computeExpression(a.arrayIndexExpr->getChild(a.arrayIndexExpr, 0), RCX, info);
                    if (res != NO) {
                        setCompRes(res, RCX, info);
                        addInstruction(info->instructions, "movzx", getGPRegisterInOrder(RCX, sizeof(long)), getGPRegisterInOrder(RCX, sizeof(char)));
                    }
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                    pANTLR3_STRING accessAddr = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)"[rbx+");
                    accessAddr->append(accessAddr, (const char *)getGPRegisterInOrder(RCX, sizeof(long)));
                    if (entry->size > 1) {
                        accessAddr->addc(accessAddr, '*');
                        accessAddr->addi(accessAddr, entry->size);
                    }
                    accessAddr->addc(accessAddr, ']');
                    addr = accessAddr;
                }
                addInstruction(
                    info->instructions,
                    "mov",
                    createSizedPtr(info->strFactory, addr, entry->size)->chars,
                    getGPRegisterInOrder(RAX, entry->size)
                );
                if (entry->isArray) {
                    addInstruction(info->instructions, "xchg", (pANTLR3_UINT8)"rbx", entry->addr->chars);
                }
                if (info->generateDebugSymbols) {
                    addLineNumberEndLabel(info, a.expr->getLine(a.expr));
                }
            break;
        }
    }
}

void labelLoopTail(cfg_node_t* node, asm_info_t* info) {
    if (node->next == NULL && node->parent != NULL) {
        label_t* bodyLabel, *nextNodeLabel;
        for (ANTLR3_UINT32 i = 0; i < info->labels->count; i++) {
            label_t* label = info->labels->get(info->labels, i);
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
    as->add(as, line, free);
}

void addLabel(pANTLR3_VECTOR as, pANTLR3_UINT8 cmd) {
    asm_line_t* line = malloc(sizeof(asm_line_t));
    line->cmd = (pANTLR3_UINT8)cmd;
    line->isLabel = true;
    as->add(as, line, free);
}

void linkLabel(pANTLR3_VECTOR labels, cfg_node_t* node, pANTLR3_STRING labelStr) {
    label_t* label = malloc(sizeof(label_t));
    label->label = labelStr;
    label->node = node;
    labels->add(labels, label, free);
}

bool isSigned(pANTLR3_STRING intType) {
    return intType->compare(intType, "int") == 0||
        intType->compare(intType, "long") == 0 ||
        intType->compare(intType, "byte") == 0;
}

ANTLR3_UINT32 getSize(pANTLR3_STRING type) {
    if (type->compare(type, "int") == 0 || type->compare(type, "uint") == 0) {
        return sizeof(int);
    }
    if (type->compare(type, "long") == 0 || type->compare(type, "ulong") == 0) {
        return sizeof(long);
    }
    if (type->compare(type, "byte") == 0 ||
            type->compare(type, "char") == 0 ||
            type->compare(type, "bool") == 0 ||
            type->compare(type, "string") == 0) {
        return sizeof(char);
    }
    return sizeof(long);
}

var_t* getVar(pANTLR3_VECTOR map, pANTLR3_UINT8 id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        var_t* entry = map->get(map, i);
        if (entry->id->compare(entry->id, (const char*)id) == 0) {
            return entry;
        }
    }
    return NULL;
}

var_t* getVarS(pANTLR3_VECTOR map, pANTLR3_STRING id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        var_t* entry = map->get(map, i);
        if (id->compareS(id, entry->id) == 0) {
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
    pANTLR3_STRING str = strFactory->newRaw(strFactory);
    str->addi(str, n);
    return str;
}

pANTLR3_STRING createSizedPtr(pANTLR3_STRING_FACTORY strFactory, pANTLR3_STRING addr, ANTLR3_UINT32 size) {
    pANTLR3_STRING ptr = strFactory->newRaw(strFactory);
    switch (size) {
        case sizeof(long): ptr->append(ptr, "QWORD"); break;
        case sizeof(int): ptr->append(ptr, "DWORD"); break;
        case sizeof(short): ptr->append(ptr, "WORD"); break;
        case sizeof(char): ptr->append(ptr, "BYTE"); break;
    }
    ptr->addc(ptr, ' ');
    ptr->appendS(ptr, addr);
    return ptr;
}

void addLineNumberLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber) {
    pANTLR3_STRING dbgLabel = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)"..@LN");
    dbgLabel->addi(dbgLabel, lineNumber);
    dbgLabel->addc(dbgLabel, '@');
    dbgLabel->append(dbgLabel, (const char *)info->funcName);
    dbgLabel->addc(dbgLabel, '@');
    dbgLabel->append(dbgLabel, (const char *)info->sourceFile);
    addLabel(info->instructions, dbgLabel->chars);
}

void addLineNumberEndLabel(asm_info_t* info, ANTLR3_UINT32 lineNumber) {
    pANTLR3_STRING dbgLabel = info->strFactory->newStr(info->strFactory, (pANTLR3_UINT8)"..@LNEND");
    dbgLabel->addi(dbgLabel, lineNumber);
    dbgLabel->addc(dbgLabel, '@');
    dbgLabel->append(dbgLabel, (const char *)info->funcName);
    dbgLabel->addc(dbgLabel, '@');
    dbgLabel->append(dbgLabel, (const char *)info->sourceFile);
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

void freeFunc(func_t* func) {
    func->args->free(func->args);
    free(func);
}

void freeAsm(asm_t* a) {
    a->strings->free(a->strings);
    a->instructions->free(a->instructions);
    a->strFactory->close(a->strFactory);
    a->localAndArgOffsetMap->free(a->localAndArgOffsetMap);
    free(a);
}
