#include <antlr3interfaces.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <antlr3defs.h>
#include "../lab2/lib2.h"
#include "lib3.h"

#define DEFAULT_TYPE "long"
#define CALL_STACK_ALIGNMENT 16
#define STACK_ALIGN(bytes) (usedStack / CALL_STACK_ALIGNMENT + (usedStack % CALL_STACK_ALIGNMENT != 0)) * CALL_STACK_ALIGNMENT

typedef struct {
    pANTLR3_STRING id;
    pANTLR3_STRING addr;
    ANTLR3_UINT32 size;
    /* TODO: signed or unsigned? */
} id_entry_t;

typedef struct {
    pANTLR3_VECTOR addrMap;
    pANTLR3_VECTOR instructions;
    ANTLR3_UINT32 usedStack;
} asm_info_t;

typedef enum {
    NO, E, NE, G, GE, L, LE
} comp_res;

void addCmd(pANTLR3_VECTOR as, const char* cmd, const unsigned char* dest, const unsigned char* src);
void addLabel(pANTLR3_VECTOR as, pANTLR3_UINT8 cmd);
pANTLR3_UINT8 getAddrS(pANTLR3_VECTOR map, pANTLR3_STRING id);
ANTLR3_UINT32 moveArgsToStack(pANTLR3_VECTOR addrMap, pANTLR3_VECTOR instructions, pANTLR3_BASE_TREE signature);
ANTLR3_UINT32 getSize(pANTLR3_STRING intType);
void compileStatement(cfg_node_t* node, asm_info_t* info);
id_entry_t* getEntry(pANTLR3_VECTOR map, pANTLR3_UINT8 id);
comp_res invertCompRes(comp_res comp);
const char* getSet(comp_res comp);
const char* getJump(comp_res comp);

typedef enum {
    RAX, RCX, RDX, RDI, RSI, R8, R9, R10, R11
} REG;

const unsigned char* getGPRegisterInOrder(REG reg, ANTLR3_UINT32 size) {
    /* I don't want to deal with callee saved registers. */
    static const char* registers[][4] = {
        [RAX] = {"rax", "eax",  "ax",   "al"},
        [RCX] = {"rcx", "ecx",  "cx",   "cl"},
        [RDX] = {"rdx", "edx",  "dx",   "dl"},
        [RDI] = {"rdi", "edi",  "di",   "dil"},
        [RSI] = {"rsi", "esi",  "si",   "sil"},
        [R8]  = {"r8",  "r8d",  "r8w",  "r8b"},
        [R9]  = {"r9",  "r9d",  "r9w",  "r9b"},
        [R10] = {"r10", "r10d", "r10w", "r10b"},
        [R11] = {"r11", "r11d", "r11w", "r11b"},
    };
    ANTLR3_UINT32 regSizeIdx;
    switch (size) {
        case 8: regSizeIdx = 0; break;
        case 4: regSizeIdx = 1; break;
        case 2: regSizeIdx = 2; break;
        case 1: regSizeIdx = 3; break;
    }
    return (const unsigned char*)registers[reg][regSizeIdx];
}

ANTLR3_UINT32 moveArgsToStack(pANTLR3_VECTOR addrMap, pANTLR3_VECTOR instructions, pANTLR3_BASE_TREE signature) {
    static REG argRegs[] = {RDI, RSI, RDX, RCX, R8, R9};
    static ANTLR3_UINT32 lenArgRegs = sizeof(argRegs)/sizeof(argRegs[0]);
    pANTLR3_STRING_FACTORY strFactory = signature->strFactory;
    ANTLR3_UINT32 usedStack = 0;
    ANTLR3_UINT32 i;
    for (i = 0; i < signature->children->count && i < lenArgRegs; i++) {
        pANTLR3_BASE_TREE argNode = signature->getChild(signature, i);
        pANTLR3_BASE_TREE id = argNode->getChild(argNode, 0);
        pANTLR3_BASE_TREE type = argNode->getChild(argNode, 1);
        ANTLR3_UINT32 size = type != NULL ? getSize(type->getText(type)) : 8;
        usedStack += size;
        pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp-");
        addr->addi(addr, usedStack);
        addr->addc(addr, ']');
        id_entry_t* entry = malloc(sizeof(id_entry_t));
        entry->id = id->getText(id);
        entry->addr = addr;
        entry->size = size;
        addrMap->add(addrMap, entry, free);
        asm_line_t* line = malloc(sizeof(asm_line_t));
        line->cmd = (pANTLR3_UINT8)"mov";
        line->src = getGPRegisterInOrder(argRegs[i], size);
        line->dest = addr->chars;
        line->isLabel = false;
        instructions->add(instructions, line, free);
    }
    for (; i < signature->children->count; i++) {
        pANTLR3_BASE_TREE argNode = signature->getChild(signature, i);
        pANTLR3_BASE_TREE id = argNode->getChild(argNode, 0);
        pANTLR3_BASE_TREE type = argNode->getChild(argNode, 1);
        ANTLR3_UINT32 size = type != NULL ? getSize(type->getText(type)) : sizeof(long);
        id_entry_t* entry = malloc(sizeof(id_entry_t));
        entry->id = id->getText(id);
        entry->size = size;
        pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp+");
        addr->addi(addr, (i - lenArgRegs + 2) * sizeof(long));
        addr->addc(addr, ']');
        entry->addr = addr;
        addrMap->add(addrMap, entry, free);
    }
    return usedStack;
}

asm_t compileToAssembly(cfg_t* cfg) {
    pANTLR3_STRING_FACTORY strFactory = antlr3StringFactoryNew(ANTLR3_ENC_UTF8);
    pANTLR3_VECTOR instructions = antlr3VectorNew(ANTLR3_SIZE_HINT);
    ANTLR3_UINT32 usedStack = 0;
    pANTLR3_VECTOR addrMap = antlr3VectorNew(ANTLR3_SIZE_HINT);
    addLabel(instructions, cfg->name);
    addCmd(instructions, "push", (pANTLR3_UINT8)"rbp", NULL);
    addCmd(instructions, "mov", (pANTLR3_UINT8)"rbp", (pANTLR3_UINT8)"rsp");

    if (cfg->signature != NULL) {
        usedStack = moveArgsToStack(addrMap, instructions, cfg->signature);
    }
    for (ANTLR3_UINT32 i = 0; i < cfg->vars->count; i++) {
        vars_t* vars = cfg->vars->get(cfg->vars, i);
        ANTLR3_UINT32 size = getSize(vars->type.identifier);
        for (ANTLR3_UINT32 i = 0; i < vars->identifiers->count; i++) {
            pANTLR3_STRING id = vars->identifiers->get(vars->identifiers, i);
            pANTLR3_STRING addr = strFactory->newStr(strFactory, (pANTLR3_UINT8)"[rbp-");
            usedStack += size;
            addr->addi(addr, usedStack);
            addr->addc(addr, ']');
            id_entry_t* entry = malloc(sizeof(id_entry_t));
            entry->id = id;
            entry->size = size;
            entry->addr = addr;
            addrMap->add(addrMap, entry, free);
            fprintf(stderr, "handled id = '%s'\n", id->chars);
        }
    }
    ANTLR3_UINT32 toSub = STACK_ALIGN(usedStack);
    asm_line_t* sub = malloc(sizeof(asm_line_t));
    sub->cmd = (pANTLR3_UINT8)"sub";
    sub->dest = (pANTLR3_UINT8)"rsp";
    pANTLR3_STRING bytes = strFactory->newRaw(strFactory);
    bytes->addi(bytes, toSub);
    sub->src = bytes->chars;
    sub->isLabel = false;
    instructions->add(instructions, sub, free);
    fprintf(stderr, "AddrMap:\n");
    for (ANTLR3_UINT32 i = 0; i < addrMap->count; i++) {
        id_entry_t* entry = addrMap->get(addrMap, i);
        fprintf(stderr, "%s -> %s\n", entry->id->chars, entry->addr->chars);
    }
    asm_info_t info = {addrMap, instructions};
    walkCfg(cfg->cfgRoot, (void (*)(cfg_node_t*, void*))compileStatement, &info);

    addCmd(instructions, "pop", (pANTLR3_UINT8)"rbp", NULL);
    asm_t as = {instructions, strFactory};
    return as;
}

comp_res computeExpression(pANTLR3_BASE_TREE expr, ANTLR3_UINT32 usedRegisters, asm_info_t* info) {
    if (usedRegisters > R11) {
        fprintf(stderr, "Error: temp var count exceeded.\n");
        return NO;
    }
    /* TODO: save strings to define them later */
    /* NOTE: comp_res can be checked during computation thus SETcc instructions can be utilized */
    switch (expr->getType(expr)) {
        case CharLiteral:
        case HexLiteral:
        case BitsLiteral:
        case Integer:
            {
                addCmd(info->instructions, "mov", getGPRegisterInOrder(usedRegisters, sizeof(long)), expr->getText(expr)->chars);
                return NO;
            }
        case Bool:
            {
                addCmd(
                    info->instructions,
                    "mov",
                    getGPRegisterInOrder(usedRegisters, sizeof(long)),
                    (pANTLR3_UINT8)(expr->getText(expr)->compare(expr->getText(expr), "true") ? "1" : "0")
                );
                return NO;
            }
        case Identifier:
            {
                asm_line_t* line = malloc(sizeof(asm_line_t));
                line->isLabel = false;
                line->cmd = (pANTLR3_UINT8)"mov";
                line->dest = getGPRegisterInOrder(usedRegisters, sizeof(long));
                line->src = getAddrS(info->addrMap, expr->getText(expr));
                if (line->src == NULL) {
                    /* TODO: handle call */
                    line->src = (pANTLR3_UINT8)"0";
                }
                info->instructions->add(info->instructions, line, free);
                return NO;
            }
        case Plus:
        case Minus:
            {
                computeExpression(expr->getChild(expr, 0), usedRegisters, info);
                if (expr->getChildCount(expr) == 1) {
                    addCmd(info->instructions, "neg", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                    return NO;
                }
                computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info);
                addCmd(
                    info->instructions,
                    expr->getType(expr) == Plus ? "add" : "sub",
                    getGPRegisterInOrder(usedRegisters, sizeof(long)),
                    getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                );
                return NO;
            }
        case MultOp:
            {
                computeExpression(expr->getChild(expr, 0), usedRegisters, info);
                computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info);
                if (expr->getText(expr)->chars[0] == '*') {
                    addCmd(
                            info->instructions,
                            "imul",
                            getGPRegisterInOrder(usedRegisters, sizeof(long)),
                            getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                          );
                    return NO;
                }
                usedRegisters += 2;
                addCmd(info->instructions, "push", getGPRegisterInOrder(RAX, sizeof(long)), NULL);
                if (usedRegisters > RDX) {
                    addCmd(info->instructions, "push", getGPRegisterInOrder(RDX, sizeof(long)), NULL);
                }
                addCmd(
                    info->instructions,
                    "mov",
                    getGPRegisterInOrder(RAX, sizeof(long)),
                    getGPRegisterInOrder(usedRegisters, sizeof(long))
                );
                addCmd(info->instructions, "mov", getGPRegisterInOrder(RDX, sizeof(long)), (pANTLR3_UINT8)"0");
                addCmd(info->instructions, "idiv", getGPRegisterInOrder(usedRegisters + 1, sizeof(long)), NULL);
                addCmd(
                    info->instructions,
                    "mov",
                    getGPRegisterInOrder(usedRegisters - 2, sizeof(long)),
                    getGPRegisterInOrder(expr->getText(expr)->chars[0] == '/' ? RAX : RDX, sizeof(long))
                );
                if (usedRegisters > RDX) {
                    addCmd(info->instructions, "pop", getGPRegisterInOrder(RDX, sizeof(long)), NULL);
                }
                addCmd(info->instructions, "pop", getGPRegisterInOrder(RAX, sizeof(long)), NULL);
                usedRegisters -= 2;
                return NO;
            }
        case Tilde:
            {
                computeExpression(expr->getChild(expr, 0), usedRegisters, info);
                addCmd(info->instructions, "not", getGPRegisterInOrder(usedRegisters, sizeof(long)), NULL);
                return NO;
            }
        case BitOp:
            {
                computeExpression(expr->getChild(expr, 0), usedRegisters, info);
                computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info);
                const char* op;
                switch (expr->getText(expr)->chars[0]) {
                    case '^': op = "xor"; break;
                    case '|': op = "or"; break;
                    case '&': op = "and"; break;
                }
                addCmd(
                    info->instructions,
                    op,
                    getGPRegisterInOrder(usedRegisters, sizeof(long)),
                    getGPRegisterInOrder(usedRegisters + 1, sizeof(long))
                );
                return NO;
            }
        case CompOp:
            {
                computeExpression(expr->getChild(expr, 0), usedRegisters, info);
                computeExpression(expr->getChild(expr, 1), usedRegisters + 1, info);
                addCmd(info->instructions, "cmp", getGPRegisterInOrder(usedRegisters, sizeof(long)), getGPRegisterInOrder(usedRegisters + 1, sizeof(long)));
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
                addCmd(
                    info->instructions,
                    getSet(computeExpression(expr->getChild(expr, 0), usedRegisters, info)),
                    getGPRegisterInOrder(usedRegisters, sizeof(char)),
                    NULL
                );
                addCmd(
                    info->instructions,
                    getSet(computeExpression(expr->getChild(expr, 0), usedRegisters + 1, info)),
                    getGPRegisterInOrder(usedRegisters + 1, sizeof(char)),
                    NULL
                );
                addCmd(
                    info->instructions,
                    expr->getType(expr) == And ? "and" : "or",
                    getGPRegisterInOrder(usedRegisters, sizeof(char)),
                    getGPRegisterInOrder(usedRegisters + 1, sizeof(char))
                );
                addCmd(info->instructions, "cmp", getGPRegisterInOrder(usedRegisters, sizeof(char)), (pANTLR3_UINT8)"0");
                return NE;
            }
    }
    return NO;
}

void compileStatement(cfg_node_t* node, asm_info_t* info) {
    switch (node->type) {
    case EXPR:
        {
            expr_t e = node->u.expr;
            computeExpression(e.tree, RAX, info);
            break;
        }
    case DIM:
    case IF:
    case BREAK:
    case WHILE:
    case DO_UNTIL:
    case DO_WHILE:
        break;
    case ASSIGNMENT:
        {
            assignment_t a = node->u.assignment;
            comp_res res = computeExpression(a.expr, RAX, info);
            if (res != NO) {
                addCmd(info->instructions, getSet(res), getGPRegisterInOrder(RAX, sizeof(char)), NULL);
            }
            id_entry_t* entry = getEntry(info->addrMap, a.identifier);
            if (entry == NULL) {
                fprintf(stderr, "Error: '%s' is not defined.\n", a.identifier);
            }
            /* movsx if signed, otherwise movzx */
            addCmd(
                info->instructions,
                entry->size == sizeof(long) ? "mov" : "movsx",
                entry->addr->chars,
                getGPRegisterInOrder(RAX, entry->size)
            );
            break;
        }
    }
}

void addCmd(pANTLR3_VECTOR as, const char* cmd, const unsigned char* dest, const unsigned char* src) {
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

bool isSigned(pANTLR3_STRING intType) {
    return intType->compare(intType, "int") == 0||
        intType->compare(intType, "long") == 0 ||
        intType->compare(intType, "byte") == 0;
}

ANTLR3_UINT32 getSize(pANTLR3_STRING intType) {
    if (intType->compare(intType, "int") == 0 || intType->compare(intType, "uint") == 0) {
        return 4;
    }
    if (intType->compare(intType, "long") == 0 || intType->compare(intType, "ulong") == 0) {
        return 8;
    }
    if (intType->compare(intType, "byte") == 0 ||
            intType->compare(intType, "char") == 0 ||
            intType->compare(intType, "bool") == 0) {
        return 1;
    }
    return 8;
}

id_entry_t* getEntry(pANTLR3_VECTOR map, pANTLR3_UINT8 id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        id_entry_t* entry = map->get(map, i);
        if (entry->id->compare(entry->id, (const char*)id) == 0) {
            return entry;
        }
    }
    return NULL;
}

id_entry_t* getEntryS(pANTLR3_VECTOR map, pANTLR3_STRING id) {
    for (ANTLR3_UINT32 i = 0; i < map->count; i++) {
        id_entry_t* entry = map->get(map, i);
        if (id->compareS(id, entry->id) == 0) {
            return entry;
        }
    }
    return NULL;
}

pANTLR3_UINT8 getAddrS(pANTLR3_VECTOR map, pANTLR3_STRING id) {
    id_entry_t* entry = getEntryS(map, id);
    return entry != NULL ? entry->addr->chars : NULL;
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
