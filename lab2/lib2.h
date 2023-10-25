#ifndef HEADER_LIB2_H
#define HEADER_LIB2_H

#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include "../lab1/lib1.h"

typedef enum {
    EXPR, DIM, IF, BREAK, WHILE, DO_UNTIL, DO_WHILE
} statement_type;

struct cfg_node_struct;

typedef struct {
    pANTLR3_BASE_TREE tree;
} expr_t;

typedef struct {
    pANTLR3_BASE_TREE condExpr;
    struct cfg_node_struct* thenNode;
    struct cfg_node_struct* elseNode;
} if_t;

typedef struct {
    struct cfg_node_struct* loopExit;
    ANTLR3_UINT32 line;
    ANTLR3_UINT32 charPositionInLine;
} break_t;

typedef struct {
    pANTLR3_BASE_TREE cond;
    struct cfg_node_struct* body;
} loop_t;

typedef struct cfg_node_struct {
    statement_type type;
    struct cfg_node_struct* parent;
    struct cfg_node_struct* next;
    union {
        expr_t expr;
        if_t cond;
        break_t breakNode;
        loop_t loop;
    } u;
} cfg_node_t;

typedef struct {
    bool conditional;
    cfg_node_t* next;
    cfg_node_t* alternate;
} step_t;

typedef struct {
    pANTLR3_UINT8 sourceFile;
    pANTLR3_UINT8 name;
    pANTLR3_BASE_TREE signature;
    pANTLR3_VECTOR errors;
    cfg_node_t* cfgRoot;
} cfg_t;


const char *getTypeDesc(statement_type type);
pANTLR3_VECTOR createCfgs(ast_t* ast, pANTLR3_UINT8 sourceFile);
cfg_t* createCfgFromFuncNode(pANTLR3_BASE_TREE tree, pANTLR3_UINT8 sourceFile);
void walkCfg(cfg_node_t* root, void (*action)(cfg_node_t*, void *), void * data);
step_t getCfgStep(cfg_node_t* node);
void freeCfg(cfg_t* cfg);

#endif
