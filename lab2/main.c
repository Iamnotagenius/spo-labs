#include "../lab1/lib1.h"
#include <antlr3collections.h>
#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <bits/types/FILE.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include "lib2.h"

typedef struct {
    FILE* output;
    pANTLR3_UINT8 funcName;
} call_info_t;

void indent(int depth) {
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
}

void printExpr(pANTLR3_BASE_TREE exprTree, FILE* output) {
    pANTLR3_BASE_TREE child = exprTree->getChild(exprTree, 0);
    if (child && child->getType(child) == LParen) {
        pANTLR3_VECTOR args = child->children;
        fprintf(output, "%s(", exprTree->getText(exprTree)->chars);
        if (args && args->count > 0) {
            printExpr(args->get(args, 0), output);
            for (ANTLR3_UINT32 i = 1; i < args->count; i++) {
                fprintf(output, ", ");
                printExpr(args->get(args, i), output);
            }
        }
        fprintf(output, ")");
        return;
    }
    if (exprTree->getChildCount(exprTree) == 1) {
        fprintf(output, "%s", exprTree->getText(exprTree)->chars);
        printExpr(exprTree->getChild(exprTree, 0), output);
        return;
    }
    
    if (exprTree->getChildCount(exprTree) == 0) {
        if (exprTree->getType(exprTree) == String) {
            pANTLR3_STRING literal = exprTree->getText(exprTree);
            pANTLR3_STRING sub = literal->subString(literal, 1, literal->len - 1);
            fprintf(output, "\\\"%s\\\"", sub->chars);
            return;
        }
        fprintf(output, "%s", exprTree->getText(exprTree)->chars);
        return;
    }

    if (exprTree->getChildCount(exprTree) != 2) {
        fprintf(stderr, "Unknown operator: '%s'\n", exprTree->getText(exprTree)->chars);
        return;
    }

    printExpr(exprTree->getChild(exprTree, 0), output);
    fprintf(output, " %s ", exprTree->getText(exprTree)->chars);
    printExpr(exprTree->getChild(exprTree, 1), output);
}

void printDim(pANTLR3_BASE_TREE tree, FILE* output) {
    pANTLR3_VECTOR vars = tree->children;
    pANTLR3_BASE_TREE var = vars->get(vars, 0);
    fprintf(output, "dim %s", var->getText(var)->chars);
    for (ANTLR3_UINT32 i = 1; i < vars->count; i++) {
        var = vars->get(vars, i);
        fprintf(output, ", %s", var->getText(var)->chars);
    }
    fprintf(output, " as %s", tree->getText(tree)->chars);
}

void printCf(cfg_node_t* node, int depth) {
    if (node == NULL) {
        indent(depth);
        puts("<no body>");
        return;
    }
    while (node) {
        indent(depth);
        printf("%s (%p): ", getTypeDesc(node->type), node);
        switch (node->type) {
        case EXPR:
        case DIM:
            {
                expr_t e = node->u.expr;
                (node->type == DIM ? printDim : printExpr)(e.tree, stdout);
                printf("\n");
                break;
            }
        case IF:
            {
                if_t i = node->u.cond;
                printf("condition ");
                printExpr(i.condExpr, stdout);
                printf("\n");
                indent(depth);
                puts("then");
                printCf(i.thenNode, depth + 1);
                indent(depth);
                puts("else");
                printCf(i.elseNode, depth + 1);
                break;
            }
        case BREAK:
            printf("points to %p\n", node->u.breakNode.loopExit);
            break;
        case WHILE:
        case DO_UNTIL:
        case DO_WHILE:
            {
                loop_t l = node->u.loop;
                printf("condition ");
                printExpr(l.cond, stdout);
                printf("\n");
                printCf(l.body, depth + 1);
                break;
            }
            case ASSIGNMENT:
            {
                assignment_t a = node->u.assignment;
                printf("%s = ", a.identifier);
                printExpr(a.expr, stdout);
                break;
            }
        }
        node = node->next;
    }
}

void printCfinWalk(cfg_node_t* node, void* data) {
    if (node == NULL) {
        puts("<no body>");
        return;
    }

    printf("%s (%p): ", getTypeDesc(node->type), node);
    switch (node->type) {
        case EXPR:
        case DIM:
            {
                expr_t e = node->u.expr;
                (node->type == DIM ? printDim : printExpr)(e.tree, stdout);
                printf("\n");
                break;
            }
        case IF:
            {
                if_t i = node->u.cond;
                printf("condition ");
                printExpr(i.condExpr, stdout);
                printf("\n");
                break;
            }
        case BREAK:
            printf("points to %p\n", node->u.breakNode.loopExit);
            break;
        case WHILE:
        case DO_UNTIL:
        case DO_WHILE:
            {
                loop_t l = node->u.loop;
                printf("condition ");
                printExpr(l.cond, stdout);
                printf("\n");
                break;
            }
        case ASSIGNMENT:
            {
                assignment_t a = node->u.assignment;
                printf("%s = ", a.identifier);
                printExpr(a.expr, stdout);
            }
    }
}

void printEdge(FILE* output, cfg_node_t* node, step_t step) {
    fprintf(output, "    \"%p\" -> \"%p\" ", node, step.next);
    if (step.conditional) {
        fprintf(output, "[xlabel=true]\n");
        fprintf(output, "    \"%p\" -> \"%p\" [xlabel=false]", node, step.alternate);
    }
    fprintf(output, "\n");
    fprintf(output, "    \"%p\" [", node);
    if (step.conditional) {
        fprintf(output, "shape=diamond,");
    }
    fprintf(output, "label=\"");
    switch (node->type) {
    case EXPR:
        printExpr(node->u.expr.tree, output);
        break;
    case DIM:
        printDim(node->u.expr.tree, output);
        break;
    case IF:
        printExpr(node->u.cond.condExpr, output);
        break;
    case BREAK:
        fprintf(output, "break");
        break;
    case WHILE:
    case DO_UNTIL:
    case DO_WHILE:
        printExpr(node->u.loop.cond, output);
        break;
    case ASSIGNMENT:
        fprintf(output, "%s = ", node->u.assignment.identifier);
        printExpr(node->u.assignment.expr, output);
    }
    fprintf(output, "\"]\n");
}

void printEdgesInWalk(cfg_node_t* node, FILE* output) {
    step_t step = getCfgStep(node);
    printEdge(output, node, step);
}

void makeDotFromCfg(cfg_t* cfg, FILE* output) {
    fprintf(output, "digraph %s {\n    splines=ortho\n    node [shape=box,fontname=consolas]\n", cfg->name);
    walkCfg(cfg->cfgRoot, (void (*))printEdgesInWalk, output);
    fprintf(output, "}\n");
}

void printCallEdge(FILE* output, pANTLR3_BASE_TREE tree, pANTLR3_UINT8 funcName) {
    if (tree == NULL) {
        return;
    }
    pANTLR3_BASE_TREE child = tree->getChild(tree, 0);
    if (child != NULL && child->getType(child) == LParen) {
        fprintf(output, "    %s -> %s", funcName, tree->getText(tree)->chars);
    }
    if (tree->getChildCount(tree) > 0) {
        for (ANTLR3_UINT32 i = 0; i < tree->getChildCount(tree); i++) {
            pANTLR3_BASE_TREE child = tree->getChild(tree, i);
            printCallEdge(output, child, funcName);
        }
    }
}

void printCallGraphEdge(cfg_node_t* node, call_info_t* info) {
    pANTLR3_BASE_TREE expr;
    switch (node->type) {
    case EXPR:
        expr = node->u.expr.tree;
        break;
    case IF:
        expr = node->u.cond.condExpr;
        break;
    case DIM:
    case BREAK:
        expr = NULL;
        break;
    case WHILE:
    case DO_UNTIL:
    case DO_WHILE:
        expr = node->u.loop.cond;
        break;
    case ASSIGNMENT:
        expr = node->u.assignment.expr;
        break;
    }
    if (expr == NULL) {
        return;
    }
    printCallEdge(info->output, expr, info->funcName);
}

void makeCallGraph(pANTLR3_VECTOR cfgs, FILE* output) {
    fprintf(output, "digraph call {\n    node [shape=box,fontname=consolas]\n");
    call_info_t ci = {output};
    for (ANTLR3_UINT32 i = 0; i < cfgs->count; i++) {
        cfg_t* cfg = cfgs->get(cfgs, i);
        ci.funcName = cfg->name;
        walkCfg(cfg->cfgRoot, (void (*))printCallGraphEdge, &ci);
    }
    fprintf(output, "}\n");
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-o OUTPUT_DIR] INPUT1 [INPUT2...]\n", argv[0]);
        return 1;
    }
    char filepath[FILENAME_MAX];
    char* name = filepath;
    int argOffset = 0;
    if (strncmp(argv[1], "-o", 2) == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s [-o OUTPUT_DIR] INPUT1 [INPUT2...]\n", argv[0]);
            return 1;
        }
        argOffset = 3;
        name += sprintf(filepath, "%s/", argv[2]);
    }
    for (int i = argOffset; i < argc; i++) {
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
            cfg_t* cfg = cfgs->elements[i].element;
            printf("Cfg for %s from %s\n", cfg->name, cfg->sourceFile);
            if (cfg->errors->count > 0) {
                fprintf(stderr, "There were %d errors:\n", cfg->errors->count);
                for (ANTLR3_UINT32 i = 0; i < cfg->errors->count; i++) {
                    pANTLR3_STRING err = cfg->errors->get(cfg->errors, i);
                    fprintf(stderr, "%s\n", err->chars);
                }
            }
            /* printCf(cfg->cfgRoot, 1); */
            sprintf(name, "%s.%s.dot", cfg->sourceFile, cfg->name);
            FILE* dotFile = fopen(filepath, "w+");
            makeDotFromCfg(cfg, dotFile);
            fclose(dotFile);
        }
        sprintf(name, "%s.callGraph.dot", basename(argv[i]));
        FILE* callGraphFile = fopen(filepath, "w+");
        makeCallGraph(cfgs, callGraphFile);
        fclose(callGraphFile);
        freeAst(ast);
        cfgs->free(cfgs);
    }
}
