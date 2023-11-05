#include "lib2.h"
#include "../lab1/lib1.h"
#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pANTLR3_VECTOR vars;
    pANTLR3_VECTOR errors;
    pANTLR3_STRING_FACTORY strFactory;
    pANTLR3_UINT8 sourceName;
} additional_data_t;

cfg_node_t* createNodesFromBody(pANTLR3_BASE_TREE body, cfg_node_t* parent, additional_data_t* data);
cfg_node_t* createNodeFromStatement(pANTLR3_BASE_TREE statement, cfg_node_t* parent, additional_data_t* data);
void appendPos(pANTLR3_STRING str, additional_data_t* data, ANTLR3_UINT32 line, ANTLR3_UINT32 charPos);
type_t parseTypeFromAst(pANTLR3_BASE_TREE tree);
void freeCfgNode(cfg_node_t* node);
void setNextForBreak(cfg_node_t* node, void* data);

void addError(additional_data_t* data, const char* message, ANTLR3_UINT32 line, ANTLR3_UINT32 charPositionInLine) {
    pANTLR3_STRING err = data->strFactory->newRaw(data->strFactory);
    appendPos(err, data, line, charPositionInLine);
    err->append(err, message);
    data->errors->add(data->errors, err, NULL);
}

const char *getTypeDesc(statement_type type) {
    switch (type) {
    case EXPR:      return "Expression";
    case DIM:       return "Dim";
    case IF:        return "If";
    case BREAK:     return "Break";
    case WHILE:     return "While";
    case DO_UNTIL:  return "Do until";
    case DO_WHILE:  return "Do while";
    case ASSIGNMENT:return "Assignment";
    }
}

pANTLR3_VECTOR createCfgs(ast_t* ast, pANTLR3_UINT8 sourceFile) {
    pANTLR3_VECTOR retval = antlr3VectorNew(sizeof(cfg_t*));
    for (ANTLR3_UINT32 i = 0; i < ast->tree->children->count; i++) {
        pANTLR3_BASE_TREE funcNode = ast->tree->children->elements[i].element;
        retval->add(retval, createCfgFromFuncNode(funcNode, sourceFile), (void (*)(void *))freeCfg);
    }
    return retval;
}

cfg_t* createCfgFromFuncNode(pANTLR3_BASE_TREE tree, pANTLR3_UINT8 sourceFile) {
    cfg_t* retval = malloc(sizeof(cfg_t));
    retval->sourceFile = sourceFile;
    retval->name = tree->getText(tree)->chars;
    retval->signature = tree->getFirstChildWithType(tree, Signature);
    pANTLR3_BASE_TREE body = tree->getFirstChildWithType(tree, Body);
    retval->errors = antlr3VectorNew(ANTLR3_SIZE_HINT);
    retval->vars = antlr3VectorNew(ANTLR3_SIZE_HINT);
    additional_data_t ed = {retval->vars, retval->errors, tree->strFactory, sourceFile};
    retval->cfgRoot = createNodesFromBody(body, NULL, &ed);
    walkCfg(retval->cfgRoot, setNextForBreak, &ed, NULL);
    return retval;
}

void appendPos(pANTLR3_STRING str, additional_data_t* data, ANTLR3_UINT32 line, ANTLR3_UINT32 charPos) {
    str->append(str, (const char *)data->sourceName);
    str->append(str, "(");
    str->addi(str, line);
    str->append(str, ":");
    str->addi(str, charPos);
    str->append(str, "): ");
}

cfg_node_t* createNodesFromBody(pANTLR3_BASE_TREE body, cfg_node_t* parent, additional_data_t* data) {
    if (body == NULL) {
        return NULL;
    }
    cfg_node_t* retval = malloc(sizeof(cfg_node_t));
    pANTLR3_VECTOR statements = body->children;
    cfg_node_t** pNext;
    pANTLR3_BASE_TREE stmt = statements->elements[0].element;
    retval = createNodeFromStatement(stmt, parent, data);
    pNext = &retval->next;
    for (ANTLR3_UINT32 i = 1; i < statements->count; i++) {
        pANTLR3_BASE_TREE stmt = statements->elements[i].element;
        cfg_node_t* current = createNodeFromStatement(stmt, parent, data);
        if (current->type == BREAK) {
            if (i < statements->count - 1) {
                addError(data, "warning: dead code after break", stmt->getLine(stmt), stmt->getCharPositionInLine(stmt));
            }
        }
        *pNext = current;
        pNext = &current->next;
    }
    *pNext = NULL;
    return retval;
}

cfg_node_t* createNodeFromStatement(pANTLR3_BASE_TREE statement, cfg_node_t* parent, additional_data_t* data) {
    if (statement == NULL) {
        return NULL;
    }

    cfg_node_t* retval = malloc(sizeof(cfg_node_t));
    retval->parent = parent;
    switch (statement->getType(statement)) {
        case Dim:
            {
                pANTLR3_BASE_TREE typeNode = statement->getChild(statement, 0);
                type_t type = parseTypeFromAst(typeNode);
                pANTLR3_VECTOR newIds = antlr3VectorNew(ANTLR3_SIZE_HINT);
                ANTLR3_UINT32 idsOffset = type.isArray ? 1 : 0;
                bool typeFound = false;
                for (ANTLR3_UINT32 i = 0; i < data->vars->count; i++) {
                    vars_t* vars = data->vars->get(data->vars, i);
                    if (!areTypesEqual(&vars->type, &type)) {
                        continue;
                    }
                    typeFound = true;
                    pANTLR3_VECTOR identifiers = typeNode->children;
                    for (ANTLR3_UINT32 i = idsOffset; i < identifiers->count; i++) {
                        pANTLR3_BASE_TREE idNode = identifiers->get(identifiers, i);
                        vars->identifiers->add(vars->identifiers, idNode->getText(idNode), NULL);
                        newIds->add(newIds, idNode->getText(idNode), NULL);
                    }
                }
                if (!typeFound) {
                    pANTLR3_VECTOR identifiers = typeNode->children;
                    for (ANTLR3_UINT32 i = idsOffset; i < identifiers->count; i++) {
                        pANTLR3_BASE_TREE idNode = identifiers->get(identifiers, i);
                        newIds->add(newIds, idNode->getText(idNode), NULL);
                    }
                    vars_t* new = malloc(sizeof(vars_t));
                    new->type = type;
                    new->identifiers = newIds;
                    data->vars->add(data->vars, new, free);
                }
                dim_t d = {type, newIds};
                retval->u.dim = d;
                retval->type = DIM;
                break;
            }
        case Expr:
            {
                retval->type = EXPR;
                expr_t e = {statement->getChild(statement, 0)};
                retval->u.expr = e;
                break;
            }
        case If:
            {
                retval->type = IF;
                if_t i = {
                    statement->getChild(statement, 0),
                    createNodesFromBody(statement->getChild(statement, 1), retval, data),
                    createNodesFromBody(statement->getChild(statement, 2), retval, data)
                };
                retval->u.cond = i;
                break;
            }
        case Break:
            {
                retval->type = BREAK;
                break_t b = {
                    NULL,
                    statement->getLine(statement),
                    statement->getCharPositionInLine(statement)
                };
                retval->u.breakNode = b;
                break;
            }
        case While:
            {
                retval->type = WHILE;
                loop_t l = {
                    statement->getChild(statement, 0),
                    createNodesFromBody(statement->getFirstChildWithType(statement, Body), retval, data)
                };
                retval->u.loop = l;
                break;
            }
        case Loop:
            {
                pANTLR3_BASE_TREE child = statement->getChild(statement, 0);
                switch (child->getType(child)) {
                    case While: retval->type = DO_WHILE; break;
                    case Until: retval->type = DO_UNTIL; break;
                }
                loop_t l = {
                    child->getChild(child, 0),
                    createNodesFromBody(statement->getFirstChildWithType(statement, Body), retval, data)
                };
                retval->u.loop = l;
                break;
            }
        case Assignment:
            {
                retval->type = ASSIGNMENT;
                pANTLR3_BASE_TREE identifierNode = statement->getChild(statement, 0);
                assignment_t a = {
                    identifierNode->getText(identifierNode)->chars,
                    statement->getChild(statement, 1)
                };
                retval->u.assignment = a;
            }

    }
    return retval;
}

void freeCfg(cfg_t* cfg) {
    cfg->errors->free(cfg->errors);
    freeCfgNode(cfg->cfgRoot);
    free(cfg);
}

void freeCfgNode(cfg_node_t* node) {
    if (node == NULL) {
        return;
    }
    cfg_node_t* tmp = node;
    while (node) {
        switch (node->type) {
            case IF:
                {
                    if_t i = node->u.cond;
                    freeCfgNode(i.thenNode);
                    freeCfgNode(i.elseNode);
                    break;
                }
            case WHILE:
            case DO_WHILE:
            case DO_UNTIL:
                {
                    loop_t l = node->u.loop;
                    freeCfgNode(l.body);
                    break;
                }
            case DIM:
            case EXPR:
            case BREAK:
            case ASSIGNMENT:
                break;
            }
        tmp = node->next;
        free(node);
        node = tmp;
    }
}

type_t parseTypeFromAst(pANTLR3_BASE_TREE tree) {
    pANTLR3_BASE_TREE arrayNode = tree->getFirstChildWithType(tree, Array);
    type_t retval = {tree->getText(tree), arrayNode != NULL};
    if (arrayNode != NULL) {
        retval.rank = arrayNode->getChildCount(arrayNode) + 1;
    }
    return retval;
}

bool areTypesEqual(type_t* first, type_t* second) {
    return first->identifier->compareS(first->identifier, second->identifier) == 0 &&
        first->isArray == second->isArray &&
        first->rank == second->rank;
}

cfg_node_t* getNextNode(cfg_node_t* node) {
    if (node == NULL) {
        return NULL;
    }
    cfg_node_t* next = node->next;
    if (next) {
        switch (next->type) {
            case DO_UNTIL:
            case DO_WHILE:
                return next->u.loop.body;
            default:
                return next;
        }
    }
    else if (node->parent) {
        cfg_node_t* parent = node->parent;
        switch (parent->type) {
            case WHILE:
            case DO_WHILE:
            case DO_UNTIL:
                return parent;
            default:
                break;
        }
    }
    return getNextNode(node->parent);
}

step_t getCfgStep(cfg_node_t* node) {
    if (node == NULL) {
        step_t s = {false, NULL, NULL};
        return s;
    }
    switch (node->type) {
    case ASSIGNMENT:
    case EXPR:
    case DIM:
        {
            step_t s = {false, getNextNode(node), NULL};
            return s;
        }
    case IF:
        {
            if_t i = node->u.cond;
            step_t s = {
                true,
                i.thenNode ? i.thenNode : getNextNode(node),
                i.elseNode ? i.elseNode : getNextNode(node)
            };
            if (!i.thenNode && !i.elseNode) {
                s.conditional = false;
                s.alternate = NULL;
            }
            return s;
        }
    case BREAK:
        {
            step_t s = {false, node->u.breakNode.loopExit, NULL};
            return s;
        }
    case WHILE:
    case DO_WHILE:
        {
            step_t s = {true, node->u.loop.body ? node->u.loop.body : node, getNextNode(node)};
            return s;
        }
    case DO_UNTIL:
        {
            step_t s = {true, getNextNode(node), node->u.loop.body ? node->u.loop.body : node};
            return s;
        }
    }
}

void walkCfg(cfg_node_t* root, void (*action)(cfg_node_t*, void *), void * data, void (*postAction)(cfg_node_t*, void *)) {
    if (root == NULL) {
        return;
    }
    while (root) {
        action(root, data);
        switch (root->type) {
            case IF:
                {
                    if_t i = root->u.cond;
                    walkCfg(i.thenNode, action, data, postAction);
                    walkCfg(i.elseNode, action, data, postAction);
                    break;
                }
            case WHILE:
            case DO_UNTIL:
            case DO_WHILE:
                {
                    loop_t l = root->u.loop;
                    walkCfg(l.body, action, data, postAction);
                    break;
                }
            default:
                break;
        }
        if (postAction) {
            postAction(root, data);
        }
        root = root->next;
    }
}

void setNextForBreak(cfg_node_t* node, void* data) {
    if (node->type != BREAK) {
        return;
    }
    cfg_node_t* loop = node->parent;
    while (loop) {
        switch (loop->type) {
            case WHILE:
            case DO_WHILE:
            case DO_UNTIL:
                node->u.breakNode.loopExit = loop->next;
                return;
            default:
                break;
        }
        loop = loop->parent;
    }
    addError(data,  "logic error: break usage outside of a loop", node->u.breakNode.line, node->u.breakNode.charPositionInLine);
}
