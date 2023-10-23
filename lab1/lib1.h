#ifndef HEADER_LIB1_H
#define HEADER_LIB1_H

#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include "langLexer.h"
#include "langParser.h"

typedef struct AST_struct {
  pANTLR3_BASE_TREE tree;
  pANTLR3_VECTOR errors;
  pANTLR3_INPUT_STREAM input;
  pANTLR3_COMMON_TOKEN_STREAM tstream;
  plangParser psr;
  plangLexer lxr;
} ast_t;

void freeAst(ast_t *a);
ast_t* parseInputStream(pANTLR3_INPUT_STREAM input);
ast_t* parseFile(pANTLR3_UINT8 filepath);
ast_t* parseString(pANTLR3_UINT8 data, ANTLR3_UINT32 size, ANTLR3_UINT32 encoding, pANTLR3_UINT8 name);
#endif
