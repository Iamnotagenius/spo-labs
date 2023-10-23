#include <antlr3defs.h>
#include <stdio.h>
#include "lib1.h"

int main(int argc, char *argv[]) {
  pANTLR3_UINT8 fName;
  ast_t *langAST;
  if (argc < 3) {
      fprintf(stderr, "Usage: %s INPUT OUTPUT", argv[0]);
      return 1;
  }
  fName = (pANTLR3_UINT8)argv[1];
  langAST = parseFile(fName);
  if (langAST->tree == NULL) {
    fprintf(stdout, "Empty tree.\n");
    return 1;
  }
  if (langAST->errors->count > 0) {
    fprintf(stderr, "There were %d errors while parsing the input...\n",
            langAST->errors->count);
    for (ANTLR3_UINT32 i = 0; i < langAST->errors->count; i++) {
      fprintf(stderr, "%s\n",
              ((pANTLR3_STRING)langAST->errors->elements[i].element)->chars);
    }
    return 1;
  }
  pANTLR3_COMMON_TREE_NODE_STREAM nodes =
      antlr3CommonTreeNodeStreamNewTree(langAST->tree, ANTLR3_SIZE_HINT);
  FILE *graph = fopen(argv[2], "w+");
  fprintf(graph, "%s\n",
          nodes->adaptor->makeDot(nodes->adaptor, langAST->tree)->chars);
  fclose(graph);
  freeAst(langAST);
  return 0;
}
