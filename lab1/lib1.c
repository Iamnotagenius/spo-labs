#include "lib1.h"
#include <antlr3defs.h>

typedef struct {
  ANTLR3_BASE_RECOGNIZER rec;
  pANTLR3_VECTOR errors;
  pANTLR3_STRING_FACTORY strFactory;
} ext_rec;

void freeAst(ast_t *a) {
  a->errors->free(a->errors);
  a->psr->free(a->psr);
  a->lxr->free(a->lxr);
  a->tstream->free(a->tstream);
  a->input->free(a->input);
  free(a);
}

pANTLR3_STRING createErrorMessage(pANTLR3_BASE_RECOGNIZER rec) {
  pANTLR3_EXCEPTION ex = rec->state->exception;
  pANTLR3_STRING_FACTORY factory = ((ext_rec *)rec)->strFactory;
  pANTLR3_STRING str = factory->newRaw(factory);
  pANTLR3_UINT8 (*append)(pANTLR3_STRING, const char *) = str->append;
  pANTLR3_UINT8 (*appendS)(pANTLR3_STRING, pANTLR3_STRING) = str->appendS;
  if (ex->streamName == NULL) {
    if (((pANTLR3_COMMON_TOKEN)(ex->token))->type == ANTLR3_TOKEN_EOF) {
      append(str, "-end of-input-(");
    } else {
      append(str, "-unknown source-(");
    }
  } else {
    appendS(str, ex->streamName->to8(ex->streamName));
    append(str, "(");
  }

  str->addi(str, ex->line);
  append(str, ":");
  str->addi(str, ex->charPositionInLine);
  append(str, "): ");
  switch (ex->type) {
  case ANTLR3_UNWANTED_TOKEN_EXCEPTION:
    if (rec->state->tokenNames == NULL) {
      append(str, "Extraneous input...");
    } else {
      append(str, "Extraneous input - expected ");
      if (ex->expecting == ANTLR3_TOKEN_EOF) {
        append(str, "<EOF>");
      } else {
        append(str, (const char *)rec->state->tokenNames[ex->expecting]);
      }
    }
    break;
  case ANTLR3_MISSING_TOKEN_EXCEPTION:
    append(str, "Missing ");
    if (rec->state->tokenNames == NULL) {
      append(str, "token (");
      str->addi(str, ex->expecting);
      append(str, ")");
    } else {
      if (ex->expecting == ANTLR3_TOKEN_EOF) {
        append(str, "<EOF>");
      } else {
        append(str, (const char *)rec->state->tokenNames[ex->expecting]);
      }
    }
    break;
  case ANTLR3_RECOGNITION_EXCEPTION:
    append(str, "syntax error...");
    break;
  case ANTLR3_MISMATCHED_TOKEN_EXCEPTION:
    if (rec->state->tokenNames == NULL) {
      append(str, "syntax error...");
    } else {
      append(str, "expected ");
      if (ex->expecting == ANTLR3_TOKEN_EOF) {
        append(str, "<EOF>");
      } else {
        append(str, (const char *)rec->state->tokenNames[ex->expecting]);
      }
    }
    break;
  case ANTLR3_NO_VIABLE_ALT_EXCEPTION:

    // We could not pick any alt decision from the input given
    // so god knows what happened - however when you examine your grammar,
    // you should. It means that at the point where the current token occurred
    // that the DFA indicates nowhere to go from here.
    //
    append(str, "cannot match to any predicted input...");
    break;
  case ANTLR3_MISMATCHED_SET_EXCEPTION: {
    ANTLR3_UINT32 count;
    ANTLR3_UINT32 bit;
    ANTLR3_UINT32 size;
    ANTLR3_UINT32 numbits;
    pANTLR3_BITSET errBits;

    // This means we were able to deal with one of a set of
    // possible tokens at this point, but we did not see any
    // member of that set.
    //
    append(str, "unexpected input... expected one of: ");

    // What tokens could we have accepted at this point in the
    // parse?
    //
    count = 0;
    errBits = antlr3BitsetLoad(ex->expectingSet);
    numbits = errBits->numBits(errBits);
    size = errBits->size(errBits);

    if (size > 0) {
      // However many tokens we could have dealt with here, it is usually
      // not useful to print ALL of the set here. I arbitrarily chose 8
      // here, but you should do whatever makes sense for you of course.
      // No token number 0, so look for bit 1 and on.
      //
      for (bit = 1; bit < numbits && count < 8 && count < size; bit++) {
        // TODO: This doesn't look right - should be asking if the bit is set!!
        //
        if (rec->state->tokenNames[bit]) {
          if (count > 0) {
            append(str, ", ");
          }
          append(str, (const char *)rec->state->tokenNames[bit]);
          count++;
        }
      }
    } else {
      append(str, "nothing is expected here.");
    }
    break;
  }
  case ANTLR3_EARLY_EXIT_EXCEPTION:
    // We entered a loop requiring a number of token sequences
    // but found a token that ended that sequence earlier than
    // we should have done.
    append(str, "missing elements...");
    break;

  default:
    // We don't handle any other exceptions here, but you can
    // if you wish. If we get an exception that hits this point
    // then we are just going to report what we know about the
    // token.
    //
    append(str, "syntax not recognized...");
    break;
  }

  return str;
}

static void saveError(pANTLR3_BASE_RECOGNIZER recognizer) {
  // Invoke the debugger event if there is a debugger listening to us
  //
  ext_rec *extended = (ext_rec *)recognizer;
  if (recognizer->debugger != NULL) {
    recognizer->debugger->recognitionException(recognizer->debugger,
                                               recognizer->state->exception);
  }

  if (recognizer->state->errorRecovery == ANTLR3_TRUE) {
    // Already in error recovery so don't display another error while doing so
    return;
  }

  // Signal we are in error recovery now
  //
  recognizer->state->errorRecovery = ANTLR3_TRUE;

  // Indicate this recognizer had an error while processing.
  //
  recognizer->state->errorCount++;
  extended->errors->add(extended->errors, createErrorMessage(recognizer),
                        NULL);
  recognizer->displayRecognitionError(recognizer, recognizer->state->tokenNames);
}

ext_rec *extendRecognizer(pANTLR3_BASE_RECOGNIZER *rec) {
  ext_rec *new = ANTLR3_CALLOC(1, sizeof(ext_rec));
  new->rec = **rec;
  new->errors = antlr3VectorNew(ANTLR3_SIZE_HINT);
  new->strFactory = antlr3StringFactoryNew(ANTLR3_ENC_UTF8);
  free(*rec);
  *rec = (pANTLR3_BASE_RECOGNIZER) new;
  (*rec)->reportError = saveError;
  return new;
}

void extendParserRecognizer(plangParser psr) {
  extendRecognizer(&psr->pParser->rec);
}

void extendLexerRecognizer(plangLexer lxr) {
  extendRecognizer(&lxr->pLexer->rec);
}

ast_t *parseInputStream(pANTLR3_INPUT_STREAM input) {
  plangLexer lxr;
  pANTLR3_COMMON_TOKEN_STREAM tstream;
  plangParser psr;
  langParser_source_return langAST;
  input->strFactory = antlr3StringFactoryNew(input->encoding);
  lxr = langLexerNew(input);
  if (lxr == NULL) {
    ANTLR3_FPRINTF(stderr,
                   "Unable to create the lexer due to malloc() failure!\n");
    exit(ANTLR3_ERR_NOMEM);
  }
  /* extendLexerRecognizer(lxr); */

  tstream = antlr3CommonTokenStreamSourceNew(
      ANTLR3_SIZE_HINT, lxr->pLexer->rec->state->tokSource);

  if (tstream == NULL) {
    ANTLR3_FPRINTF(stderr, "Out of memory trying to allocate token stream\n");
    exit(ANTLR3_ERR_NOMEM);
  }
  psr = langParserNew(tstream);

  if (psr == NULL) {
    ANTLR3_FPRINTF(stderr, "Out of memory trying to allocate parser\n");
    exit(ANTLR3_ERR_NOMEM);
  }
  extendParserRecognizer(psr);
  langAST = psr->source(psr);

  ast_t *retval = malloc(sizeof(ast_t));
  retval->errors = ((ext_rec *)psr->pParser->rec)->errors;
  retval->tree = langAST.tree;
  retval->psr = psr;
  retval->lxr = lxr;
  retval->tstream = tstream;
  retval->input = input;
  return retval;
}

ast_t* parseFile(ANTLR3_UINT8 *filepath) {
    return parseInputStream(antlr3FileStreamNew(filepath, ANTLR3_ENC_UTF8));
}

ast_t* parseString(pANTLR3_UINT8 data, ANTLR3_UINT32 size, ANTLR3_UINT32 encoding, pANTLR3_UINT8 name) {
    return parseInputStream(antlr3StringStreamNew(data, encoding, size, name));
}
