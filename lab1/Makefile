SOURCES = lib1.c main.c
ANTLR3_HEADERS=langLexer.h langParser.h
ANTLR3_SOURCES=langLexer.c langParser.c
ANTLR3_ARTIFACTS=$(ANTLR3_HEADERS) $(ANTLR3_SOURCES)
LIBS=-lantlr3c

.PHONY: parser all debug

all: parser a.out

parser: $(ANTLR3_ARTIFACTS)

$(ANTLR3_ARTIFACTS): lang.g
	java -jar ./antlr-3.4-complete-no-antlrv2.jar $^

a.out: $(SOURCES) $(ANTLR3_SOURCES)
	${CC} $(LIBS) $^

debug: $(SOURCES) $(ANTLR3_SOURCES)
	${CC} -g $^ -Wl,-rpath=/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib $(LIBS)
