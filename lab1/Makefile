DEBUG_ANTLR3_PATH=/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib
SOURCES = lib1.c main.c
ANTLR3_HEADERS=langLexer.h langParser.h
ANTLR3_SOURCES=langLexer.c langParser.c
ANTLR3_ARTIFACTS=$(ANTLR3_HEADERS) $(ANTLR3_SOURCES)
LIBS=-lantlr3c

.PHONY: parser all

all: parser a.out lib/lib1.so

parser: $(ANTLR3_ARTIFACTS)

$(ANTLR3_ARTIFACTS): lang.g
	java -jar ./antlr-3.4-complete-no-antlrv2.jar $^

a.out: $(SOURCES) $(ANTLR3_SOURCES)
	${CC} $^ $(LIBS)

lib/lib1.so: lib1.c $(ANTLR3_SOURCES)
	[ -d lib ] || mkdir lib
	${CC} -shared -o lib/lib1.so -fPIC $^

debug: $(SOURCES) $(ANTLR3_SOURCES)
	${CC} -g $^ -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)
	${CC} -g -shared -o lib/lib1.so -fPIC $^ -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)

lab1.zip: $(SOURCES) $(ANTLR3_ARTIFACTS) Makefile lang.g input
	7z a $@ $?
