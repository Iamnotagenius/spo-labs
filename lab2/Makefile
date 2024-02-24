DEBUG_ANTLR3_PATH=/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib
LIB1_PATH=../lab1/lib/lib1.so
LIBS=-lantlr3c
SOURCES=main.c lib2.c

.PHONY: all debug

all: a.out lib/lib2.so

a.out: $(SOURCES)
	${CC} $^ $(LIB1_PATH) $(LIBS)

lib/lib2.so: $(SOURCES)
	[ -d lib ] || mkdir lib
	${CC} -shared -fPIC $^ $(LIB1_PATH) -o $@

lab2.zip: $(SOURCES) input Makefile lib2.h
	7z a $@ $? 

debug: main.c lib2.c
	${CC} -g $^ -L$(DEBUG_ANTLR3_PATH) -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)
	${CC} -shared -o lib/lib2.so -g -fPIC $^ $(LIB1_PATH) -L$(DEBUG_ANTLR3_PATH) -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)
