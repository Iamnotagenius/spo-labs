DEBUG_ANTLR3_PATH=/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib
LIB1_PATH=../lab1/lib/lib1.so
LIB2_PATH=../lab2/lib/lib2.so
LIBS=-lantlr3c
SOURCES=main.c lib3.c

.PHONY: clean all debug

all: a.out lib/lib3.so test

a.out: $(SOURCES)
	${CC} $^ $(LIB1_PATH) $(LIB2_PATH) $(LIBS)

lib/lib3.so: $(SOURCES)
	[[ -d lib ]] || mkdir lib
	${CC} -shared -fPIC $^ -o $@

lab3.zip: $(SOURCES) input Makefile lib3.h test_call.c
	7z a $@ $? 

debug: main.c lib3.c
	[ -d lib ] || mkdir lib
	${CC} -g $^ -L$(DEBUG_ANTLR3_PATH) $(LIB1_PATH) $(LIB2_PATH) -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)
	${CC} -shared -o lib/lib3.so -g -fPIC $^ -L$(DEBUG_ANTLR3_PATH) $(LIB1_PATH) $(LIB2_PATH) -Wl,-rpath=$(DEBUG_ANTLR3_PATH) $(LIBS)

test: out.o test_call.c
	${CC} -o $@ $^ -g

out.o: out.asm
	nasm -g -felf64 $^

out.asm: a.out input
	./a.out input $@

clean:
	rm *.o out.asm test a.out
