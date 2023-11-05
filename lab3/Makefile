LIB1_PATH=/home/iamnotagenius/Sources/spo_labs/lab1/lib
LIB2_PATH=/home/iamnotagenius/Sources/spo_labs/lab2/lib
LIBS=-l1 -l2 -lantlr3c
SOURCES=main.c lib3.c

.PHONY: all debug

all: a.out lib/lib3.so

a.out: $(SOURCES)
	${CC} $^ -L$(LIB1_PATH) -L$(LIB2_PATH) $(LIBS)

lib/lib3.so: $(SOURCES)
	[[ -d lib ]] || mkdir lib
	${CC} -shared -fPIC $^ -o $@

lab3.zip: $(SOURCES) input Makefile lib3.h
	7z a $@ $? 

debug: main.c lib3.c
	[ -d lib ] || mkdir lib
	${CC} -g $^ -L/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib -L$(LIB1_PATH) -L$(LIB2_PATH) -Wl,-rpath=$(LIB1_PATH):$(LIB2_PATH):/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib $(LIBS)
	${CC} -shared -o lib/lib3.so -g -fPIC $^ -L/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib -L$(LIB1_PATH) -L$(LIB2_PATH) -Wl,-rpath=$(LIB1_PATH):$(LIB2_PATH):/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib $(LIBS)
