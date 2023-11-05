LIB1_PATH=/home/iamnotagenius/Sources/spo_labs/lab1/lib
LIBS=-l1 -lantlr3c
SOURCES=main.c lib2.c

.PHONY: all debug

all: a.out lib/lib2.so

a.out: $(SOURCES)
	${CC} $^ -L$(LIB1_PATH) $(LIBS)

lib/lib2.so: $(SOURCES)
	[[ -d lib ]] || mkdir lib
	${CC} -shared -fPIC $^ -o $@

lab2.zip: $(SOURCES) input Makefile lib2.h
	7z a $@ $? 

debug: main.c lib2.c
	${CC} -g $^ -L/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib -L$(LIB1_PATH) -Wl,-rpath=$(LIB1_PATH):/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib $(LIBS)
	${CC} -shared -o lib/lib2.so -g -fPIC $^ -L/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib -L$(LIB1_PATH) -Wl,-rpath=$(LIB1_PATH):/home/iamnotagenius/Sources/spo_labs/libantlr3c-3.4/lib/lib $(LIBS)
