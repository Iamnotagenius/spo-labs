XED_DIR=/home/iamnotagenius/Sources/spo-labs/build/kits/xed-install-base-2024-02-24-lin-x86-64
XED_ARGS=-I$(XED_DIR)/include -L$(XED_DIR)/lib
SRC=main.c lists.c
LIBS=-lxed -lantlr3c
LIBUNWIND=-lunwind -lunwind-ptrace -lunwind-x86_64

.PHONY: all debug with-unwind

all: a.out

a.out: $(SRC)
	${CC} $^ $(XED_ARGS) $(LIBS)


debug: $(SRC)
	${CC} -g $^ $(XED_ARGS) $(LIBS)

with-unwind: $(SRC)
	${CC} -DUSE_LIBUNWIND $^ $(XED_ARGS) $(LIBS) $(LIBUNWIND)
