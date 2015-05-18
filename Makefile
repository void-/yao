CC = "gcc"
LDFLAGS = -lcrypto
CFLAGS = -DDEBUG=1
BIN = "yao"
DOC_CONFIG = "docs/doxygenConfig"

main: main.c yao.o ot.o
	$(CC) $(CFLAGS) main.c yao.o ot.o $(LDFLAGS) -o $(BIN)
yao.o: yao.c yao.h
ot.o: ot.c ot.h

.PHONY: clean docs

clean:
	rm -f $(BIN) *.o
docs:
	doxygen $(DOC_CONFIG)
