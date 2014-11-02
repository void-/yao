CC = "gcc"
LIBS = -lssl -lcrypto
BIN = "yao"
DOC_CONFIG = "docs/doxygenConfig"

main: main.c yao.o ot.o
	$(CC) main.c yao.o ot.o $(LIBS) -o $(BIN)
yao.o: yao.c yao.h
ot.o: ot.c ot.h

.PHONY: clean docs

clean:
	rm -f $(BIN) *.o
docs:
	doxygen $(DOC_CONFIG)
