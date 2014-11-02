CC = "gcc"
BIN = "yao"
DOC_CONFIG = "docs/doxygenConfig"

ot.o: ot.c ot.h

.PHONY: clean docs

clean:
	rm -f $(BIN) *.o
docs:
	doxygen $(DOC_CONFIG)
