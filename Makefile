CC = "gcc"
BIN = "yao"

ot.o: ot.c ot.h

.PHONY: clean

clean:
	rm -f $(BIN) *.o
