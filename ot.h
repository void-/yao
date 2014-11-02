#ifndef OT_H
#define OT_H
#include <stdbool.h>
#include <stddef.h>

int OTsend(const unsigned char *, const unsigned char *, size_t, int);
int OTreceive(unsigned char *, size_t, bool, int);
#endif //OT_H
