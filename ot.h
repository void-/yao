#ifndef OT_H
#define OT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int OTsend(const unsigned char *, const unsigned char *, size_t, uint16_t,
  int);
int OTreceive(unsigned char *, size_t, bool, uint16_t, int);
#endif //OT_H
