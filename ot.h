#ifndef OT_H
#define OT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/aes.h>

typedef uint16_t seq_t;
#define SYM_SIZE AES_BLOCK_SIZE

int OTsend(const unsigned char *, const unsigned char *, size_t, seq_t,
  int);
int OTreceive(unsigned char *, size_t, bool, seq_t, int);
#endif //OT_H
