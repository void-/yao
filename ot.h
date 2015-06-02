#ifndef OT_H
#define OT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/aes.h>

typedef uint16_t seq_t;
#define SYM_SIZE AES_BLOCK_SIZE

int OTsend(unsigned char const *const, unsigned char const *const,
  const size_t, const seq_t, const int);
int OTreceive(unsigned char *const, const size_t, const bool, const seq_t,
  const int);
#endif //OT_H
