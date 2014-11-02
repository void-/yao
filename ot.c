/**
 *  Oblivious transfer protocol.
 *
 *  Protocol implementation.
 *  -# Client says hello: "OT#i", where `i' specifies this is the little-endian
 *     binary representing this is the ith OT preformed.
 *  -# Server sends (K0, K1): two public keys
 *  -# Client sends Ck: a padded symmetric key encrypted under either K0 or K1.
 *  -# Server sends (C0, C1) : the symmetric encryption of secrets 0 and 1.
 */

#include "ot.h"
#include <unistd.h>

/**
 *  BUF_MAX the maximum number of bytes to read at once from a socket.
 *  HELLO_MSG the initial text of a hello message, without the sequence number.
 *  HELLO_SIZE the number of characters for a hello message.
 */
#define BUF_MAX 512
#define HELLO_MSG "OT#"
#define HELLO_SIZE sizeof(HELLO_MSG) - 1 + sizeof(seq_t) //don't count null
#define PUB_BITS 1024

#define EBAD_HELLO 2

/**
 *  @brief send one of two secrets via an oblivious transfer given a socket.
 *
 *  Important parameter notes:
 *  <p>
 *  - The ordering of the secrets may be important.
 *  - \p secret0 and \p secret1 must both be \p size bytes.
 *  - \p size must be less than or equal to the size of one symmetric block.
 *  - \p socketfd must be a file descriptor for an already opened connection.
 *  - \p no should be incremented between calls to OTSend() on both computers.
 *  </p>
 *
 *  @param secret0 buffer of \p size bytes containing the first secret.
 *  @param secret1 buffer of \p size bytes containing the first secret.
 *  @param size number of bytes held in both \p secret0 and \p secret1.
 *  @param no sequence number of which iteration of oblivious transfer this is.
 *  @param socketfd file descriptor to the socket to use for the connection.
 *  @return non-zero on failure.
 */
int OTsend(const unsigned char *secret0, const unsigned char *secret1,
    size_t size, seq_t no, int socketfd)
{
  unsigned char buf[BUF_MAX];

  ssize_t count;
  bool success = true;
  int error = 0;
  size_t i;
  RSA k0;
  RSA k1;
  BIGNUM e;

  count = read(socketfd, buf, BUF_MAX);
  //check hello length
  if(count < HELLO_SIZE)
  {
    return -EBAD_HELLO;
  }

  //check hello message
  for(i = 0; i < sizeof(HELLO_MSG); ++i)
  {
    success = success & (HELLO_MSG[i] == buf[i]);
  }

  //check sequence number; NOTE: endianness dependant
  for(; i < HELLO_SIZE; ++i)
  {
    success = success &
      (buf[i] == ((unsigned char *)(&no))[i - sizeof(HELLO_MSG)]);
  }

  if(!success)
  {
    error = -EBAD_HELLO;
    goto done;
  }

  //initialize the public exponent
  BN_init(&e);
  BN_set_word(&e, RSA_F4);

  //generate and send two public keys
  RSA_generate_key_ex(&k0, PUB_BITS, &e, NULL);
  RSA_generate_key_ex(&k1, PUB_BITS, &e, NULL);

  done:
    bn_free(&e);
    return error;
}

/**
 *  @brief receive a given secret in an oblivious transfer.
 *
 *  Important parameter notes:
 *  <p>
 *  - \p size must be greater than or equal to the size of one symmetric block.
 *  - \p no should be incremented between calls to OTreceive() like OTsend().
 *  </p>
 *
 *  @param output buffer of size \p size to write the secret to.
 *  @param size the number of bytes that \p output can hold.
 *  @param which the secret number to receive: either secret 0 or secret 1.
 *  @param socketfd file descriptor to the socket to use for the connection.
 *  @param no sequence number of which iteration of oblivious transfer this is.
 *  @return non-zero on failure.
 */
int OTreceive(unsigned char *output, size_t size, bool which, seq_t no,
    int socketfd)
{
}
