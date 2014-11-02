/**
 *  Oblivious transfer protocol.
 *
 *  Protocol implementation.
 *  -# Client says hello: "OT#i", where 'i' specifies this is the little-endian
 *     binary representing this is the ith OT preformed.
 *  -# Server sends (K0, K1): two public keys
 *  -# Client sends Ck: a padded symmetric key encrypted under either K0 or K1.
 *  -# Server sends (C0, C1) : the symmetric encryption of secrets 0 and 1.
 *
 *  The public key encryption must not have any structured padding(e.g. PKCS#1
 *  or OAEP) otherwise the server could detect which secret the client is
 *  requesting.
 */

#include "ot.h"
#include <unistd.h>

#ifdef DEBUG
  #include <stdio.h>
  #define debug printf
#else
  #define debug
#endif //DEBUG

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/aes.h>

/**
 *  Constants.
 *
 *  BUF_MAX the maximum number of bytes to read at once from a socket.
 *  HELLO_MSG the initial text of a hello message, without the sequence number.
 *  HELLO_SIZE the number of characters for a hello message.
 *  PUB_BITS the number of bits to use for public keys.
 *  SERIAL_SIZE the number of bytes to represent a serialized public key.
 *  SYM_SIZE the number of bytes use for symmetric keys.
 */
#define BUF_MAX 512
#define HELLO_MSG "OT#"
#define HELLO_SIZE sizeof(HELLO_MSG) - 1 + sizeof(seq_t) //don't count null
#define PUB_BITS 1024
#define SERIAL_SIZE 140
#define SYM_SIZE AES_BLOCK_SIZE

/**
 *  Errors.
 *
 *  EBAD_HELLO error when the hello message is bad.
 *  EBAD_GEN error when generating a public key.
 *  EBAD_SEND error when sending a public key.
 *  EBAD_READ error when reading the encrypted symmetric key.
 *  EBAD_DECRYPT error when decrypting under the private key.
 */
#define EBAD_HELLO 2
#define EBAD_GEN 3
#define EBAD_SEND 4
#define EBAD_READ 5
#define EBAD_DECRYPT 6

static int sendPubicKeys(RSA *, RSA *, int);

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
  debug("OTsend()#%d\n", no);
  unsigned char buf[BUF_MAX];

  ssize_t count;
  bool success = true;
  int error = 0;
  size_t i;
  RSA *k0 = NULL;
  RSA *k1 = NULL;

  unsigned char symKey0[PUB_BITS/8];
  unsigned char symKey1[PUB_BITS/8];

  //check hello length
  if((count = read(socketfd, buf, HELLO_SIZE)) < HELLO_SIZE)
  {
    debug("count < HELLO_SIZE? %d\n", count < HELLO_SIZE);
    debug("Hello was wrong length; got %d, expected %d\n", count, HELLO_SIZE);
    error = -EBAD_HELLO;
    goto done;
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
    debug("Hello msg/Sequence number didn't match\n");
    error = -EBAD_HELLO;
    goto done;
  }

  //generate and send two public keys
  if((k0 = RSA_generate_key(PUB_BITS, RSA_F4, NULL, NULL)) == NULL)
  {
    debug("Couldn't generate a public key\n");
    error = -EBAD_GEN;
    goto done;
  }
  if((k1 = RSA_generate_key(PUB_BITS, RSA_F4, NULL, NULL)) == NULL)
  {
    debug("Couldn't generate a public key\n");
    error = -EBAD_GEN;
    goto done;
  }

  if(sendPubicKeys(k0, k1, socketfd))
  {
    debug("Couldn't send public keys\n");
    error = -EBAD_SEND;
    goto done;
  }

  //read for the encrypted symmetric key
  if((count = read(socketfd, buf, BUF_MAX)) < SYM_SIZE)
  {
    debug("Couldn't read symmetric key\n");
    error = -EBAD_READ;
    goto done;
  }

  //decrypt under both private keys for two possible symmetric keys
  if(RSA_private_decrypt(RSA_size(k0), buf, symKey0, k0, RSA_NO_PADDING) <
      PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k0\n");
    error = -EBAD_DECRYPT;
  }
  if(RSA_private_decrypt(RSA_size(k0), buf, symKey1, k1, RSA_NO_PADDING) <
      PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k0\n");
    error = -EBAD_DECRYPT;
  }

done:
  //deallocate keys
  if(k0 != NULL)
  {
    RSA_free(k0);
  }
  if(k1 != NULL)
  {
    RSA_free(k1);
  }
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

/**
 *  @brief given two public keys, serialize and write them to a socket.
 *
 *  NOTES:
 *  <p>
 *  - How are the serialized keys freed?
 *
 *  @param k0 pointer to RSA key to send.
 *  @param k1 pointer to RSA key to send.
 *  @param fd file descriptor to write to.
 *  @return non-zero on failure.
 */
static int sendPubicKeys(RSA *k0, RSA *k1, int fd)
{
  debug("sending public keys\n");
  unsigned char *buf0;
  unsigned char *buf1;
  int count0 = i2d_RSAPublicKey(k0, &buf0);
  int count1 = i2d_RSAPublicKey(k1, &buf1);

  //check serialization lengths
  if(count0 != SERIAL_SIZE || count1 != SERIAL_SIZE)
  {
    return -1;
  }

  //write keys
  if(write(fd, buf0, count0) != count0 || write(fd, buf1, count1) != count1)
  {
    return -3;
  }

  //how are buf0 and buf1 freed?
  return 0;
}
