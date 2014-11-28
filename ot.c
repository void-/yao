/**
 *  Oblivious transfer protocol.
 *
 *  Protocol implementation.
 *  -# Client says hello: "OT#i", where 'i' specifies this is the little-endian
 *     binary representing this is the ith OT preformed.
 *  -# Server sends (K, x0, x1): K a public key, x0, x1 blinding factors
 *  -# Client sends k: an encrypted symmetric key, blinded under either x.
 *  -# Server sends (C0, C1) : secrets 0 and 1 encrypted under k and k'.
 *  -# Client sends goodbye: "FN#i", where 'i' is the ith OT preformed.
 *
 *  Use RSA with blinding to mitigate problems with the RSA modulus.
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
#include <openssl/err.h>

/**
 *  Constants.
 *
 *  BUF_MAX the maximum number of bytes to read at once from a socket.
 *  HELLO_MSG the initial text of a hello message, without the sequence number.
 *  HELLO_SIZE the number of characters for a hello message.
 *  GOODBYE_MSG the terminating message, without the sequence number.
 *  GOODBYE_SIZE the number of characters for a goodbye message.
 *  PUB_BITS the number of bits to use for public keys.
 *  SERIAL_SIZE the number of bytes to represent a serialized public key.
 *  SYM_SIZE the number of bytes use for symmetric keys.
 */
#define BUF_MAX 512
#define HELLO_MSG "OT#"
#define HELLO_SIZE sizeof(HELLO_MSG) - 1 + sizeof(seq_t) //don't count null
#define GOODBYE_MSG "FN#"
#define GOODBYE_SIZE sizeof(GOODBYE_MSG) - 1 + sizeof(seq_t)
#define PUB_BITS 1024
#define SERIAL_SIZE 140
#define SYM_SIZE AES_BLOCK_SIZE

/**
 *  Errors.
 *
 *  EBAD_HELLO error when the hello message is bad.
 *  EBAD_GEN error when generating a key.
 *  EBAD_SEND error when sending a public key.
 *  EBAD_READ error when reading the encrypted symmetric key.
 *  EBAD_DECRYPT error when decrypting under the private key.
 *  EBAD_TRANSFER error when transfering either secret.
 *  EBAD_DERIVE error when deriving the symmetric key from plaintext.
 *  EBAD_RECEIVE error when reading serialized symmetric keys.
 *  EBAD_DECODE error when deserializing a public key.
 *  EBAD_ENCRYPT error when encrypting under a public key.
 *  EBAD_SIZE error when not enough bytes for writing a secret.
 *  EBAD_BYE error when the goodbye message is bad.
 */
#define EBAD_HELLO 2
#define EBAD_GEN 3
#define EBAD_SEND 4
#define EBAD_READ 5
#define EBAD_DECRYPT 6
#define EBAD_TRANSFER 7
#define EBAD_DERIVE 8
#define EBAD_RECEIVE 9
#define EBAD_DECODE 10
#define EBAD_ENCRYPT 11
#define EBAD_SIZE 12
#define EBAD_BYE 13

static int sendPublicKeys(RSA *, RSA *, int);
static ssize_t readExactly(int, void *, size_t);
static int sendSeq(int, const char *, size_t, seq_t);
static int getSeq(int, const char *, size_t, seq_t);

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
  int error = 0;
  RSA *k0 = NULL;
  RSA *k1 = NULL;

  unsigned char decryptBuffer[PUB_BITS/8];
  AES_KEY symKey0;
  AES_KEY symKey1;

  //read and check the hello message
  if(getSeq(socketfd, HELLO_MSG, sizeof(HELLO_MSG)-1, no))
  {
    debug("Hello msg/Sequence number didn't match\n");
    error = -EBAD_HELLO;
    goto send_done;
  }

  //generate and send two public keys
  if((k0 = RSA_generate_key(PUB_BITS, RSA_F4, NULL, NULL)) == NULL)
  {
    debug("Couldn't generate a public key\n");
    error = -EBAD_GEN;
    goto send_done;
  }
  if((k1 = RSA_generate_key(PUB_BITS, RSA_F4, NULL, NULL)) == NULL)
  {
    debug("Couldn't generate a public key\n");
    error = -EBAD_GEN;
    goto send_done;
  }

  if(sendPublicKeys(k0, k1, socketfd))
  {
    debug("Couldn't send public keys\n");
    error = -EBAD_SEND;
    goto send_done;
  }

  //read for the encrypted symmetric key
  if((count = readExactly(socketfd, buf, PUB_BITS/8)) < PUB_BITS/8)
  {
    debug("Couldn't read symmetric key, read %d\n", count);
    error = -EBAD_READ;
    goto send_done;
  }

  //decrypt under both private keys for two possible symmetric keys
  if((count = RSA_private_decrypt(PUB_BITS / 8, buf, decryptBuffer, k0,
        RSA_NO_PADDING)) < PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k0, got %d\n", count);
    error = -EBAD_DECRYPT;
    goto send_done;
  }
  if(AES_set_encrypt_key(decryptBuffer, SYM_SIZE*8, &symKey0))
  {
    debug("couldn't derive symmetric key0\n");
    error = -EBAD_DERIVE;
    goto send_done;
  }

  if((count = RSA_private_decrypt(PUB_BITS / 8, buf, decryptBuffer, k1,
        RSA_NO_PADDING)) < PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k1, got %d\n", count);
    ERR_load_crypto_strings();
    debug("error:%s\n", ERR_error_string(ERR_get_error(), NULL));
    error = -EBAD_DECRYPT;
    goto send_done;
  }
  if(AES_set_encrypt_key(decryptBuffer, SYM_SIZE*8, &symKey1))
  {
    debug("couldn't derive symmetric key1\n");
    error = -EBAD_DERIVE;
    goto send_done;
  }

  //encrypt and write both secrets
  AES_encrypt(secret0, buf, &symKey0);
  if(write(socketfd, buf, SYM_SIZE) != SYM_SIZE)
  {
    debug("Couldn't write secret0 \n");
    error = -EBAD_TRANSFER;
    goto send_done;
  }
  AES_encrypt(secret1, buf, &symKey0);
  if(write(socketfd, buf, SYM_SIZE) != SYM_SIZE)
  {
    debug("Couldn't write secret1 \n");
    error = -EBAD_TRANSFER;
    goto send_done;
  }

  //read and check the goodbye message
  if(getSeq(socketfd, GOODBYE_MSG, sizeof(GOODBYE_MSG)-1, no))
  {
    debug("Goodbye msg/Sequence number didn't match\n");
    error = -EBAD_BYE;
    goto send_done;
  }

send_done:
  //deallocate keys
  if(k0 != NULL)
  {
    RSA_free(k0);
  }
  if(k1 != NULL)
  {
    RSA_free(k1);
  }
  debug("error:%d\n");
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
  debug("OTreceive()#%d\n", no);
  unsigned char buf[BUF_MAX];
  int error = 0;
  ssize_t count;
  RSA *k;
  AES_KEY symKey;
  unsigned char keyBuffer[PUB_BITS/8];
  unsigned const char *tmpPtr = (buf+(SERIAL_SIZE * which));
  //unsigned const char *tmpPtr = buf;

  //must have enough bytes
  if(size < SYM_SIZE)
  {
    error = -EBAD_SIZE;
    goto rec_done;
  }

  //write hello
  if(sendSeq(socketfd, HELLO_MSG, sizeof(HELLO_MSG)-1, no) != HELLO_SIZE)
  {
    debug("Couldn't write hello;\n");
    error = -EBAD_HELLO;
    goto rec_done;
  }

  debug("trying to read a serialized key\n");
  //read serialized keys
  if((count = readExactly(socketfd, buf, 2*SERIAL_SIZE)) < 2*SERIAL_SIZE)
  {
    debug("couldn't read serialized public keys; read %d\n", count);
    error = -EBAD_RECEIVE;
    goto rec_done;
  }

  ////hexdump
  //for(i = 0; i < SERIAL_SIZE; ++i)
  //{
  //  putchar(buf[i]);
  //}

  //deserialize either public key
  if((k = d2i_RSAPublicKey(NULL,  &(tmpPtr), (long) SERIAL_SIZE)) == NULL)
  {
    debug("couldn't deserialize key %d properly\n", which);
    error = -EBAD_DECODE;
    goto rec_done;
  }

  //generate a padded symmetric key and encrypt it under k
  if(!RAND_bytes(keyBuffer, sizeof(keyBuffer)))
  {
    debug("couldn't generate random key\n");
    error = -EBAD_GEN;
    goto rec_done;
  }
  if((count = RSA_public_encrypt(sizeof(keyBuffer), keyBuffer, buf, k,
      RSA_NO_PADDING)) < RSA_size(k))
  {
    ERR_load_crypto_strings();
    debug("couldn't generate random key; got %d of %d bytes\n", count,
      sizeof(keyBuffer));
    debug("error:%s\n", ERR_error_string(ERR_get_error(), NULL));
    error = -EBAD_ENCRYPT;
    goto rec_done;
  }

  //send encrypted symmetric key
  if(write(socketfd, buf, PUB_BITS/8) != PUB_BITS/8)
  {
    debug("Couldn't send encrypted symmetric key\n");
    error = -EBAD_SEND;
    goto rec_done;
  }

  //derive a symmetric key from the first 128 bits
  if(AES_set_encrypt_key(keyBuffer, SYM_SIZE*8, &symKey))
  {
    debug("couldn't derive symmetric key1\n");
    error = -EBAD_DERIVE;
    goto rec_done;
  }

  //receive both encrypted secrets
  if((count = readExactly(socketfd, buf, 2*SYM_SIZE)) < 2*SYM_SIZE)
  {
    debug("received too few bytes from transfer; count = %d", count);
    error = -EBAD_TRANSFER;
    goto rec_done;
  }

  //decrypt either secret
  AES_decrypt(buf+(which*SYM_SIZE), output, &symKey);

  //write goodbye
  if(sendSeq(socketfd, GOODBYE_MSG, sizeof(GOODBYE_MSG)-1, no) != GOODBYE_SIZE)
  {
    debug("couldn't write goodbye, i=%d", no);
    error = -EBAD_BYE;
    goto rec_done;
  }

rec_done:
  debug("error:%d\n", error);
  return error;
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
static int sendPublicKeys(RSA *k0, RSA *k1, int fd)
{
  debug("sending k0\n");
  unsigned char buf[SERIAL_SIZE];
  unsigned char *bufPtr = buf;
  debug("serializing k0\n");
  int count = i2d_RSAPublicKey(k0, &bufPtr);
  debug("serialization complete\n");

  //check serialization length
  if(count != SERIAL_SIZE)
  {
    debug("Serialized the wrong number of bytes\n");
    return -1;
  }
  debug("count:%d\n", count);

  size_t i;
  //write k0
  if((i = write(fd, buf, count)) != count)
  {
    debug("Failed to write key 1; wrote %d\n", i);
    return -2;
  }
  debug("k0 sent\n");

  //serialize k1
  bufPtr = buf;
  debug("serializing k1\n");
  count = i2d_RSAPublicKey(k1, &bufPtr);
  debug("serialization complete\n");

  if(count != SERIAL_SIZE)
  {
    debug("Serialized the wrong number of bytes\n");
    return -3;
  }
  debug("count:%d\n", count);

  //write k1
  if((i = write(fd, buf, count)) != count)
  {
    debug("Failed to write key 1; wrote %d\n", i);
    return -4;
  }
  debug("k1 sent\n");

  return 0;
}

/**
 *  @brief send either the hello or goodbye message with the sequence number.
 *
 *  Write \p len bytes of \p msg to fd followed by the bytes of \p no.
 *
 *  NOTE: How the sequence number is written is endianness dependant.
 *  Fortunately if both computers are little-endian, this isn't a problem, but
 *  not something to be relied upon.
 * 
 *  @param fd file descriptor to write to.
 *  @param msg string to write first.
 *  @param len number of bytes of \p msg to write.
 *  @param no the sequence number to write.
 * 
 *  @return number of bytes written or -1 on failure.
 */
static int sendSeq(int fd, const char *msg, size_t len, seq_t no)
{
  //buffer the write all at once
  unsigned char buf[len+sizeof(seq_t)];
  size_t i;

  for(i = 0; i < len; ++i)
  {
    buf[i] = msg[i];
  }

  //create sequence number; NOTE: endianness dependant
  for(i = 0; i < sizeof(no); ++i)
  {
    buf[len+i] = ((unsigned char *)(&no))[i];
  }

  return write(fd, buf, len+sizeof(seq_t));
}

/**
 *  @brief read for a hello/goodbye message and verify its correctness.
 *
 *  NOTE: How the sequence number is read is endianness dependant. Fortunately
 *  if both computers are little-endian, this isn't a problem, but not
 *  something to be relied upon.
 *
 *  @param fd file descriptor to read from.
 *  @param msg the message to check.
 *  @param len the number of bytes from \p msg to check
 *  @param no the sequence number.
 *
 *  @return non-zero on failure.
 */
static int getSeq(int fd, const char *msg, size_t len, seq_t no)
{
  unsigned char buf[len+sizeof(no)];
  size_t count;
  size_t i;
  bool failure = false;

  //check length
  if((count = readExactly(fd, buf, len+sizeof(no))) < len+sizeof(no))
  {
    debug("seq wrong length; got %d, expected %d\n", count, len+sizeof(no));
    return -1;
  }

  //check message
  for(i = 0; i < len; ++i)
  {
    failure |= (msg[i] != buf[i]);
  }

  //check sequence number; NOTE: endianness dependant
  for(i = 0; i < sizeof(no); ++i)
  {
    failure |= (buf[len + i] != ((unsigned char *)(&no))[i]);
  }

  return failure;
}

/**
 *  @brief given a file descriptor read exactly \p count bytes or until error.
 *
 *  NOTE:
 *  - blocks until all bytes are read
 *  - no timeout on reading from \p fd.
 *
 *  @param fd file descriptor to read from.
 *  @param buf buffer to write to.
 *  @param count number of bytes to read from fd.
 *  @return the number of bytes read or -1 on failure.
 */
static ssize_t readExactly(int fd, void *buf, size_t count)
{
  ssize_t success;
  size_t left = count;
  size_t total = 0;
  debug("trying to read exactly %d bytes\n", count);
  while(total < count)
  {
    success = read(fd, buf+total, left);
    //debug("read %d bytes\n", success);
    if(success < 0)
    {
      return -1;
    }
    total += success;
    left -= success;
  }
  return count;
}
