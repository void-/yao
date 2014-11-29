/**
 *  Oblivious transfer protocol.
 *
 *  Protocol implementation.
 *  -# Client says hello: "OT#i", where 'i' specifies this is the little-endian
 *     binary representing this is the ith OT preformed.
 *  -# Server sends (K, x0, x1): K a public key, x0, x1 blinding factors
 *  -# Client sends k: an encrypted symmetric key, blinded under either x.
 *  -# Server sends (C0, C1) : secrets 0 and 1 encrypted under decrypted k.
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
 *  EBAD_RECEIVE error when reading serialized public key or blinding factors.
 *  EBAD_DECODE error when deserializing a public key.
 *  EBAD_ENCRYPT error when encrypting under a public key.
 *  EBAD_SIZE error when not enough bytes for writing a secret.
 *  EBAD_BYE error when the goodbye message is bad.
 *  EBAD_BLIND error when generating a blinding factor.
 *  EBAD_ARITHM error when doing bignum arithmetic.
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
#define EBAD_BLIND 14
#define EBAD_ARITHM 15

static int sendPublicKey(RSA *, int);
static int sendBlindingFactors(BIGNUM *, BIGNUM *, int);
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
  RSA *k = NULL;
  BIGNUM *b0 = BN_new();
  BIGNUM *b1 = BN_new();
  BIGNUM *c = BN_new();

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

  //generate and send public key
  if((k = RSA_generate_key(PUB_BITS, RSA_F4, NULL, NULL)) == NULL)
  {
    debug("Couldn't generate a public key\n");
    error = -EBAD_GEN;
    goto send_done;
  }

  if(sendPublicKey(k, socketfd))
  {
    debug("Couldn't send public keys\n");
    error = -EBAD_SEND;
    goto send_done;
  }

  //generate and send both blinding factors
  if(!BN_rand_range(b0, k->n))
  {
    debug("Couldn't generate blinding factor 0\n");
    error = -EBAD_BLIND;
    goto send_done;
  }
  if(!BN_rand_range(b1, k->n))
  {
    debug("Couldn't generate blinding factor 1\n");
    error = -EBAD_BLIND;
    goto send_done;
  }

  if(count = sendBlindingFactors(b0, b1, socketfd))
  {
    debug("Couldn't send blinding factors ; got %d.\n", count);
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

  //encrypted symmetric key -> bignum
  if(BN_bin2bn(buf, PUB_BITS/8, c) != c)
  {
    debug("Couldn't create bignum from buffer");
    error = -EBAD_DECODE;
    goto send_done;
  }

  //b0 = c - b0 (mod n)
  if(!BN_mod_sub(b0, c, b0, k->n, NULL))
  {
    debug("Error subtracting blinding factor b0\n");
    error = -EBAD_ARITHM;
    goto send_done;
  }

  //b1 = c - b1 (mod n)
  if(!BN_mod_sub(b1, c, b1, k->n, NULL))
  {
    debug("Error subtracting blinding factor b1\n");
    error = -EBAD_ARITHM;
    goto send_done;
  }

  //b0 bignum -> buffer
  if((count = BN_bn2bin(b0, buf)) > PUB_BITS/8)
  {
    debug("Couldn't convert bignum b0 back to a buffer.\n");
    error = -EBAD_DECODE;
    goto send_done;
  }

  //buf -> bignum k
  //(k - b0 (mod N) ; k - b1 (mod N)) -> buf
  //decrypt buf

  //decrypt under private key
  if((count = RSA_private_decrypt(PUB_BITS / 8, buf, decryptBuffer, k,
        RSA_NO_PADDING)) < PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k and b0, got %d\n", count);
    ERR_load_crypto_strings();
    debug("error:%s\n", ERR_error_string(ERR_get_error(), NULL));
    error = -EBAD_DECRYPT;
    goto send_done;
  }
  if(AES_set_encrypt_key(decryptBuffer, SYM_SIZE*8, &symKey0))
  {
    debug("couldn't derive symmetric key0\n");
    error = -EBAD_DERIVE;
    goto send_done;
  }

  //b1 bignum -> buffer
  if((count = BN_bn2bin(b1, buf)) > PUB_BITS/8)
  {
    debug("Couldn't convert bignum b1 back to a buffer.\n");
    error = -EBAD_DECODE;
    goto send_done;
  }

  if((count = RSA_private_decrypt(PUB_BITS / 8, buf, decryptBuffer, k,
        RSA_NO_PADDING)) < PUB_BITS / 8)
  {
    debug("Couldn't decrypt with k and b1, got %d\n", count);
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
  //deallocate keys and bignums
  if(k != NULL)
  {
    RSA_free(k);
  }
  if(b0 != NULL)
  {
    BN_free(b0);
  }
  if(b1 != NULL)
  {
    BN_free(b1);
  }
  if(c != NULL)
  {
    BN_free(c);
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
  BIGNUM *b = BN_new();
  BIGNUM *p = BN_new();
  BN_CTX *bnTmp = BN_CTX_new();
  AES_KEY symKey;
  unsigned char keyBuffer[PUB_BITS/8] = {0};
  unsigned const char *tmpPtr = buf;
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
  //read serialized key and deserialize it
  if((count = readExactly(socketfd, buf, SERIAL_SIZE)) < SERIAL_SIZE)
  {
    debug("couldn't read serialized public keys; read %d\n", count);
    error = -EBAD_RECEIVE;
    goto rec_done;
  }
  if((k = d2i_RSAPublicKey(NULL,  &(tmpPtr), (long) SERIAL_SIZE)) == NULL)
  {
    debug("couldn't deserialize key %d properly\n", which);
    error = -EBAD_DECODE;
    goto rec_done;
  }

  //read blinding factors and deserialize either
  if((count = readExactly(socketfd, buf, (PUB_BITS/8)*2)) != (PUB_BITS/8)*2)
  {
    debug("Couldn't read blinding factors ; read %d", count);
    error = -EBAD_RECEIVE;
    goto rec_done;
  }
  debug("trying to turn buffer into bignum\n");
  if(BN_bin2bn(buf+((PUB_BITS/8)*which), PUB_BITS/8, b) != b)
  {
    debug("Error deserializing blinding factor\n");
    error = -EBAD_DECODE;
    goto rec_done;
  }

  debug("generating symmetric key\n");
  //generate a symmetric key through a bignum; encrypt and blind it
  if(!BN_rand_range(p, k->n))
  {
    debug("couldn't generate random key\n");
    error = -EBAD_GEN;
    goto rec_done;
  }
  debug("converting bignum to buffer\n");
  if((count = BN_bn2bin(p, keyBuffer)) > PUB_BITS/8)
  {
    debug("Couldn't convert bignum to buffer ; got %d.\n", count);
    error = -EBAD_DECODE;
    goto rec_done;
  }

  debug("deriving symmetric key from last 128 bits\n");
  //derive a symmetric key from the last 128 bits - big endian
  if(AES_set_encrypt_key(keyBuffer+((PUB_BITS/8) - SYM_SIZE - 1), SYM_SIZE*8,
      &symKey))
  {
    debug("couldn't derive symmetric key1\n");
    error = -EBAD_DERIVE;
    goto rec_done;
  }

  debug("encrypting under k\n");
  //encrypt padded symmetric key
  if((count = RSA_public_encrypt(PUB_BITS/8, keyBuffer, buf, k,
      RSA_NO_PADDING)) < PUB_BITS/8)
  {
    ERR_load_crypto_strings();
    debug("couldn't generate random key; got %d of %d bytes\n", count,
      sizeof(keyBuffer));
    debug("error:%s\n", ERR_error_string(ERR_get_error(), NULL));
    error = -EBAD_ENCRYPT;
    goto rec_done;
  }

  debug("converting ciphertext to bignum\n");
  //convert and blind symmetric key
  if(BN_bin2bn(keyBuffer, count, p) != p)
  {
    debug("could not convert symmetric key to bignum\n");
    error = EBAD_DECODE;
    goto rec_done;
  }

  debug("blinding ciphertext with blinding factor\n");
  if(!BN_mod_add(p, p, b, k->n, bnTmp))
  {
    debug("Error adding blinding factor, p+b\n");
    error = -EBAD_ARITHM;
    goto rec_done;
  }

  debug("serializing bn to buffer\n");
  //serialize p and send it
  if((count = BN_bn2bin(p, keyBuffer)) > PUB_BITS/8)
  {
    debug("Couldn't convert bignum to buffer.\n");
    error = -EBAD_DECODE;
    goto rec_done;
  }

  debug("writing blinded key\n");
  //send encrypted symmetric key
  if(write(socketfd, keyBuffer, PUB_BITS/8) != PUB_BITS/8)
  {
    debug("Couldn't send encrypted symmetric key\n");
    error = -EBAD_SEND;
    goto rec_done;
  }

  debug("reading secrets\n");
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
  //free big nums and key
  if(k != NULL)
  {
    RSA_free(k);
  }
  if(b != NULL)
  {
    BN_free(b);
  }
  if(p != NULL)
  {
    BN_free(p);
  }
  if(bnTmp != NULL)
  {
    BN_CTX_free(bnTmp);
  }
  debug("error:%d\n", error);
  return error;
}

/**
 *  @brief serialize two BIGNUM's(blinding factors) and write them to a socket.
 *
 *  NOTE:
 *  <p>
 *  - Both blinding factors must be representable in the same number of bytes.
 *  </p>
 *
 *  @param b0 pointer to bignum to send.
 *  @param b1 pointer to bignum to send.
 *  @param fd file descriptor to write to.
 *  @return non-zero on failure.
 */
static int sendBlindingFactors(BIGNUM *b0, BIGNUM *b1, int fd)
{
  int sz = BN_num_bytes(b0);
  int count;
  debug("blinding factor takes %d bytes\n", sz);
  unsigned char buf[sz];

  //zero buffer
  for(count = 0; count < sz; ++count)
  {
    buf[count] = 0;
  }

  //serialize b0
  if((count = BN_bn2bin(b0, buf)) > sz)
  {
    debug("serialzing b0 got sz:%d != count:%d bytes\n", sz, count);
    return -1;
  }

  //send b0
  if((count = write(fd, buf, sz)) != sz)
  {
    debug("Failed to write blinding factor 0, wrote %d\n", count);
    return -2;
  }

  //zero buffer
  for(count = 0; count < sz; ++count)
  {
    buf[count] = 0;
  }

  //serialize b1 ; < 128 bytes is ok because the higher order bytes can = 0
  if((count = BN_bn2bin(b1, buf)) > sz)
  {
    debug("serialzing b1 got %d bytes\n", count);
    return -3;
  }

  //send b1
  if((count = write(fd, buf, sz)) > sz)
  {
    debug("Failed to write blinding factor 1, wrote %d\n", count);
    return -4;
  }

  return 0;
}

/**
 *  @brief given a public key, serialize it and write it to a socket.
 *
 *  @param k pointer to RSA key to send.
 *  @param fd file descriptor to write to.
 *  @return non-zero on failure.
 */
static int sendPublicKey(RSA *k, int fd)
{
  debug("sending k\n");
  unsigned char buf[SERIAL_SIZE];
  unsigned char *bufPtr = buf;
  debug("serializing k\n");
  int count = i2d_RSAPublicKey(k, &bufPtr);
  debug("serialization complete\n");

  //check serialization length
  if(count != SERIAL_SIZE)
  {
    debug("Serialized the wrong number of bytes\n");
    return -1;
  }
  debug("count:%d\n", count);

  size_t i;
  //write k
  if((i = write(fd, buf, count)) != count)
  {
    debug("Failed to write key ; wrote %d\n", i);
    return -2;
  }
  debug("k sent\n");

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
