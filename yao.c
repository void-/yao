/**
 *  Yao's Millionaires problem implementation.
 *
 *  Pseudo-code.
 *  @code
 *  Let d = 32 //number of bits to represent fortunes
 *  Let k = 128 //number of bits for symmetric key in OT
 *
 *  Determine fortune from argv
 *  Determine from argv if we are Alice or Bob.
 *  Alice:
 *    pick a random u in (0,2k)
 *    pick a random v in [0,k]
 *    allocate matrix K size [d][2][k]
 *    allocate array S size [d][k]
 *
 *    for i in 0..(d - 1):
 *      for j in 0..1:
 *        for l in [v, k):
 *          k[i][j][l] = 0 or 1
 *      for j in [0, 2i]:
 *        k[i][ !fortune[i] ][j] = 0 or 1
 *      k[i][ !fortune[i] ][2i+1] = 1
 *      k[i][ !fortune[i] ][2i  ] = fortune[i]
 *      S[i] = random k bit number
 *
 *    S[d-1][k-2] = 1 ^ reduce(xor, S[0..d-1][k-2]) ^
 *      reduce(xor, K[0..d-1][0][k-2])
 *
 *    S[d-1][k-1] = 1 ^ reduce(xor, S[0..d-1][k-1]) ^
 *      reduce(xor, K[0..d-1][0][k-1])
 *
 *    for i in 0..(d - 1):
 *      for l in 0..1:
 *        K[i][l] = rol(K[i][l] ^ S[i], u)
 *
 *    N = rol(reduce(xor, S[0..d-1]), u)
 *
 *    listen for a connection from Bob
 *    send N
 *    for i in 0..(d-1)
 *      OTsend(K[i][0], K[i][1])
 *
 *  Bob:
 *    make a connection to Alice
 *    listen for N
 *    r = N ^ reduce(xor, map(OTreceive, fortune[0..d-1]))
 *
 *    look at r to determine if Alice's fortune > Bob's fortune
 *  @endcode
 */

#include <unistd.h>

#include "ot.h"
#include "yao.h"

/**
 *  Constants.
 *
 *  d number of bits needed to represent a secret.
 *  k number of bits needed to represent a symmetric oblivious transfer key.
 */
#define d (sizeof(sec_t) * 8)
#define k (SYM_SIZE * 8)

/**
 *  EBAD_GEN error when random number generation fails.
 *  EBAD_WRITE error when writing fails.
 *  EBAD_OT error if an OT fails.
 *  EBAD_READ error when reading fails.
 */
#define EBAD_GEN 2
#define EBAD_WRITE 3
#define EBAD_OT 4
#define EBAD_READ 5

#define fortuneI(f, i) ((f >> i) & 01)

#ifdef DEBUG
  #include <stdio.h>
  #define debug printf
#else
  #define debug
#endif //DEBUG

static void rol(bool [], size_t, size_t);
static void pack(bool [], unsigned char [], size_t);
static unsigned char boolToChar(bool *);
static void unpack(unsigned char *, bool *, size_t);
static void charToBool(unsigned char , bool *);

/**
 *  @brief act as Alice in the protocol.
 *
 *  @param secret the secret to compare in the protocol.
 *  @param socketfd file descriptor to write to for the protocol.
 */
int alice(sec_t secret, int socketfd)
{
  debug("called alice() with secret %d with fd %d\n", secret, socketfd);
  int error = 0;
  size_t u;
  size_t v;

  bool K[d][2][k] = {0};
  bool S[d][k] = {0};
  bool N[k] = {0};

  unsigned char packedSecret0[SYM_SIZE];
  unsigned char packedSecret1[SYM_SIZE];

  unsigned char buf[1];
  bool reduce;

  size_t i;
  size_t j;
  size_t l;
  size_t count;

  //pick random u in (0,2k) and v in [0,k]
  error |= RAND_bytes(&u, sizeof(u));
  u = 1 + u % ((2*k) - 1);
  error |= RAND_bytes(&v, sizeof(v));
  v = v % (k+1);

  debug("u:%d, v:%d\n",u,v);

  debug("alice(): beggining to fill matrix\n");
  for(i = 0; i < d; ++i)
  {
    for(j = 0; j < 2; ++j)
    {
      for(l = v; l < k; ++l)
      {
        error |= RAND_bytes(buf, sizeof(buf));
        //pick a random bit
        K[i][j][l] = (*buf) & 01;
      }
    }
    //debug("patterned higher matrix\n");

    for(j = 0; j <= 2*i; ++j)
    {
      error |= RAND_bytes(buf, sizeof(buf));
      K[i][!fortuneI(secret, i)][j] = (*buf) & 01;
    }
    K[i][!fortuneI(secret, i)][(2*i) + 1] = 1;
    K[i][!fortuneI(secret, i)][2*i] = fortuneI(secret, i);

    //S[i] should be a random k-bit number
    for(j = 0; j < k; ++j)
    {
      error |= RAND_bytes(buf, sizeof(buf));
      S[i][j] = (*buf) & 01;
    }
  }
  debug("alice(): filled matrix\n");

  if(error) //error if any random generations failed
  {
    debug("Error generating random bits\n");
    error = -EBAD_GEN;
    //goto done;
  }

  //compute S's k-2 bit
  reduce = 1;
  S[d-1][k-2] = 0;
  for(i = 0; i < d; ++i)
  {
    reduce ^= S[i][k-2] ^ K[i][0][k-2];
  }
  S[d-1][k-2] = reduce;

  //compute S's k-1 bit
  reduce = 1;
  S[d-1][k-1] = 0;
  for(i = 0; i < d; ++i)
  {
    reduce ^= S[i][k-1] ^ K[i][0][k-1];
  }
  S[d-1][k-1] = reduce;
  debug("computed higher order bits\n");

  //reduce and shift N
  for(i = 0; i < d; ++i)
  {
    for(j = 0; j < k; ++j)
    {
      N[j] ^= S[i][j];
    }
  }
  debug("Reduced N\n");
  rol(N, sizeof(N), u);
  debug("rol()'d N\n");

  //send N
  if((count = write(socketfd, N, sizeof(N))) != sizeof(N))
  {
    debug("Couldn't write N; read %d bytes\n", count);
    error = -EBAD_WRITE;
    goto done;
  }

  debug("starting oblivious transfers\n");
  //do OTs
  for(i = 0; i < d; ++i)
  {
    if(OTsend((unsigned char *)K[i][0], (unsigned char *)K[i][1], k, i,
        socketfd))
    {
      debug("OTsend() failed on i=%d\n", i);
      error = -EBAD_OT;
      goto done;
    }
    debug("OT %d complete\n", i);
  }

  debug("Oblivious transfers complete\n");

done:
  debug("error:%d\n", error);
  return error;
}

/**
 *  @brief act as Bob in the protocol.
 *
 *  @param secret the secret to compare in the protocol.
 *  @param socketfd file descriptor to read and write during the protocol.
 *  @return non-zero on failure, 1 if a >= b, 0 if b > a.
 */
int bob(sec_t secret, int socketfd)
{
  debug("called bob() with secret %d with fd %d\n", secret, socketfd);
  int error = 0;
  bool N[k];
  size_t count;
  size_t i;
  size_t j;
  //unsigned char buf[SYM_SIZE];
  bool bitBuf[k];

  //read N
  if((count = read(socketfd, N, sizeof(N))) != sizeof(N))
  {
    debug("Couldn't read N; read %d bytes\n", count);
    error = -EBAD_READ;
    goto done;
  }

  //OT's
  for(i = 0; i < d; ++i)
  {
    if(OTreceive((unsigned char *) bitBuf, sizeof(bitBuf), fortuneI(secret, i),
        i, socketfd))
    {
      debug("OTreceive() failed on i=%d\n", i);
      error = -EBAD_OT;
      goto done;
    }
    for(j = 0; j < k; ++j)
    {
      N[j] = bitBuf[j] ^ N[j];
    }
  }

  //lookAt r = N
  count = 0;
  for(i = sizeof(N) - 1; i; --i)
  {
    debug("%d", N[i]);
    //apply a bad heuristic
    count += (N[i] == 0);
    if(count > 2)
    {
      break;
    }
  }

  //apply bad heuristic again
  error = (N[i-1] == 1);

done:
  debug("error: %d\n", error);
  return error;
}

/**
 *  @brief cyclic left shift a bit array by \p u.
 *
 *  \p n will be mutated.
 *
 *  @param n bit array to mutate by left shifting.
 *  @param size, in bits, of \p n.
 *  @param shift, ammount to shift \n by.
 */
static void rol(bool n[], size_t size, size_t shift)
{
  size_t i;
  bool highBit;
  while(shift--)
  {
    highBit = n[size-1]; //save the highbit
    for(i = size-1; i; --i)
    {
      n[i] = n[i-1];
    }
    n[0] = highBit;
  }
}

/**
 *  @brief pack a bool array into a blob.
 *
 *  @param a the bool array to read data from.
 *  @param b the char array to pack the data into.
 *  @param len the size, in bits, of a.
 */
static void pack(bool a[], unsigned char b[], size_t len)
{
  size_t i;

  for(i = 0; i < (len/sizeof(unsigned char)); ++i)
  {
    b[i] = boolToChar(a+(8*i));
  }
}

/**
 *  @brief turn an 8 element bool array into a single unsigned char.
 *
 *  No bounds checking is preformed.
 *
 *  @param in bool array to read.
 *  @return packed unsigned char of \p in[0..7].
 */
static unsigned char boolToChar(bool *in)
{
  unsigned char out;
  out = in[0]      |
        in[1] << 1 |
        in[2] << 2 |
        in[3] << 3 |
        in[4] << 4 |
        in[5] << 5 |
        in[6] << 6 |
        in[7] << 7 ;
  return out;
}

/**
 *  @brief unpack an array of chars into an array of bits.
 *
 *  @param buf the char array to read from.
 *  @param bitBuf the bool array to unpack into.
 *  @param the size, in bits, of \p bitBuf.
 */
static void unpack(unsigned char *buf, bool *bitBuf, size_t size)
{
  size_t i;
  for(i = 0; i < (size / (8 * sizeof(unsigned char))); ++i)
  {
    charToBool(buf[i], bitBuf+(8*i));
  }
}

/**
 *  @brief unpack 8 bits from a char into a bool array.
 *
 *  No bounds checks are preformed.
 *
 *  @param c the char to read.
 *  @param bitBuf the bool array to write into.
 */
static void charToBool(unsigned char c, bool *bitBuf)
{
  size_t i;
  for(i = 0; i < 8 * sizeof(unsigned char); ++i)
  {
    bitBuf[i] = (c >> i) & 01;
  }
}
