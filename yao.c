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

int alice(sec_t secret, int socketfd)
{
}

int bob(sec_t secret, int socketfd)
{
}
