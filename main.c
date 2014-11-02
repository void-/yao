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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fctnl.h>
#include <unistd.h>
#include <stdlib.h>

#include "ot.h"

/**
 *  Constants.
 *
 *  MAX_QUEUE the maximum number of connections to have queued waiting.
 */
#define MAX_QUEUE 2

int main(int argc, char **argv)
{

}

/**
 *  @brief act as a server in the protocol.
 *
 *  @param portno the port number to listen on.
 *  @return non-zero on success.
 */
int server(int portno)
{
  int error = 0;
  struct sockaddr_in servAddr;
  struct sockaddr_in cliAddr;
  unsigned cliLen = sizeof(cli_addr);
  int listenfd = socket(PF_INET, SOCK_STREAM, 0);
  int connfd = -1;
  int socketOption = 1;

  if(sockfd < 0)
  {
    error = -1;
    goto done;
  }

  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socketOption,
      sizeof(socketOption)))
  {
    error = -2;
    goto done;
  }

  memset((unsigned char *) &serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);
  if(bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
  {
    error = -3;
    goto done;
  }

  //listen for a connection
  listen(listenfd, MAX_QUEUE);
  if((connfd = accept(listenfd, (struct sockaddr *) &cli_addr, &clilen)) < 0)
  {
    error = -4;
    goto done;
  }

  //close the socket, only 1 connection is needed
  close(listenfd);

  error = alice(connfd);

done:
  close(listenfd);
  close(connfd);
  return error;
}
