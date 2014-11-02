#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fctnl.h>
#include <unistd.h>
#include <stdlib.h>

#include "yao.h"

/**
 *  Constants.
 *
 *  MAX_QUEUE the maximum number of connections to have queued waiting.
 */
#define MAX_QUEUE 2

/**
 *  Errors.
 *  
 *  EBAD_ARG error if the command line arguments are invalid.
 */
#define EBAD_ARG

static sec_t secret;

/**
 *  @brief determine whether to act as the server or client.
 *
 *  argv = binary secret host port
 *       = binary secret port 
 */
int main(int argc, char **argv)
{
  int error;
  if(argc < 3)
  {
    fprintf(stderr, "usage: %s secret [host] port\n", *argv);
    return -EBAD_ARG;
  }

  secret = atoi(argv[1]);
  error = (argc >= 4) ? client(argv[2], atoi(argv[3])) : server(atoi(argv[2]));
  secret = 0;

  return error;
}

/**
 *  @brief act as a server in the protocol.
 *
 *  @param portno the port number to listen on.
 *  @return non-zero on failure.
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

  error = alice(secret, connfd);

done:
  close(listenfd);
  close(connfd);
  return error;
}

/**
 *  @brief act as a client in the protocol.
 *
 *  @param host string representing the host name.
 *  @param portno the port number to connect to.
 *  @return non-zero on failure.
 */
int client(char *host, int portno)
{
  return 0;
}
