#ifndef YAO_H
#define YAO_H

/**
 *  sec_t used to represent the secret transfered in the protocol
 */
typedef int sec_t;

int alice(sec_t, int);
int bob(sec_t, int);

#endif //YAO_H
