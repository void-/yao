#ifndef YAO_H
#define YAO_H

/**
 *  sec_t used to represent the secret transfered in the protocol
 */
typedef int sec_t;

int alice(const sec_t, const int);
int bob(const sec_t, const int);

#endif //YAO_H
