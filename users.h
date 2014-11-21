#ifndef _USERS_H_
#define _USERS_H_

#include <time.h>
#include <sys/queue.h>

#include "protocol.h"

LIST_HEAD(userlist, reserved_port);

struct reserved_port {
  char *username;
  uid_t uid;
  int fd;
  int released;
  time_t reacquire_time;
  uint16_t port;
  char dont_reacquire;
  LIST_ENTRY(reserved_port) entries;
};

void users_init(void);
void users_sync(void);
void users_reacquire_ports(void);
int users_port_request(uid_t uid, uint16_t port);
int users_port_release(uid_t uid, uint16_t port);
int users_port_acquire_policy(uid_t uid, uint8_t dont_reacquire);
int users_port_list(uid_t uid, struct portinfo **info, uint16_t *len);
#endif
