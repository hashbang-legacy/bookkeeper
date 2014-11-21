#ifndef _CONFIG_H
#define CONFIG_H

struct config {
  int system_user_threshold;
  int port_offset;
  char *user;
  char *sockfile;
  uid_t uid;
  gid_t gid;
};

#define DEFAULT_SOCKPATH "/var/run/bookkeeper/bookkeeper.sock"
#define DEFAULT_REACQUIRE_TIMEOUT 7200
#define PRIVPORTS 1024

#endif
