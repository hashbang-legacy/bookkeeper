#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "config.h"
#include "users.h"

extern struct config config;

static struct userlist ulist;
static int ulistnum = 0;

static const char *user_blacklist[] = {
  "nfsnobody",
  "nobody",
  NULL,
};

static int users_port_bind(
    uint16_t port,
    char try)
{
  struct addrinfo *ai, hints;
  char s_port[64];
  int fd = -1;
  int rc;

  memset(&hints, 0, sizeof(hints));
  memset(s_port, 0, sizeof(s_port));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET6;
  snprintf(s_port, 64, "%hu", port);

  if (port < PRIVPORTS || port > 65535) {
    syslog(LOG_WARNING, "Cannot bind to port %d, invalid port range: %s", port, strerror(errno));
    return -1;
  }

  rc = getaddrinfo(NULL, s_port, &hints, &ai);
  if (rc) {
    syslog(LOG_WARNING, "Cannot resolve address to bind to: %s", gai_strerror(rc));
    return -1;
  }

  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    syslog(LOG_WARNING, "Cannot allocate socket: %s", strerror(errno));
    goto fail;
  }

  rc = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) < 0) {
    syslog(LOG_WARNING, "Cannot set socket options: %s", strerror(errno)); 
    goto fail;
  }

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    if (!try)
      syslog(LOG_WARNING, "Cannot bind to address: %s", strerror(errno));
    goto fail;
  }

end:
  free(ai);
  return fd;

fail:
  if (ai)
    free(ai);
  if (fd >= 0)
    close(fd);
  return -1;
}



static int users_search(
    struct passwd *p)
{
  struct reserved_port *rp = NULL;
  if (!p)
    return 0;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (p->pw_uid == rp->uid)
      return 1;
  }

  return 0;
}


static int users_add(
    struct passwd *p)
{
  struct reserved_port *rp = NULL;

  if (!p)
    goto fail;

  /* User already exists */
  if (users_search(p))
    goto fail;

  rp = malloc(sizeof(*rp));
  if (!rp) {
    syslog(LOG_WARNING, "Cannot allocate memory for user %s to bind to port: %s", p->pw_name, strerror(errno));
    goto fail;
  }

  rp->username = strdup(p->pw_name);
  if (!rp->username) {
    syslog(LOG_WARNING, "Cannot allocate memory for username %s to bind to port: %s", p->pw_name, strerror(errno));
    goto fail;
  }

  rp->uid = p->pw_uid;
  rp->fd = -1;
  rp->dont_reacquire = 0;
  rp->reacquire_time = 0;
  rp->port = config.port_offset + p->pw_uid;
  /* Dont allow overflow */
  if ((int)rp->port < (int)config.port_offset) {
    syslog(LOG_WARNING, "Cannot bind port, integer overflow");
    goto fail;
  }

  if ((rp->fd = users_port_bind(rp->port, 0)) < 0)
    goto fail;
  rp->released = 0;

  LIST_INSERT_HEAD(&ulist, rp, entries);
  ulistnum++;
  syslog(LOG_NOTICE, "Added port %d for user %s", rp->port, rp->username);
  return 1;

fail:
  if (rp) {
    if (rp->username)
      free(rp->username);
    if (rp->fd > -1)
      close(rp->fd);
  }
  return 0;
}


static int users_delete(
   uid_t uid)
{
  struct reserved_port *rp = NULL;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (rp->uid == uid)
      break;
  }

  if (!rp)
    return 0;

  syslog(LOG_NOTICE, "Deleting %s", rp->username);
  if (rp->released == 0)
    close(rp->fd);
  free(rp->username);
  LIST_REMOVE(rp, entries);
  ulistnum--;
  free(rp);
  return 1;
}



void users_init(
    void)
{
  LIST_INIT(&ulist);
}



void users_sync(
    void)
{
  struct passwd *p = NULL;
  struct reserved_port *rp = NULL, *rp2 = NULL;
  char **blacklist;

  /* Add any users we are unaware of */
  while ((p = getpwent())) {
    /* Make sure the blacklist does not match */
    for (blacklist = (char **)user_blacklist; *blacklist != NULL; blacklist++) {
      if (strcmp(*blacklist, p->pw_name) == 0)
        goto next;
    }

    /* Dont register users below the system user threshold */
    if (p->pw_uid < config.system_user_threshold)
      goto next;
    users_add(p);
next:
    continue;
  }

  /* Delete any users that no longer exist */
  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
restart:
    p = getpwuid(rp->uid);
    if (!p) {
      /* Once the entry is deleted, we need to short-circuit the loop */
      rp2 = rp->entries.le_next;
      users_delete(rp->uid);
      rp = rp2;
      if (!rp)
        break;
      goto restart;
    }
  }

  endpwent();
}

void users_reacquire_ports(
    void)
{
  struct reserved_port *rp = NULL;
  time_t now = time(NULL);
  int tmp;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (rp->released && rp->reacquire_time < now && rp->dont_reacquire == 0) {
      tmp = users_port_bind(rp->port, 1);
      if (errno == EADDRINUSE) {
        rp->reacquire_time += DEFAULT_REACQUIRE_TIMEOUT;
        return;
      }
      syslog(LOG_NOTICE, "Re-acquired port %d for user %s", rp->port, rp->username);
      rp->fd = tmp;
      rp->reacquire_time = 0;
      rp->released = 0;
    }
  }
}


int users_port_request(
     uid_t uid,
     uint16_t port)
{
  struct reserved_port *rp;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (rp->uid == uid) {
      if (port == 0)
        port= rp->port;
      else if (rp->port != port)
        return -EINVAL;

      if (rp->released) {
        rp->fd = users_port_bind(port, 0);
        if (rp->fd >= 0) {
          rp->released = 0;
          rp->reacquire_time = 0;
        }
        return -errno;
      }
      return -EADDRINUSE;
    }
  }
  return -ENOENT;
}

int users_port_release(
    uid_t uid,
    uint16_t port)
{
  struct reserved_port *rp;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (rp->uid == uid) {
      if (port == 0)
        port= rp->port;
      else if (rp->port != port)
        return -EINVAL;

      if (!rp->released) {
        close(rp->fd);
        rp->fd = -1;
        rp->released = 1;
        rp->reacquire_time = time(NULL) + DEFAULT_REACQUIRE_TIMEOUT;
        return -errno;
      }
      return -ENOTCONN;
    }
  }
  return -ENOENT;
}

int users_port_acquire_policy(
    uid_t uid,
    uint8_t dont_reacquire)
{
  struct reserved_port *rp;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    if (rp->uid == uid) {
        rp->dont_reacquire = dont_reacquire;
        return 0;
    }
  }
  return -ENOENT;
}

int users_port_list(
    uid_t uid,
    struct portinfo **info,
    uint16_t *len)
{
  struct portinfo *pi = NULL;
  struct reserved_port *rp;
  int i=0;
  pi = calloc(ulistnum, sizeof(*pi));
  if (!pi)
    return -errno;

  for (rp = ulist.lh_first; rp != NULL; rp = rp->entries.le_next) {
    pi[i].uid = rp->uid;
    pi[i].port = rp->port;
    /* Dont share reserve status with unauthorized users */
    if (uid == rp->uid || uid == 0) {
      pi[i].status = rp->released;
      pi[i].dont_reacquire = rp->dont_reacquire;
    }
    else {
      pi[i].status = STATUS_UNKNOWN;
      pi[i].dont_reacquire = REACQUIRE_UNKNOWN;
    }
    i++;
  }
  *info = pi;
  *len = ulistnum;
  return 0;
}
