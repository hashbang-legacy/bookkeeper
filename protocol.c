/* Fetches and decodes packet */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <pwd.h>

#include "protocol.h"

static inline void fill_request_vector(
    struct port_request *pr,
    struct iovec vec[7])
{
  vec[0].iov_base = &pr->magic;
  vec[0].iov_len = sizeof(pr->magic);
  vec[1].iov_base = &pr->request;
  vec[1].iov_len = sizeof(pr->request);
  vec[2].iov_base = &pr->pi.uid;
  vec[2].iov_len = sizeof(pr->pi.uid);
  vec[3].iov_base = &pr->pi.port;
  vec[3].iov_len = sizeof(pr->pi.port);
  vec[4].iov_base = &pr->pi.status;
  vec[4].iov_len = sizeof(pr->pi.status);
  vec[5].iov_base = &pr->pi.dont_reacquire;
  vec[5].iov_len = sizeof(pr->pi.dont_reacquire);
  vec[6].iov_base = &pr->error;
  vec[6].iov_len = sizeof(pr->error);  
}

static void handle_request(
    int fd,
    struct ucred *uc,
    struct port_request *pr)
{
  struct port_response resp;
  struct portinfo *pi = NULL;
  int len;

  if (uc->pid == 0)
    return;

  if (pr->magic != MAGIC)
    return;

  memset(&resp, 0, sizeof(resp));

  switch(pr->request) {
    case PORT_RESERVE:
      if (pr->pi.uid != uc->uid && uc->uid != 0) {
        resp.error = EPERM;
        break;
      }
      resp.error = users_port_request(pr->pi.uid, pr->pi.port);
    break;

    case PORT_RELEASE:
      if (pr->pi.uid != uc->uid && uc->uid != 0) {
        resp.error = EPERM;
        break;
      }
      resp.error = users_port_release(pr->pi.uid, pr->pi.port);
    break;

    case PORT_RQPOLICY:
      if (pr->pi.uid != uc->uid && uc->uid != 0) {
        resp.error = EPERM;
        break;
      }
      resp.error = users_port_acquire_policy(pr->pi.uid, pr->pi.dont_reacquire);
    break;

    case PORT_LIST:
      resp.error = users_port_list(uc->uid, &pi, &resp.portslen);
      if (resp.error == 0) {
        if (send(fd, &resp, sizeof(resp), 0) < 0) {
          free(pi);
          return;
        }
        send(fd, pi, sizeof(pi) * resp.portslen, 0);
        free(pi);
        return;
      }
    break;

    default:
      resp.error = EINVAL;
    break; 
  }

  resp.error = abs(resp.error);
  send(fd, &resp, sizeof(resp), 0);
}

int decode_packet(
    int fd,
    int event,
    void *data)
{
  int rc;
  char buf[64];
  struct msghdr msg;
  struct ucred *uc;
  struct cmsghdr *cmsg = NULL;
  struct port_request pr;
  struct iovec vec[7];

  if ((event & EPOLLERR) == EPOLLERR || (event & EPOLLHUP) == EPOLLHUP)
     return -1;

  memset(buf, 0, sizeof(buf));
  memset(&msg, 0, sizeof(msg));
  memset(&pr, 0, sizeof(pr));
  memset(vec, 0, sizeof(vec));
  fill_request_vector(&pr, vec);

  msg.msg_iov = vec;
  msg.msg_iovlen = 7;
  msg.msg_control = buf;
  msg.msg_controllen = 64;
  msg.msg_flags = 0;
  
  rc = recvmsg(fd, &msg, 0);
  if (rc < 0) {
    close(fd);
    return -1;
  }

  /* Expect credentials */
  cmsg = CMSG_FIRSTHDR(&msg);
  uc = (struct ucred *)CMSG_DATA(cmsg);

  handle_request(fd, uc, &pr);

  close(fd);
  return 0;
}
