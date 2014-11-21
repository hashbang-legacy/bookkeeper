#include "event.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/queue.h>

/* Event */
struct callback {
  void *data;
  int fd;
  int (*callback)(int fd, int event, void *data);
  void (*destroy)(void *data);
  LIST_ENTRY(callback) list;
};

/* Global event handle */
struct event_handle {
  int epollfd;
  int curfds;
  int maxfds;
  LIST_HEAD(evlist_head, callback) head;
};


/* Static function prototypes */
static struct callback * event_search(int fd);

static struct event_handle eh = { -1, 0, EVENT_MAXFDS };

/* Returns an event handle from searching by fd */ 
static struct callback * event_search(
    int fd)
{
  struct callback *ev;
  for (ev = eh.head.lh_first; ev != NULL; ev = ev->list.le_next) {
    if (ev->fd == fd)
      return ev;
  }

  return NULL;
}


/* Initialize the event handle */
void event_init(
    void)
{
  int fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot initialize event handler");

  eh.epollfd = fd; 
  LIST_INIT(&eh.head); 
}


/* Perform the event loop */
int event_loop(
    int max,
    int timeout)
{
  int cnt = 0;
  int rc, i;
  struct callback *cb;
  assert(max < EVENT_MAXFDS && max > 0);
  assert(timeout >= -1);

  struct epoll_event *events = calloc(max, sizeof(struct epoll_event));
  if (!events) {
    syslog(LOG_ERR, "Cannot allocate memory for events: %s", strerror(errno));
    goto fail;
  }

restart:
  /* Do the epoll, safely handle interrupts */
  rc = epoll_wait(eh.epollfd, events, max, timeout);
  if (rc < 0) {
    if (errno == EINTR)
      goto restart;
    else {
      goto fail;
    }
  }

  for (i=0; i < rc; i++) {
    cb = (struct callback *)events[i].data.ptr;
    assert(cb->callback);
    if (cb->callback(cb->fd, events[i].events, cb->data) < 0) {
      event_del_fd(cb->fd);
    }
    else {
      cnt++;
    }
  }

  free(events);
  return cnt;
  
fail:
  if (events)
    free(events);
  return -1;
}


/* Delete an FD from the events, is idempotent */
void event_del_fd(
    int fd)
{
  struct callback *ev = event_search(fd); 
  if (!ev)
    return;

  /* Remove from the list */
  LIST_REMOVE(ev, list);

  /* Call the objects destructor */
  if (ev->destroy)
    ev->destroy(ev->data);

  /* Remove from the epoll */
  epoll_ctl(eh.epollfd, EPOLL_CTL_DEL, ev->fd, NULL);
  /* WARNING WARNING, cb->data MAY BE ALLOCATED */
  free(ev);
}

/* Modify the event mask of an existing cli */
int event_mod_event(
    int fd,
    int event)
{
    assert(fd > -1);

    struct epoll_event ev;
    struct callback *cb;

    if ((cb = event_search(fd)) == NULL) {
      return 0;
    }

    ev.events = event;
    ev.data.ptr = cb;
    if (epoll_ctl(eh.epollfd, EPOLL_CTL_MOD, fd, &ev) < 0)
      syslog(LOG_WARNING, "Unable to modify event mask: %s", strerror(errno));
      return -1;

    return 0;
}


/* Add a FD onto the events */
int event_add_fd(
    int fd,
    int (*callback)(int fd, int event, void *data),
    void (*destructor),
    void *data,
    int event)
{
  assert(fd >= 0);
  assert(callback);
  struct epoll_event ep_ev;
  struct callback *ev = malloc(sizeof(*ev));
  struct callback *tmp;
  if (!ev) {
    syslog(LOG_ERR, "Cannot allocate memory for callback: %s", strerror(errno));
    goto fail;
  }
  memset(&ep_ev, 0, sizeof(ep_ev));

  /* Initialize callback and epoll event */
  ev->fd = fd;
  ev->data = data;
  ev->callback = callback;
  ev->destroy = destructor;

  ep_ev.events = event;
  ep_ev.data.ptr = ev;

  /* Insert the FD onto our list */
  LIST_INSERT_HEAD(&eh.head, ev, list);

  /* Register the fd with the epoll handler */
  if (epoll_ctl(eh.epollfd, EPOLL_CTL_ADD, fd, &ep_ev) < 0) {
    syslog(LOG_ERR, "Cannot add event to epoll: %s", strerror(errno));
    goto fail;
  }

  if (eh.curfds + 1 > eh.maxfds) {
    syslog(LOG_ERR, "Adding FD maximum number of descriptors to monitor: %s", strerror(errno));
    goto fail;
  }

  eh.curfds++;
  return 0;

fail:
  tmp = event_search(fd);
  if (tmp) {
    LIST_REMOVE(tmp, list);
  }

  if (ev)
    free(ev);
  return -1;
}
