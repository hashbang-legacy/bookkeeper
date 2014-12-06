#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
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

#include "config.h"
#include "users.h"
#include "event.h"
#include "protocol.h"

struct config config;
int sockfd = -1;
int inotifyfd = -1;
int sigfd = -1;
int timefd = -1;

int wds[2];

static void print_help(
    void)
{
  printf("Usage: bookkeeper [OPTION]\n\n"
"Options:\n"
"  -h  --help                          Prints this help\n"
"  -s  --sys-uid-threshold   INTEGER   This UID and the ones below it will never be considered for\n"
"                                      port reservation\n"
"  -p  --port-offset         INTEGER   Adds this number to the users UID as the relevent port offset\n"
"                                      default: 10000\n"
"  -u  --user                STRING    User and group to transiton to\n"
"  -f  --sockpath            STRING    Path of the socket file to create for client communication.\n"
"                                      default: %s"
"\n\n",
DEFAULT_SOCKPATH);
}

static void parse_config(
    const int argc,
    char **argv)
{
  int c;
  struct passwd *p;
  static struct option long_options[] = {
    { "help", no_argument, 0, 'h'},
    { "port-offset", required_argument, 0, 'p' },
    { "sys-uid-threshold", required_argument, 0, 's' },
    { "user", required_argument, 0, 'u' },
    { 0, 0, 0, 0 }
  };

  while (1) {
    int opt_idx = 0;

    c = getopt_long(argc, argv, "hs:p:u:", long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c) {
      case 's':
        config.system_user_threshold = atoi(optarg);
        if (config.system_user_threshold <= 0)
          errx(EXIT_FAILURE, "The sys_uid_threshold must a number be 1 or greater");
      break;

      case 'f':
        /* Dont check the path until later, just check its absolute */
        config.sockfile = strdup(optarg);
        if (config.sockfile)
          err(EXIT_FAILURE, "Cannot setup sockpath");
        if (config.sockfile[0] != '/')
          err(EXIT_FAILURE, "The socket path must be an absolute path");
      break;

      case 'h':
        print_help();
        exit(0);
      break;

      case 'p':
        config.port_offset = atoi(optarg);
        if (config.port_offset < PRIVPORTS)
          errx(EXIT_FAILURE, "Port offset must be an integer with an offset of at least %d", PRIVPORTS);
      break;

      case 'u':
        config.user = strdup(optarg);
        if (!config.user)
          err(EXIT_FAILURE, "Cannot assign username");
        p = getpwnam(config.user);
        if (!p)
          errx(EXIT_FAILURE, "Unable to switch to a non-existant user");
        config.uid = p->pw_uid;
        config.gid = p->pw_gid;
      break;

      default:
        fprintf(stderr, "An unknown option was passed");
        print_help();
        exit(EXIT_FAILURE);
      break;
    }
  }

  if (config.system_user_threshold == 0)
    config.system_user_threshold = 1000;
  if (config.port_offset == 0)
    config.port_offset = 10000;
  if (config.user == NULL)
    errx(EXIT_FAILURE, "You must supply a username to transition to");
  if (config.sockfile == NULL) {
    config.sockfile = strdup(DEFAULT_SOCKPATH);
    if (!config.sockfile)
      err(EXIT_FAILURE, "Cannot setup initial configuration");
  }
}


static void set_resource_limits(
    void)
{
  struct rlimit lim;
  lim.rlim_cur = 70000;
  lim.rlim_max = 70000;

  if (setrlimit(RLIMIT_NOFILE, &lim) < 0)
    err(EXIT_FAILURE, "Cannot set file handle limit");
}


static void switch_users(
    void)
{
  if (setregid(config.gid, config.gid) < 0)
    err(EXIT_FAILURE, "Cannot switch users");
  if (setreuid(config.uid, config.uid) < 0)
    err(EXIT_FAILURE, "Cannot switch users");
}


static void inotify_setup(
    void)
{
  inotifyfd = -1;

  if ((inotifyfd = inotify_init()) < 0)
    err(EXIT_FAILURE, "Cannot start inotify");

  /* We actually watch etc too because of renames overwriting the original file */
  if ((wds[0] = inotify_add_watch(inotifyfd, "/etc", IN_MOVED_TO)) < 0)
    err(EXIT_FAILURE, "Cannot add watch of /etc/passwd to inotify");

  /* If someone edits passwd directly, we know from here */
  if ((wds[1] = inotify_add_watch(inotifyfd, "/etc/passwd", IN_MODIFY)) < 0)
    err(EXIT_FAILURE, "Cannot add watch of /etc/passwd to inotify");
}


static int inotify_read(
    int fd,
    int event,
    void *data)
{
  int rc;
  char buf[2048];
  char *p;
  struct inotify_event *in;

  if ((event & EPOLLERR) == EPOLLERR || (event & EPOLLHUP) == EPOLLHUP)
     return -1;

  rc = read(fd, buf, sizeof(buf));
  if (rc < 0)
    return -1;

  p = buf;
  while (p < (buf+rc)) {
    in = (struct inotify_event *)p;

    /* The directory being watched */
    if (in->wd == wds[0]) {
      if (strcmp(in->name, "passwd") != 0)
        goto next;

      if ((in->mask & IN_MOVED_TO) == IN_MOVED_TO)
        users_sync();
    }

    /* Is /etc/passwd */
    else if (in->wd == wds[1]) {

      /* The file was edited by hand */
      if ((in->mask & IN_MODIFY) == IN_MODIFY)
        users_sync();
      if ((in->mask & IN_IGNORED) == IN_IGNORED) {
        /* In this case, we must re-add the watch */
        if ((wds[1] = inotify_add_watch(fd, "/etc/passwd", IN_MODIFY)) < 0)
          err(EXIT_FAILURE, "Unable to re-add watch for /etc/passwd!");
      }
    }

    else {
      syslog(LOG_WARNING, "Unknown watch descriptor was passed to us: %s", strerror(errno));
    }

next:
    p += sizeof(struct inotify_event) + in->len;
  }

  return 0;
}


static void signal_setup(
    void)
{
  sigset_t sigs;
  /* Assume this all just works */
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGHUP);
  sigaddset(&sigs, SIGINT);
  sigaddset(&sigs, SIGTERM);

  if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
    err(EXIT_FAILURE, "Cannot setup signalfd");

  if ((sigfd = signalfd(-1, &sigs, 0)) < 0)
    err(EXIT_FAILURE, "Cannot setup signalfd");
}

static int signal_read(
    int fd,
    int event,
    void *data)
{
  int rc;
  struct signalfd_siginfo info;

  if ((event & EPOLLERR) == EPOLLERR || (event & EPOLLHUP) == EPOLLHUP)
     return -1;

  rc = read(fd, &info, sizeof(info));
  if (rc != sizeof(info))
    return -1;

  switch (info.ssi_signo) {

  case SIGHUP:
    syslog(LOG_WARNING, "Got HUP, re-reading passwd file");
    users_sync();
  break;

  case SIGTERM:
  case SIGINT:
    exit(0);
  break;
 
  }

  return 0;
}

static void sockfile_setup(
    void)
{
  struct sockaddr_un un;
  int rc = 1;
  memset(&un, 0, sizeof(un));

  if (access(config.sockfile, R_OK|W_OK) < 0) {
    if (errno != ENOENT)
      err(EXIT_FAILURE, "Cannot access sockfile");
  }

  un.sun_family = AF_UNIX;
  strncpy(un.sun_path, config.sockfile, strlen(config.sockfile));
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (sockfd < 0)
    err(EXIT_FAILURE, "Could not acquire unix socket");

  if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &rc, sizeof(rc)) < 0)
    err(EXIT_FAILURE, "Could not set socket options\n");

  /* May not work as file doesn't exist. Dont care about this */
  if (unlink(config.sockfile) < 0)
    if (errno != ENOENT)
      err(EXIT_FAILURE, "Could not remove old socket");

  if (bind(sockfd, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) < 0)
    err(EXIT_FAILURE, "Could not bind to socket");

  if (chmod(config.sockfile, 0777) < 0)
    err(EXIT_FAILURE, "Cannot set mode on socket");

  if (listen(sockfd, 5) < 0)
    err(EXIT_FAILURE, "Cannot listen on socket");
}


static int sockfile_read(
    int fd,
    int event,
    void *data)
{
  int clifd = -1;

  if ((event & EPOLLERR) == EPOLLERR || (event & EPOLLHUP) == EPOLLHUP)
     return -1;

  clifd = accept(sockfd, NULL, NULL);
  if (clifd < 0)
    return 0;

  event_add_fd(clifd, decode_packet, NULL, NULL, EPOLLIN);
  return 0;
}


static void timer_setup(
    void)
{
  timefd = timerfd_create(CLOCK_MONOTONIC, 0);
  struct itimerspec ts;
  ts.it_interval.tv_sec = 60;
  ts.it_interval.tv_nsec = 0;
  ts.it_value.tv_sec = 60;
  ts.it_value.tv_nsec = 0;

  if (timefd < 0)
    err(EXIT_FAILURE, "Failed to setup timerfd");

  if (timerfd_settime(timefd, 0, &ts, NULL) < 0)
    err(EXIT_FAILURE, "Failed to setup timerfd");
}


static int timer_read(
    int fd,
    int event,
    void *data)
{
  uint64_t triggered;
  int rc;

  if ((event & EPOLLERR) == EPOLLERR || (event & EPOLLHUP) == EPOLLHUP)
     return -1;

  rc = read(fd, &triggered, sizeof(triggered));
  if (rc != sizeof(triggered))
    err(EXIT_FAILURE, "Error reading from timerfd");

  /* When the timer is triggered, we read all our reserved ports for released entries */
  users_reacquire_ports();

  return 0;
}

static void setup_events(
    void)
{
  if (event_add_fd(timefd, timer_read, NULL, NULL, EPOLLIN) < 0)
    err(EXIT_FAILURE, "Cannot add timer event");
  if (event_add_fd(sigfd, signal_read, NULL, NULL, EPOLLIN) < 0)
    err(EXIT_FAILURE, "Cannot add signal event");
  if (event_add_fd(inotifyfd, inotify_read, NULL, NULL, EPOLLIN) < 0)
    err(EXIT_FAILURE, "Cannot add inotify event");
  if (event_add_fd(sockfd, sockfile_read, NULL, NULL, EPOLLIN) < 0)
    err(EXIT_FAILURE, "Cannot add inotify event");
}

int main(
    const int argc,
    const char **argv)
{

  openlog(NULL, LOG_PID, LOG_DAEMON);
  chdir("/");
  parse_config(argc, (char **)argv);
  set_resource_limits();
  switch_users();

  inotify_setup();
  signal_setup();
  sockfile_setup();
  timer_setup();

  users_init();
  event_init();

  setup_events();

  users_sync();

  while(1) {
    event_loop(128, -1);
  }

  exit(0);
}

