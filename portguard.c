#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <getopt.h>
#include <pwd.h>

#include "protocol.h"

#define DEFAULT_SOCKPATH "/var/run/bookkeeper/bookkeeper.sock"

struct {
  char *sockfile;
  uid_t uid;
  int cmd;
  int rqpolicy;
} config;

static void print_help(
    void)
{
  printf("Usage: portguard [OPTION] COMMAND\n\n"
"OPTION:\n"
"  -h  --help                          Prints this help\n"
"  -f  --sockpath            STRING    The path to the socket. Defaults to %s\n"
"  -u  --user                STRING    The user to perform the request on. Only root can change a port for another user\n"
"\n"
"COMMAND:\n"
"  release                             The port is unprotected and can be used.\n\n"
"  reserve                             The port is protected, it will not be possible to bind to it.\n\n"
"  list                                Produces a list of users and the ports that are guarded by the system.\n\n"
"  no_reacquire                        By default, if the port is no longer in use, eventually it will become\n"
"                                      automatically re-acquired by the server to prevent another user from binding\n"
"                                      to it. If you pass this option this informs the server to never attempt this\n"
"                                      operation.\n\n"
"  reacquire                           Tells the system that re-acquiring the port automatically is permitted.\n"
"\n\n",
DEFAULT_SOCKPATH);
}

static void parse_config(
    const int argc,
    char **argv)
{
  int c;
  char nodefault = 1;
  char haveuid = 0;
  struct passwd *p;
  static struct option long_options[] = {
    { "help", no_argument, 0, 'c'},
    { "sockpath", required_argument, 0, 'f' },
    { "user", required_argument, 0, 'u' },
    { 0, 0, 0, 0 }
  };

  config.cmd = -1;
  config.uid = -1;
  int opt_idx = 0;

  while (1) {
    c = getopt_long(argc, argv, "h:f:u:", long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c) {
      case 'f':
        config.sockfile = strdup(optarg);
        if (!config.sockfile)
          err(EXIT_FAILURE, "Cannot get memory for configuration of socket path");
      break;

      case 'u':
        p = getpwnam(optarg);
        if (!p)
          errx(EXIT_FAILURE, "User does not exist");
        config.uid = p->pw_uid;
        haveuid = 1;
      break;

      case 'h':
        print_help();
        exit(0);
      break;

      default:
        print_help();
        exit(0);
      break;
    }
  }

  if (optind >= argc) {
    nodefault = 0;
    config.cmd = PORT_LIST;
  }
  else if (argc - optind != 1) {
    fprintf(stderr, "Passed incorrect number of commands.\n");
    print_help();
    exit(EXIT_FAILURE);
  }

  if (nodefault) {
    if (strcmp(argv[optind], "release") == 0)
      config.cmd = PORT_RELEASE;
    else if (strcmp(argv[optind], "reserve") == 0)
      config.cmd = PORT_RESERVE;
    else if (strcmp(argv[optind], "no_reacquire") == 0) {
      config.cmd = PORT_RQPOLICY;
      config.rqpolicy = 1;
    }
    else if (strcmp(argv[optind], "list") == 0)
      config.cmd = PORT_LIST;
    else if (strcmp(argv[optind], "reacquire") == 0) {
      config.cmd = PORT_RQPOLICY;
      config.rqpolicy = 0;
    }
    else {
      fprintf(stderr, "The command passed was not recognised\n");
      print_help();
      exit(EXIT_FAILURE);
    }
  }

  if (config.sockfile == NULL) {
    config.sockfile = strdup(DEFAULT_SOCKPATH);
    if (!config.sockfile)
      err(EXIT_FAILURE, "Cannot setup initial configuration");
  }

  if (!haveuid)
    config.uid = getuid();
}


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



int main(
    const int argc,
    const char **argv)
{
  int sock = -1;
  int rc, i;

  parse_config(argc, (char **)argv);

  struct passwd *pw;
  struct portinfo *pi = NULL;
  struct port_request pr;
  struct port_response resp;
  struct iovec vec[7];
  struct sockaddr_un un;

  memset(&un, 0, sizeof(un));
  fill_request_vector(&pr, vec);

  pr.magic = MAGIC;
  pr.request = config.cmd;
  pr.pi.uid = config.uid;
  pr.pi.port = 0;
  pr.pi.status = 0;
  if (config.cmd == PORT_RQPOLICY)
    pr.pi.dont_reacquire = config.rqpolicy;
  pr.error = 0;

  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    err(EXIT_FAILURE, "Could not make socket");

  un.sun_family = AF_UNIX;
  strncpy(un.sun_path, config.sockfile, strlen(config.sockfile));

  if (connect(sock, (struct sockaddr *)&un, sizeof(un)) < 0)
    err(EXIT_FAILURE, "Cannot connect to socket");

  rc = writev(sock, vec, 7);
  if (rc < 0)
    err(EXIT_FAILURE, "Failed to send message");

  rc = recv(sock, &resp, sizeof(resp), 0);
  if (resp.error) {
    errno = resp.error;
    err(EXIT_FAILURE, "Result");
  }

  if (config.cmd == PORT_LIST) {
    if (resp.portslen < 0 || resp.portslen > 65535)
      errx(EXIT_FAILURE, "Garbled response from the server");
    pi = calloc(resp.portslen, sizeof(*pi));

    rc = recv(sock, pi, sizeof(*pi) * resp.portslen, 0);
    if (rc < 0)
      err(EXIT_FAILURE, "Cannot receive from server");

    printf("%-24s%-8s%-16s%-8s\n", "User", "Port", "Status", "Re-acquire");
    printf("----------------------------------------------------------\n", "");
    for (i=0; i < resp.portslen; i++) {
        pw = getpwuid(pi[i].uid);
        if (!pw)
          printf("%-24d", pi[i].uid);
        else
          printf("%-24s", pw->pw_name);

        printf("%-8hd", pi[i].port);

        if (pi[i].status == STATUS_RESERVED)
          printf("%-16s", "reserved");
        else if (pi[i].status == STATUS_RELEASED)
          printf("%-16s", "released");
        else if (pi[i].status == STATUS_UNKNOWN)
          printf("%-16s", "");
        else
          printf("%-16s", "unknown");

        if (pi[i].dont_reacquire == REACQUIRE_DO)
          printf("%-8s", "yes");
        else if (pi[i].dont_reacquire == REACQUIRE_DONT)
          printf("%-8s", "no");
        else if (pi[i].dont_reacquire == REACQUIRE_UNKNOWN)
          printf("%-8s", "");
        else
          printf("%-8s", "unknown");
        printf("\n");
    }
  }
  close(sock);
  exit(0);
}
