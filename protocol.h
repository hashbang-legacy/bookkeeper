#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#define MAGIC 0x504F5254

#define STATUS_RESERVED 0
#define STATUS_RELEASED 1
#define STATUS_UNKNOWN  2

#define REACQUIRE_DO      0
#define REACQUIRE_DONT    1
#define REACQUIRE_UNKNOWN 2

#define PORT_RESERVE   0
#define PORT_RELEASE   1
#define PORT_RQPOLICY  2
#define PORT_LIST      3

#define PORT_RQMIN 0
#define PORT_RQMAX 3

struct portinfo {
  uid_t uid;
  uint16_t port;
  uint8_t status;
  uint8_t dont_reacquire;
};

struct port_request {
  uint32_t magic;
  uint32_t request;
  struct portinfo pi;
  int error;
};

struct port_response {
  int error;
  uint16_t portslen;
};

int decode_packet(int fd, int event, void *data);
#endif
