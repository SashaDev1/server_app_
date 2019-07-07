#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char *kServerPort = "8000";
const unsigned kMaxConnectionsNumb = 1000;

/*
Client
    socket()
  ? bind()    ?
    connect()
    ----------------
    write()   | read()
    send()    | recv()
    sendto()  | recvfrom()
    writev()  | readv()
    sendmsg() | recvmsg()
    ----------------
    close()
Server
    socket()
    bind()
    listen()
    accept()
    ----------------
    write()   | read()
    send()    | recv()
    sendto()  | recvfrom()
    writev()  | readv()
    sendmsg() | recvmsg()
    ----------------
    close()
*/

typedef enum {
  eHTTP_UNKNOWN = 0,
  eHTTP_CONNECT,
  eHTTP_DELETE,
  eHTTP_GET,
  eHTTP_HEAD,
  eHTTP_OPTIONS,
  eHTTP_PATCH,
  eHTTP_POST,
  eHTTP_PUT,
  eHTTP_TRACE
} eHTTPMethod;

typedef struct {
  eHTTPMethod type;
  char path[255];
} sHTTPHeader;

int CreateSocket(const char *);
void *GetClientAddress(struct sockaddr *sa);
void HttpRequest(int);
void ParseHttpRequest(const char *, sHTTPHeader *);
void SendMessage(int, const char *);
void Send404(int);

int main(int argc, char **argv) {
  int server_socket_descriptor;

  struct sockaddr_storage client_address;
  int client_socket_descriptor;

  server_socket_descriptor = CreateSocket(kServerPort);

  if (server_socket_descriptor == -1) {
    fprintf(stderr, "error server socket creation\n");
    return -1;
  }

  puts("Server created!");

  for (;;) {
    socklen_t address_length = sizeof(client_address);
    client_socket_descriptor =
        accept(server_socket_descriptor, (struct sockaddr *)&client_address,
               &address_length);
    // TODO (@pochka15): check why it makes accept 2 times

    if (-1 == client_socket_descriptor) {
      fprintf(stderr, "error accept\n");
      return -1;
    }

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(client_address.ss_family,
              GetClientAddress((struct sockaddr *)&client_address), ip,
              sizeof(ip));
    printf("server: got connection from %s\n", ip);

    // read
    HttpRequest(client_socket_descriptor);

    close(client_socket_descriptor);
  }
  return 0;
}

void *GetClientAddress(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int CreateSocket(const char *port_p) {
  struct addrinfo hints;
  struct addrinfo *server_info;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;     /* for IPv4 and IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* TCP stream socket */
  hints.ai_flags = AI_PASSIVE;     /* fill ip address in a passive way */

  int result = getaddrinfo(NULL, port_p, &hints, &server_info);

  if (result != 0) {
    fprintf(stderr, "error getaddrinfo() \n");
    return -1;
  }

  int socket_descriptor;
  struct addrinfo *p;
  for (p = server_info; p != NULL; p = p->ai_next) {
    socket_descriptor = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (-1 == socket_descriptor) continue;

    /* to reuse our server, set some options */
    int tmp_option;
    if (-1 == setsockopt(socket_descriptor, SOL_SOCKET,
                         (SO_REUSEPORT | SO_REUSEADDR), &tmp_option,
                         sizeof(int))) {
      fprintf(stderr, "error setsockopt\n");
      close(socket_descriptor);
      freeaddrinfo(server_info);  // all done with this structure
      return -2;
    }

    // TODO (@pochka15): cannot bind, what's hapennin here?
    if (-1 == bind(socket_descriptor, p->ai_addr, p->ai_addrlen)) {
      close(socket_descriptor);
      fprintf(stderr, "error bind: %s\n", strerror(errno));
      continue;
    }
    break;
  }

  freeaddrinfo(server_info);

  if (NULL == p) {
    fprintf(stderr, "failed to find address\n");
    return -3;
  }

  if (-1 == listen(socket_descriptor, kMaxConnectionsNumb)) {
    fprintf(stderr, "error listen\n");
    return -4;
  }

  return socket_descriptor;
}

void HttpRequest(int socket_descriptor) {
  const int request_buffer_size = 65536;
  char request[request_buffer_size];

  int bytes_recieved =
      recv(socket_descriptor, request, request_buffer_size - 1, 0);

  if (bytes_recieved < 0) {
    fprintf(stderr, "error recieve\n");
    return;
  }
  request[bytes_recieved] = '\0';

  printf("request:\n%s\n", request);

  sHTTPHeader req;
  ParseHttpRequest(request, &req);

  if (req.type == eHTTP_GET) {
    char *txt_msg = "Test message. 20<br>";
    // TODO (@pochka15): enable rus lang from txt msg
    SendMessage(socket_descriptor, txt_msg);
  } else {
    Send404(socket_descriptor);
  }
}

void SendMessage(int socket_descriptor, const char *message_ptr) {
  char buffer[65536] = {0};

  strcat(buffer, "HTTP/1.1 200 OK\n\n");
  strcat(buffer, "<h1>");
  strcat(buffer, message_ptr);
  strcat(buffer, "</h1>");

  int len = strlen(buffer);
  send(socket_descriptor, buffer, len, 0);
}

void Send404(int socket_descriptor) {
  const char *buffer = "HTTP/1.1 400 \n\n";
  int length = strlen(buffer);
  send(socket_descriptor, buffer, length, 0);
}

void ParseHttpRequest(const char *str_request_ptr, sHTTPHeader *header_ptr) {
  int type_length = 0;
  char type[255] = {0};
  int index = 0;

  header_ptr->type = eHTTP_UNKNOWN;

  sscanf(&str_request_ptr[index], "%s", type);
  type_length = strlen(type);

  if (3 == type_length) {
    if ('G' == type[0] && 'E' == type[1] && 'T' == type[2])
      header_ptr->type = eHTTP_GET;

    index += type_length + 1;
    sscanf(&str_request_ptr[index], "%s", header_ptr->path);
  }
}

// TODO (@pochka15): write function wrappers like from the Unix network book
// TODO (@pochka15): clean code, make smaller functions, think about namings and
// add comments