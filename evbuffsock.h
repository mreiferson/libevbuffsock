#ifndef __buffered_socket_h
#define __buffered_socket_h

#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ev.h>

#define EVBUFFSOCK_VERSION "0.1.1"

struct Buffer {
    char *data;
    char *orig;
    size_t offset;
    size_t length;
    size_t capacity;
};

struct Buffer *new_buffer(size_t length, size_t capacity);
void free_buffer(struct Buffer *buf);
void buffer_reset(struct Buffer *buf);
int buffer_add(struct Buffer *buf, void *source, size_t length);
void buffer_drain(struct Buffer *buf, size_t length);
int buffer_read_fd(struct Buffer *buf, int fd);
int buffer_write_fd(struct Buffer *buf, int fd);
int buffer_has_data(struct Buffer *buf);
int buffer_expand(struct Buffer *buf, size_t need);

enum BufferedSocketStates {
    BS_INIT,
    BS_CONNECTING,
    BS_CONNECTED,
    BS_DISCONNECTED
};

struct BufferedSocket {
    char *address;
    int port;
    int fd;
    int state;
    struct ev_io conn_ev;
    struct ev_timer timer_ev;
    struct ev_io read_ev;
    struct ev_io write_ev;
    struct Buffer *read_buf;
    struct Buffer *write_buf;
    struct ev_timer read_bytes_timer_ev;
    size_t read_bytes_n;
    void (*read_bytes_callback)(struct BufferedSocket *buffsock, void *arg);
    void *read_bytes_arg;
    struct ev_loop *loop;
    void (*connect_callback)(struct BufferedSocket *buffsock, void *arg);
    void (*close_callback)(struct BufferedSocket *buffsock, void *arg);
    void (*read_callback)(struct BufferedSocket *buffsock, struct Buffer *buf, void *arg);
    void (*write_callback)(struct BufferedSocket *buffsock, void *arg);
    void (*error_callback)(struct BufferedSocket *buffsock, void *arg);
    void *cbarg;
};

struct BufferedSocket *new_buffered_socket(const char *address, int port,
        void (*connect_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*close_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*read_callback)(struct BufferedSocket *buffsock, struct Buffer *buf, void *arg),
        void (*write_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*error_callback)(struct BufferedSocket *buffsock, void *arg),
        void *cbarg);
void free_buffered_socket(struct BufferedSocket *socket);
void buffered_socket_set_loop(struct BufferedSocket *socket, struct ev_loop *loop);
int buffered_socket_connect(struct BufferedSocket *buffsock);
void buffered_socket_close(struct BufferedSocket *socket);
size_t buffered_socket_write(struct BufferedSocket *buffsock, void *data, size_t len);
size_t buffered_socket_write_buffer(struct BufferedSocket *buffsock, struct Buffer *buf);
void buffered_socket_read_bytes(struct BufferedSocket *buffsock, size_t n, 
    void (*data_callback)(struct BufferedSocket *buffsock, void *arg), void *arg);

#endif
