#include "evbuffsock.h"

#ifdef DEBUG
#define _DEBUG(...) fprintf(stdout, __VA_ARGS__)
#else
#define _DEBUG(...) do {;} while (0)
#endif

static void buffered_socket_read_cb(EV_P_ struct ev_io *w, int revents);
static void buffered_socket_write_cb(EV_P_ struct ev_io *w, int revents);
static void buffered_socket_connect_cb(EV_P_ struct ev_io *w, int revents);
static void buffered_socket_connect_timeout_cb(EV_P_ struct ev_timer *w, int revents);
static void buffered_socket_read_bytes_cb(EV_P_ struct ev_timer *w, int revents);

struct BufferedSocket *new_buffered_socket(const char *address, int port,
        void (*connect_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*close_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*read_callback)(struct BufferedSocket *buffsock, struct Buffer *buf, void *arg),
        void (*write_callback)(struct BufferedSocket *buffsock, void *arg),
        void (*error_callback)(struct BufferedSocket *buffsock, void *arg),
        void *cbarg)
{
    struct BufferedSocket *buffsock;
    
    buffsock = malloc(sizeof(struct BufferedSocket));
    buffsock->address = strdup(address);
    buffsock->port = port;
    buffsock->read_buf = new_buffer(4096);
    buffsock->write_buf = new_buffer(4096);
    buffsock->fd = -1;
    buffsock->state = BS_INIT;
    buffsock->connect_callback = connect_callback;
    buffsock->close_callback = close_callback;
    buffsock->read_callback = read_callback;
    buffsock->write_callback = write_callback;
    buffsock->error_callback = error_callback;
    buffsock->cbarg = cbarg;
    buffsock->read_bytes_n = 0;
    buffsock->read_bytes_callback = NULL;
    buffsock->read_bytes_arg = NULL;
    buffsock->loop = ev_default_loop(0);
    
    ev_init(&buffsock->read_bytes_timer_ev, buffered_socket_read_bytes_cb);
    buffsock->read_bytes_timer_ev.data = buffsock;
    ev_timer_set(&buffsock->read_bytes_timer_ev, 0., 0.);
    
    return buffsock;
}

void free_buffered_socket(struct BufferedSocket *buffsock)
{
    if (buffsock) {
        buffered_socket_close(buffsock);
        free_buffer(buffsock->read_buf);
        free_buffer(buffsock->write_buf);
        free(buffsock->address);
        free(buffsock);
    }
}

void buffered_socket_set_loop(struct BufferedSocket *buffsock, struct ev_loop *loop)
{
    buffsock->loop = loop;
}

int buffered_socket_connect(struct BufferedSocket *buffsock)
{
    struct addrinfo ai, *aitop;
    char strport[32];
    struct sockaddr *sa;
    int slen;
    long flags;
    
    if ((buffsock->state == BS_CONNECTED) || (buffsock->state == BS_CONNECTING)) {
        return 0;
    }
    
    memset(&ai, 0, sizeof(struct addrinfo));
    ai.ai_family = AF_INET;
    ai.ai_socktype = SOCK_STREAM;
    snprintf(strport, sizeof(strport), "%d", buffsock->port);
    if (getaddrinfo(buffsock->address, strport, &ai, &aitop) != 0) {
        _DEBUG("%s: getaddrinfo() failed\n", __FUNCTION__);
        return -1;
    }
    sa = aitop->ai_addr;
    slen = aitop->ai_addrlen;
    
    if ((buffsock->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        _DEBUG("%s: socket() failed\n", __FUNCTION__);
        return -1;
    }
    
    // set non-blocking
    if ((flags = fcntl(buffsock->fd, F_GETFL, NULL)) < 0) {
        close(buffsock->fd);
        _DEBUG("%s: fcntl(%d, F_GETFL) failed\n", __FUNCTION__, buffsock->fd);
        return -1;
    }
    if (fcntl(buffsock->fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(buffsock->fd);
        _DEBUG("%s: fcntl(%d, F_SETFL) failed\n", __FUNCTION__, buffsock->fd);
        return -1;
    }
    
    if (connect(buffsock->fd, sa, slen) == -1) {
        if (errno != EINPROGRESS) {
            close(buffsock->fd);
            _DEBUG("%s: connect() failed\n", __FUNCTION__);
            return -1;
        }
    }
    
    freeaddrinfo(aitop);
    
    // initialize and start the connection io watcher
    buffsock->conn_ev.data = buffsock;
    ev_init(&buffsock->conn_ev, buffered_socket_connect_cb);
    ev_io_set(&buffsock->conn_ev, buffsock->fd, EV_WRITE);
    
    // initialize and start a connect timer (for timeouts)
    ev_init(&buffsock->timer_ev, buffered_socket_connect_timeout_cb);
    ev_timer_set(&buffsock->timer_ev, 2.0, 0.);
    
    ev_timer_start(buffsock->loop, &buffsock->timer_ev);
    ev_io_start(buffsock->loop, &buffsock->conn_ev);
    
    buffsock->state = BS_CONNECTING;
    
    return buffsock->fd;
}

static void buffered_socket_connect_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
    struct BufferedSocket *buffsock = (struct BufferedSocket *)(w->data);
    _DEBUG("%s: connection timeout for \"%s:%d\" on %d\n",
           __FUNCTION__, buffsock->address, buffsock->port, buffsock->fd);
    
    ev_io_stop(buffsock->loop, &buffsock->conn_ev);
    buffered_socket_close(buffsock);
}

static void buffered_socket_connect_cb(EV_P_ struct ev_io *w, int revents)
{
    struct BufferedSocket *buffsock = (struct BufferedSocket *)(w->data);
    int error;
    socklen_t errsz = sizeof(error);
    
    ev_timer_stop(buffsock->loop, &buffsock->timer_ev);
    ev_io_stop(buffsock->loop, &buffsock->conn_ev);
    
    if (getsockopt(buffsock->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errsz) == -1) {
        _DEBUG("%s: getsockopt failed for \"%s:%d\" on %d\n",
               __FUNCTION__, buffsock->address, buffsock->port, buffsock->fd);
        buffered_socket_close(buffsock);
        return;
    }
    
    if (error) {
        _DEBUG("%s: \"%s\" for \"%s:%d\" on %d\n",
               __FUNCTION__, strerror(error), buffsock->address, buffsock->port, buffsock->fd);
        buffered_socket_close(buffsock);
        return;
    }
    
    _DEBUG("%s: connected to \"%s:%d\" on %d\n",
           __FUNCTION__, buffsock->address, buffsock->port, buffsock->fd);
           
    buffsock->state = BS_CONNECTED;
    
    // setup the read io watcher
    buffsock->read_ev.data = buffsock;
    ev_init(&buffsock->read_ev, buffered_socket_read_cb);
    ev_io_set(&buffsock->read_ev, buffsock->fd, EV_READ);
    
    // setup the write io watcher
    buffsock->write_ev.data = buffsock;
    ev_init(&buffsock->write_ev, buffered_socket_write_cb);
    ev_io_set(&buffsock->write_ev, buffsock->fd, EV_WRITE);
    
    // kick off the read events
    ev_io_start(buffsock->loop, &buffsock->read_ev);
    
    if (buffsock->connect_callback) {
        (*buffsock->connect_callback)(buffsock, buffsock->cbarg);
    }
}

void buffered_socket_close(struct BufferedSocket *buffsock)
{
    _DEBUG("%s: closing \"%s:%d\" on %d\n",
           __FUNCTION__, buffsock->address, buffsock->port, buffsock->fd);
           
    buffsock->state = BS_DISCONNECTED;
    
    ev_io_stop(buffsock->loop, &buffsock->conn_ev);
    ev_timer_stop(buffsock->loop, &buffsock->timer_ev);
    
    if (buffsock->fd != -1) {
        if (buffsock->close_callback) {
            (*buffsock->close_callback)(buffsock, buffsock->cbarg);
        }
        close(buffsock->fd);
        buffsock->fd = -1;
    }
    
    ev_io_stop(buffsock->loop, &buffsock->read_ev);
    ev_io_stop(buffsock->loop, &buffsock->write_ev);
}

size_t buffered_socket_write(struct BufferedSocket *buffsock, void *data, size_t len)
{
    if (buffsock->state != BS_CONNECTED) {
        return -1;
    }
    
    _DEBUG("%s: writing %lu bytes starting at %p\n", __FUNCTION__, len, data);
    
    buffer_add(buffsock->write_buf, data, len);
    ev_io_start(buffsock->loop, &buffsock->write_ev);
    
    return len;
}

size_t buffered_socket_write_buffer(struct BufferedSocket *buffsock, struct Buffer *buf)
{
    size_t n;
    
    n = buffer_has_data(buf);
    if (n > 0) {
        buffered_socket_write(buffsock, buf->data, n);
        buffer_reset(buf);
    }
    
    return n;
}

static void buffered_socket_read_bytes_cb(EV_P_ struct ev_timer *w, int revents)
{
    struct BufferedSocket *buffsock = (struct BufferedSocket *)w->data;
    void (*cb)(struct BufferedSocket *buffsock, void *arg);
    void *cb_arg;
    
    _DEBUG("%s: %p\n", __FUNCTION__, buffsock->read_bytes_arg);
    
    cb = buffsock->read_bytes_callback;
    cb_arg = buffsock->read_bytes_arg;
    
    buffsock->read_bytes_callback = NULL;
    buffsock->read_bytes_n = 0;
    buffsock->read_bytes_arg = NULL;
    
    cb(buffsock, cb_arg);
}

void buffered_socket_read_bytes(struct BufferedSocket *buffsock, size_t n, 
    void (*data_callback)(struct BufferedSocket *buffsock, void *arg), void *arg)
{
    buffsock->read_bytes_callback = data_callback;
    buffsock->read_bytes_arg = arg;
    buffsock->read_bytes_n = n;
    
    if (buffer_has_data(buffsock->read_buf) >= n) {
        ev_timer_start(buffsock->loop, &buffsock->read_bytes_timer_ev);
    }
}

static void buffered_socket_read_cb(EV_P_ struct ev_io *w, int revents)
{
    struct BufferedSocket *buffsock = (struct BufferedSocket *)(w->data);
    int res;
    
    res = buffer_read_fd(buffsock->read_buf, w->fd);
    _DEBUG("%s: %d bytes read\n", __FUNCTION__, res);
    
    if (res == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            return;
        }
        goto error;
    } else if (res == 0) {
        goto error;
    }
    
    // client's responsibility to drain the buffer
    if (buffsock->read_callback) {
        (*buffsock->read_callback)(buffsock, buffsock->read_buf, buffsock->cbarg);
    }
    
    if (buffsock->read_bytes_n && (buffer_has_data(buffsock->read_buf) >= buffsock->read_bytes_n)) {
        ev_timer_start(buffsock->loop, &buffsock->read_bytes_timer_ev);
    }
    
    return;

error:
    if (buffsock->error_callback) {
        (*buffsock->error_callback)(buffsock, buffsock->cbarg);
    }
    buffered_socket_close(buffsock);
}

static void buffered_socket_write_cb(EV_P_ struct ev_io *w, int revents)
{
    struct BufferedSocket *buffsock = (struct BufferedSocket *)(w->data);
    int res;
    
    res = buffer_write_fd(buffsock->write_buf, w->fd);
    _DEBUG("%s: %d written, left to write %d\n", __FUNCTION__, res, buffer_has_data(buffsock->write_buf));
    
    if (!buffer_has_data(buffsock->write_buf)) {
        ev_io_stop(buffsock->loop, &buffsock->write_ev);
    }
    
    if (res == -1) {
        if (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS) {
            return;
        }
        goto error;
    } else if (res == 0) {
        goto error;
    }
    
    if (buffsock->write_callback) {
        (*buffsock->write_callback)(buffsock, buffsock->cbarg);
    }
    
    return;

error:
    if (buffsock->error_callback) {
        (*buffsock->error_callback)(buffsock, buffsock->cbarg);
    }
    buffered_socket_close(buffsock);
}
