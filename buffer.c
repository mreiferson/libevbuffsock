#include "evbuffsock.h"

struct Buffer *new_buffer(size_t length)
{
    struct Buffer *buf;
    
    buf = malloc(sizeof(struct Buffer));
    buf->data = malloc(length);
    buf->orig = buf->data;
    buf->offset = 0;
    buf->length = length;
    
    return buf;
}

void free_buffer(struct Buffer *buf)
{
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

void buffer_reset(struct Buffer *buf)
{
    buf->data = buf->orig;
    buf->offset = 0;
}

int buffer_add(struct Buffer *buf, void *source, size_t length)
{
    memcpy(buf->data + buf->offset, source, length);
    buf->offset += length;
    
    return 0;
}

void buffer_drain(struct Buffer *buf, size_t length)
{
    if (length > buf->offset) {
        buf->offset = 0;
        buf->data = buf->orig;
    } else {
        buf->data += length;
        buf->offset -= length;
    }
}

int buffer_read_fd(struct Buffer *buf, int fd)
{
    int n;
    n = recv(fd, buf->data, buf->length - buf->offset, 0);
    if (n > 0) {
        buf->offset += n;
    }
    return n;
}

int buffer_write_fd(struct Buffer *buf, int fd)
{
    int n;
    n = send(fd, buf->data, buf->offset, 0);
    if (n > 0) {
        buffer_drain(buf, n);
    }
    return n;
}

int buffer_has_data(struct Buffer *buf)
{
    return buf->offset;
}
